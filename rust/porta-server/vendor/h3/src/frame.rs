use std::task::{Context, Poll};

use bytes::Buf;

#[cfg(feature = "tracing")]
use tracing::trace;

use crate::error::Code;
use crate::proto::frame::SettingsError;
use crate::proto::push::InvalidPushId;
use crate::quic::{InvalidStreamId, StreamErrorIncoming};
use crate::stream::{BufRecvStream, WriteBuf};
use crate::{
    buf::BufList,
    proto::{
        frame::{self, Frame, FrameType, PayloadLen},
        stream::StreamId,
        varint::VarInt,
    },
    quic::{BidiStream, RecvStream, SendStream},
};

/// Decodes Frames from the underlying QUIC stream
pub struct FrameStream<S, B> {
    pub stream: BufRecvStream<S, B>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
}

impl<S, B> FrameStream<S, B> {
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
        }
    }

    pub(crate) fn with_max_field_section_size(mut self, limit: u64) -> Self {
        // QPACK's field section prefix is not included in the decoded field size.
        self.decoder.max_field_section_size = limit.saturating_add(2);
        self
    }

    pub(crate) fn control(stream: BufRecvStream<S, B>) -> Self {
        let mut framed = Self::new(stream);
        framed.decoder.require_settings = true;
        framed
    }

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
    pub fn into_inner(self) -> BufRecvStream<S, B> {
        self.stream
    }
}

impl<S, B> FrameStream<S, B>
where
    S: crate::quic::Is0rtt,
{
    /// Checks if the stream was opened in 0-RTT mode
    pub(crate) fn is_0rtt(&self) -> bool {
        self.stream.is_0rtt()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: RecvStream,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        assert!(
            self.remaining_data == 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        loop {
            match self.decoder.decode(self.stream.buf_mut())? {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    return Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))));
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    return Poll::Ready(Ok(frame));
                }
                Some(frame) => return Poll::Ready(Ok(Some(frame))),
                None => {}
            }

            match self.try_recv(cx)? {
                // Received a chunk but the frame is incomplete, poll until we get `Pending`.
                Poll::Ready(false) => continue,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true) => {
                    if self.stream.buf_mut().has_remaining() || !self.decoder.is_idle() {
                        // A buffered frame or an incrementally discarded frame is incomplete.
                        return Poll::Ready(Err(FrameStreamError::UnexpectedEnd));
                    } else {
                        return Poll::Ready(Ok(None));
                    }
                }
            }
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let data = self.stream.buf_mut().take_chunk(self.remaining_data);

        match (data, end) {
            (None, true) => Poll::Ready(Ok(None)),
            (None, false) => Poll::Pending,
            (Some(d), true)
                if d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining() =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos() && !self.stream.buf().has_remaining() && self.decoder.is_idle()
    }

    fn try_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self.stream.poll_read(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(FrameStreamError::Quic(e))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(eos)) => Poll::Ready(Ok(eos)),
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B> SendStream<B> for FrameStream<T, B>
where
    T: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.stream.send_id()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: BidiStream<B>,
    B: Buf,
{
    pub(crate) fn split(self) -> (FrameStream<S::SendStream, B>, FrameStream<S::RecvStream, B>) {
        let (send, recv) = self.stream.split();
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::default(),
                remaining_data: 0,
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
            },
        )
    }
}

// Bound buffering even when SETTINGS_MAX_FIELD_SECTION_SIZE is left unlimited.
// Control frames use this independent cap, not the request/response header limit.
const MAX_BUFFERED_FRAME_SIZE: u64 = 64 * 1024;

#[derive(Debug, Default)]
enum DecodeState {
    #[default]
    Header,
    Buffered {
        expected: usize,
    },
    Discard {
        remaining: u64,
    },
}

pub struct FrameDecoder {
    state: DecodeState,
    max_field_section_size: u64,
    require_settings: bool,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self {
            state: DecodeState::Header,
            max_field_section_size: MAX_BUFFERED_FRAME_SIZE,
            require_settings: false,
        }
    }
}

impl FrameDecoder {
    fn is_idle(&self) -> bool {
        matches!(self.state, DecodeState::Header)
    }

    fn decode<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        // Decode in a loop since we ignore unknown frames, and there may be
        // other frames already in our BufList.
        loop {
            match &mut self.state {
                DecodeState::Discard { remaining } => {
                    let discarded = (*remaining).min(src.remaining() as u64) as usize;
                    src.advance(discarded);
                    *remaining -= discarded as u64;
                    if *remaining != 0 {
                        return Ok(None);
                    }
                    self.state = DecodeState::Header;
                    continue;
                }
                DecodeState::Buffered { expected } => {
                    if src.remaining() < *expected {
                        return Ok(None);
                    }
                }
                DecodeState::Header => {
                    // Keep at most two varints until the declaration is complete.
                    // No payload may be accumulated before this preflight succeeds.
                    let mut cur = src.cursor();
                    let Ok(ty) = FrameType::decode(&mut cur) else {
                        return Ok(None);
                    };
                    if self.require_settings && ty != FrameType::SETTINGS {
                        return Err(FrameStreamError::Proto(FrameProtocolError::MissingSettings));
                    }
                    let Ok(value) = VarInt::decode(&mut cur) else {
                        return Ok(None);
                    };
                    let header_len = cur.position();
                    let len = value.into_inner();
                    let limit = match ty {
                        // WebTransport's second varint is a session ID, not a length.
                        FrameType::WEBTRANSPORT_BI_STREAM => 0,
                        FrameType::DATA => {
                            let len = usize::try_from(len).map_err(|_| {
                                FrameStreamError::Proto(FrameProtocolError::ExcessiveLoad)
                            })?;
                            src.advance(header_len);
                            return Ok(Some(Frame::Data(PayloadLen(len))));
                        }
                        FrameType::HEADERS => self.max_field_section_size,
                        FrameType::PUSH_PROMISE => self
                            .max_field_section_size
                            .saturating_add(VarInt::MAX_SIZE as u64),
                        FrameType::SETTINGS
                        | FrameType::CANCEL_PUSH
                        | FrameType::GOAWAY
                        | FrameType::MAX_PUSH_ID => MAX_BUFFERED_FRAME_SIZE,
                        FrameType::H2_PRIORITY
                        | FrameType::H2_PING
                        | FrameType::H2_WINDOW_UPDATE
                        | FrameType::H2_CONTINUATION => {
                            return Err(FrameStreamError::Proto(
                                FrameProtocolError::ForbiddenFrame(ty.value()),
                            ));
                        }
                        _ => {
                            #[cfg(feature = "tracing")]
                            trace!("ignore unknown frame type {:?}", ty);
                            src.advance(header_len);
                            self.state = DecodeState::Discard { remaining: len };
                            continue;
                        }
                    };
                    let payload_len = if ty == FrameType::WEBTRANSPORT_BI_STREAM {
                        0
                    } else {
                        if len > limit.min(MAX_BUFFERED_FRAME_SIZE) {
                            return Err(FrameStreamError::Proto(FrameProtocolError::ExcessiveLoad));
                        }
                        len as usize
                    };
                    self.state = DecodeState::Buffered {
                        expected: header_len + payload_len,
                    };
                    continue;
                }
            }

            let (pos, decoded) = {
                let mut cur = src.cursor();
                let decoded = Frame::decode(&mut cur);
                (cur.position(), decoded)
            };

            match decoded {
                Err(frame::FrameError::UnknownFrame(_)) => {
                    unreachable!("unknown frames are discarded during preflight");
                }
                Err(frame::FrameError::Incomplete(_)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Malformed));
                }
                Ok(frame) => {
                    src.advance(pos);
                    self.state = DecodeState::Header;
                    self.require_settings = false;
                    return Ok(Some(frame));
                }
                // -------------- Map the error Values --------------
                Err(frame::FrameError::InvalidStreamId(e)) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidStreamId(e),
                    ));
                }
                Err(frame::FrameError::InvalidPushId(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::InvalidPushId(
                        e,
                    )));
                }
                Err(frame::FrameError::Settings(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Settings(e)));
                }
                Err(frame::FrameError::UnsupportedFrame(ty)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(
                        ty,
                    )));
                }
                Err(frame::FrameError::InvalidFrameValue) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidFrameValue,
                    ));
                }
                Err(frame::FrameError::Malformed) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Malformed));
                }
            }
        }
    }
}

#[derive(Debug)]
/// Errors that can occur while decoding frames
pub enum FrameStreamError {
    Proto(FrameProtocolError),
    Quic(StreamErrorIncoming),
    UnexpectedEnd,
}

#[derive(Debug, PartialEq)]
/// Protocol specific errors that can occur while decoding frames in a stream
pub enum FrameProtocolError {
    ExcessiveLoad,
    MissingSettings,
    Malformed,
    ForbiddenFrame(u64), // Known (http2) frames that should generate an error
    InvalidFrameValue,
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::future::poll_fn;
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    use crate::proto::{coding::Encode, frame::FrameType, varint::VarInt};

    // Decoder

    #[test]
    fn one_frame() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = Frame::headers(&b"salut"[..]);

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    #[test]
    fn header_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf_list = BufList::new();
        // Cut buffer between type and length
        buf_list.push(&buf[..1]);
        buf_list.push(&buf[1..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn varint_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers("salut".repeat(1024)).encode_with_payload(&mut buf);

        let mut buf_list = BufList::new();
        // Cut buffer in the middle of length's varint
        buf_list.push(&buf[..2]);
        buf_list.push(&buf[2..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);

        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    // FrameStream

    macro_rules! assert_poll_matches {
        ($poll_fn:expr, $match:pat) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match
            );
        };
        ($poll_fn:expr, $match:pat if $cond:expr ) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match if $cond
            );
        }
    }

    #[tokio::test]
    async fn poll_full_request() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
    }

    #[tokio::test]
    async fn poll_next_applies_backpressure_before_reading_more_chunks() {
        const CHUNK_COUNT: usize = 64;
        const FRAMES_PER_CHUNK: usize = 16;
        const FRAME_PAYLOAD_SIZE: usize = 1024;

        let mut encoded_chunk = BytesMut::new();
        let payload = Bytes::from(vec![0_u8; FRAME_PAYLOAD_SIZE]);
        for _ in 0..FRAMES_PER_CHUNK {
            Frame::headers(payload.clone()).encode_with_payload(&mut encoded_chunk);
        }
        let encoded_chunk = encoded_chunk.freeze();
        let max_buffered = encoded_chunk.len();

        let mut recv = FakeRecv::default();
        for _ in 0..CHUNK_COUNT {
            recv.chunk(encoded_chunk.clone());
        }
        let transport_polls = recv.poll_count.clone();

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // Model a consumer that processes one frame per wake while the
        // transport can provide chunks containing many complete frames.
        for _ in 0..CHUNK_COUNT {
            assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        }

        let buffered = stream.stream.buf().remaining();
        assert!(
            buffered <= max_buffered,
            "frame buffering grew past one transport chunk: {buffered} > {max_buffered}"
        );
        assert_eq!(
            transport_polls.get(),
            CHUNK_COUNT.div_ceil(FRAMES_PER_CHUNK),
            "transport was polled while complete frames were still buffered"
        );
    }

    #[tokio::test]
    async fn huge_buffered_frames_are_rejected_from_the_prefix() {
        for ty in [
            FrameType::HEADERS,
            FrameType::SETTINGS,
            FrameType::PUSH_PROMISE,
            FrameType::CANCEL_PUSH,
            FrameType::GOAWAY,
            FrameType::MAX_PUSH_ID,
        ] {
            let mut prefix = BytesMut::new();
            ty.encode(&mut prefix);
            VarInt::MAX.encode(&mut prefix);
            assert!(prefix.len() <= 16);

            let mut recv = FakeRecv::default();
            for byte in &prefix {
                recv.chunk(Bytes::copy_from_slice(&[*byte]));
            }
            recv.chunk(Bytes::from(vec![0; 1024]));
            let polls = recv.poll_count.clone();
            let mut stream: FrameStream<_, ()> =
                FrameStream::new(BufRecvStream::new(recv)).with_max_field_section_size(1024);

            let error = poll_fn(|cx| stream.poll_next(cx)).await.unwrap_err();
            let FrameStreamError::Proto(error) = error else {
                panic!("expected a protocol error");
            };
            assert_eq!(error, FrameProtocolError::ExcessiveLoad);
            assert_eq!(
                crate::error::internal_error::InternalConnectionError::got_frame_error(error).code,
                Code::H3_EXCESSIVE_LOAD
            );
            assert_eq!(polls.get(), prefix.len(), "read past the frame declaration");
            assert_eq!(stream.stream.buf().remaining(), prefix.len());
        }
    }

    #[tokio::test]
    async fn configured_header_limit_is_checked_before_the_body() {
        let mut prefix = BytesMut::new();
        FrameType::HEADERS.encode(&mut prefix);
        VarInt::from(1027u32).encode(&mut prefix);
        let mut recv = FakeRecv::default();
        recv.chunk(prefix.freeze());
        let polls = recv.poll_count.clone();
        let mut stream: FrameStream<_, ()> =
            FrameStream::new(BufRecvStream::new(recv)).with_max_field_section_size(1024);
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Proto(FrameProtocolError::ExcessiveLoad))
        );
        assert_eq!(polls.get(), 1);
    }

    #[test]
    fn huge_unknown_frame_is_discarded_incrementally() {
        let mut prefix = BytesMut::new();
        // Exercise eight-byte type and length varints without allocating a huge body.
        VarInt::MAX.encode(&mut prefix);
        VarInt::MAX.encode(&mut prefix);
        let mut buf = BufList::from(prefix.freeze());
        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
        assert_eq!(buf.remaining(), 0);

        let chunk = Bytes::from(vec![0; 1024]);
        for count in 1..=128 {
            buf.push(chunk.clone());
            assert_matches!(decoder.decode(&mut buf), Ok(None));
            assert_eq!(buf.remaining(), 0, "retained unknown frame payload");
            assert_matches!(
                decoder.state,
                DecodeState::Discard { remaining }
                    if remaining == VarInt::MAX.into_inner() - count * 1024
            );
        }
    }

    #[test]
    fn unknown_frame_discard_resumes_at_the_next_frame() {
        let mut prefix = BytesMut::new();
        FrameType::RESERVED.encode(&mut prefix);
        VarInt::from(1024 * 1024u32).encode(&mut prefix);
        let mut buf = BufList::from(prefix.freeze());
        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));

        let chunk = Bytes::from(vec![0; 1024]);
        for _ in 0..1023 {
            buf.push(chunk.clone());
            assert_matches!(decoder.decode(&mut buf), Ok(None));
            assert_eq!(buf.remaining(), 0);
        }
        let mut last = BytesMut::from(chunk.as_ref());
        Frame::headers(&b"next"[..]).encode_with_payload(&mut last);
        buf.push(last.freeze());
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Headers(headers))) if headers == b"next"[..]
        );
        assert_eq!(buf.remaining(), 0);
        assert!(decoder.is_idle());
    }

    #[tokio::test]
    async fn truncated_unknown_frame_is_not_a_clean_end() {
        let mut prefix = BytesMut::new();
        FrameType::RESERVED.encode(&mut prefix);
        VarInt::MAX.encode(&mut prefix);
        let mut recv = FakeRecv::default();
        recv.chunk(prefix.freeze());
        recv.chunk(Bytes::from_static(b"partial payload"));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
        assert_eq!(stream.stream.buf().remaining(), 0);
        assert!(!stream.is_eos());
    }

    #[tokio::test]
    async fn control_frames_use_an_independent_buffering_limit() {
        let mut buf = BytesMut::new();
        let mut settings = frame::Settings::default();
        settings
            .insert(frame::SettingId::MAX_HEADER_LIST_SIZE, 0)
            .unwrap();
        Frame::<Bytes>::Settings(settings).encode(&mut buf);
        FrameType::RESERVED.encode(&mut buf);
        VarInt::from(3u32).encode(&mut buf);
        buf.put_slice(b"xyz");
        Frame::<Bytes>::Goaway(VarInt::from(0u32)).encode(&mut buf);
        let mut recv = FakeRecv::default();
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> =
            FrameStream::control(BufRecvStream::new(recv)).with_max_field_section_size(0);
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Settings(_))));
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Goaway(_))));
    }

    #[tokio::test]
    async fn control_stream_cannot_skip_unknown_frames_before_settings() {
        let mut prefix = BytesMut::new();
        FrameType::RESERVED.encode(&mut prefix);
        VarInt::MAX.encode(&mut prefix);
        let mut recv = FakeRecv::default();
        recv.chunk(prefix.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::control(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Proto(FrameProtocolError::MissingSettings))
        );
    }

    #[tokio::test]
    async fn data_declaration_is_not_subject_to_buffering_limits() {
        let mut prefix = BytesMut::new();
        FrameType::DATA.encode(&mut prefix);
        VarInt::from(1024 * 1024u32).encode(&mut prefix);
        let mut recv = FakeRecv::default();
        recv.chunk(prefix.freeze());
        recv.chunk(Bytes::from_static(b"body"));
        let polls = recv.poll_count.clone();
        let mut stream: FrameStream<_, ()> =
            FrameStream::new(BufRecvStream::new(recv)).with_max_field_section_size(0);
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(1048576))))
        );
        assert_eq!(polls.get(), 1);
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(body)) if body == b"body"[..]
        );
    }

    #[test]
    fn webtransport_header_is_not_a_length_prefixed_frame() {
        let mut prefix = BytesMut::new();
        FrameType::WEBTRANSPORT_BI_STREAM.encode(&mut prefix);
        VarInt::from(1024 * 1024u32).encode(&mut prefix);
        let mut decoder = FrameDecoder::default();
        let mut buf = BufList::new();
        for byte in &prefix[..prefix.len() - 1] {
            buf.push(Bytes::copy_from_slice(&[*byte]));
            assert_matches!(decoder.decode(&mut buf), Ok(None));
        }
        buf.push(Bytes::copy_from_slice(&prefix[prefix.len() - 1..]));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::WebTransportStream(_)))
        );
        assert_eq!(buf.remaining(), 0);
    }

    #[tokio::test]
    async fn poll_next_incomplete_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 1));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "There is still data to read, please call poll_data() until it returns None"
    )]
    async fn poll_next_reamining_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // There is still data to consume, poll_next should panic
        let _ = poll_fn(|cx| stream.poll_next(cx)).await;
    }

    #[tokio::test]
    async fn poll_data_split() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Body is split into two bufs
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 2));
        recv.chunk(buf);
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // We get the total size of data about to be received
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // Then we get parts of body, chunked as they arrived
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
    }

    #[tokio::test]
    async fn poll_data_unexpected_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Truncated body
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"b"[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_data_ignores_unknown_frames() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // grease a lil
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(0);

        // grease with some data
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(6);
        buf.put_slice(b"grease");

        // Body
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    #[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }

    // Helpers

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
        poll_count: Rc<Cell<usize>>,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.poll_count.set(self.poll_count.get() + 1);
            Poll::Ready(Ok(self.chunks.pop_front()))
        }

        fn stop_sending(&mut self, _: u64) {
            unimplemented!()
        }

        fn recv_id(&self) -> StreamId {
            unimplemented!()
        }
    }

    fn to_bytes(
        x: Poll<Result<Option<impl Buf>, FrameStreamError>>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        x.map(|b| b.map(|b| b.map(|mut b| b.copy_to_bytes(b.remaining()))))
    }
}
