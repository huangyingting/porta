use std::io::{self, Read, Write};

use thiserror::Error;

pub const VERSION: &str = "2";
pub const MIN_VERSION: &str = VERSION;
pub const MAX_VERSION: &str = VERSION;
pub const HEADER_VERSION: &str = "X-Porta-Version";
pub const HEADER_MIN_VERSION: &str = "X-Porta-Min-Version";
pub const HEADER_MAX_VERSION: &str = "X-Porta-Max-Version";
pub const CONTENT_TYPE: &str = "application/x-porta-packets";
pub const MAX_PACKET_SIZE: usize = u16::MAX as usize;
pub const MAX_PACKET: usize = MAX_PACKET_SIZE;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("porta frame exceeds maximum packet size")]
    TooLarge,
    #[error("EOF")]
    EndOfStream,
    #[error("unexpected EOF")]
    UnexpectedEndOfStream,
    #[error("short write")]
    ShortWrite,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("read packet payload: EOF")]
    ReadPayloadEndOfStream,
    #[error("read packet payload: unexpected EOF")]
    ReadPayloadUnexpectedEndOfStream,
    #[error("read packet payload: {0}")]
    ReadPayload(#[source] io::Error),
}

pub type Result<T> = std::result::Result<T, FrameError>;

pub struct Encoder<W> {
    writer: W,
    header: [u8; 2],
}

impl<W: Write> Encoder<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            header: [0; 2],
        }
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        let size = u16::try_from(packet.len()).map_err(|_| FrameError::TooLarge)?;
        self.header = size.to_be_bytes();
        write_all(&mut self.writer, &self.header)?;
        write_all(&mut self.writer, packet)?;
        Ok(())
    }

    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

pub struct Decoder<R> {
    reader: R,
    header: [u8; 2],
}

impl<R: Read> Decoder<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            header: [0; 2],
        }
    }

    pub fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut packet = Vec::new();
        self.read_packet_into(&mut packet)?;
        Ok(packet)
    }

    pub fn read_packet_into<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Result<&'a [u8]> {
        read_header(&mut self.reader, &mut self.header)?;
        let size = usize::from(u16::from_be_bytes(self.header));
        buffer.resize(size, 0);
        read_payload(&mut self.reader, buffer)?;
        Ok(buffer)
    }

    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

fn read_header(reader: &mut impl Read, header: &mut [u8; 2]) -> Result<()> {
    let mut offset = 0;
    while offset < header.len() {
        match reader.read(&mut header[offset..]) {
            Ok(0) if offset == 0 => return Err(FrameError::EndOfStream),
            Ok(0) => return Err(FrameError::UnexpectedEndOfStream),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_payload(reader: &mut impl Read, payload: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < payload.len() {
        match reader.read(&mut payload[offset..]) {
            Ok(0) if offset == 0 => return Err(FrameError::ReadPayloadEndOfStream),
            Ok(0) => return Err(FrameError::ReadPayloadUnexpectedEndOfStream),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::ReadPayload(error)),
        }
    }
    Ok(())
}

fn write_all(writer: &mut impl Write, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        match writer.write(data) {
            Ok(0) => return Err(FrameError::ShortWrite),
            Ok(written) => data = &data[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct ChunkWriter {
        bytes: Vec<u8>,
        maximum: usize,
    }

    impl Write for ChunkWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let length = data.len().min(self.maximum);
            self.bytes.extend_from_slice(&data[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn frame_round_trip_matches_go_wire_bytes() {
        let mut stream = Vec::new();
        {
            let mut encoder = Encoder::new(&mut stream);
            encoder.write_packet(&[1, 2, 3]).unwrap();
            encoder.write_packet(&[]).unwrap();
            encoder.write_packet(&[4, 5]).unwrap();
        }
        assert_eq!(stream, [0, 3, 1, 2, 3, 0, 0, 0, 2, 4, 5]);

        let mut decoder = Decoder::new(Cursor::new(stream));
        assert_eq!(decoder.read_packet().unwrap(), [1, 2, 3]);
        assert!(decoder.read_packet().unwrap().is_empty());
        assert_eq!(decoder.read_packet().unwrap(), [4, 5]);
        assert!(matches!(
            decoder.read_packet().unwrap_err(),
            FrameError::EndOfStream
        ));
    }

    #[test]
    fn decoder_reuses_the_supplied_allocation() {
        let mut decoder = Decoder::new(Cursor::new([0, 3, 1, 2, 3]));
        let mut buffer = Vec::with_capacity(16);
        let original = buffer.as_ptr();
        let packet = decoder.read_packet_into(&mut buffer).unwrap();
        assert_eq!(packet, [1, 2, 3]);
        assert_eq!(packet.as_ptr(), original);
    }

    #[test]
    fn reports_truncated_header_and_payload_exactly() {
        let mut decoder = Decoder::new(Cursor::new([0]));
        assert!(matches!(
            decoder.read_packet().unwrap_err(),
            FrameError::UnexpectedEndOfStream
        ));

        let mut decoder = Decoder::new(Cursor::new([0, 3, 1, 2]));
        let error = decoder.read_packet().unwrap_err();
        assert!(matches!(
            error,
            FrameError::ReadPayloadUnexpectedEndOfStream
        ));
        assert_eq!(error.to_string(), "read packet payload: unexpected EOF");

        let mut decoder = Decoder::new(Cursor::new([0, 1]));
        assert_eq!(
            decoder.read_packet().unwrap_err().to_string(),
            "read packet payload: EOF"
        );
    }

    #[test]
    fn rejects_packets_larger_than_the_two_byte_bound() {
        let mut encoder = Encoder::new(Vec::new());
        let error = encoder
            .write_packet(&vec![0; MAX_PACKET_SIZE + 1])
            .unwrap_err();
        assert!(matches!(error, FrameError::TooLarge));
        assert_eq!(error.to_string(), "porta frame exceeds maximum packet size");
        assert!(encoder.into_inner().is_empty());
    }

    #[test]
    fn accepts_the_maximum_packet_size() {
        let packet = vec![0xa5; MAX_PACKET_SIZE];
        let mut encoder = Encoder::new(Vec::new());
        encoder.write_packet(&packet).unwrap();
        let encoded = encoder.into_inner();
        assert_eq!(&encoded[..2], &[0xff, 0xff]);
        assert_eq!(&encoded[2..], packet);
    }

    #[test]
    fn retries_short_writes_and_reports_write_zero() {
        let writer = ChunkWriter {
            bytes: Vec::new(),
            maximum: 1,
        };
        let mut encoder = Encoder::new(writer);
        encoder.write_packet(&[1, 2, 3]).unwrap();
        assert_eq!(encoder.into_inner().bytes, [0, 3, 1, 2, 3]);

        let writer = ChunkWriter {
            bytes: Vec::new(),
            maximum: 0,
        };
        let error = Encoder::new(writer).write_packet(&[1]).unwrap_err();
        assert!(matches!(error, FrameError::ShortWrite));
        assert_eq!(error.to_string(), "short write");
    }
}
