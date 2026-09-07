use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use atomic_waker::AtomicWaker;
use bytes::{Buf, Bytes};
use futures_channel::{mpsc, oneshot};
use futures_core::{ready, Stream};
use h2::{Reason, RecvStream, SendStream};
use pin_project_lite::pin_project;

use super::ping::Recorder;
use super::SendBuf;
use crate::rt::{Read, ReadBufCursor, Write};

pub(super) fn pair<B>(
    send_stream: SendStream<SendBuf<B>>,
    recv_stream: RecvStream,
    ping: Recorder,
) -> (H2Upgraded, UpgradedSendStreamTask<B>) {
    let (tx, rx) = mpsc::channel(1);
    let (error_tx, error_rx) = oneshot::channel();
    let (shutdown_ready_tx, shutdown_ready_rx) = oneshot::channel();
    let (shutdown_ack_tx, shutdown_ack_rx) = oneshot::channel();
    let close_notify = Arc::new(UpgradedCloseNotify::new());

    (
        H2Upgraded {
            send_stream: UpgradedSendStreamBridge {
                tx,
                error_rx,
                close_notify: close_notify.clone(),
                shutdown_ready_rx,
                shutdown_ack_tx: Some(shutdown_ack_tx),
                shutdown_complete: false,
            },
            recv_stream,
            ping,
            buf: Bytes::new(),
        },
        UpgradedSendStreamTask {
            h2_tx: send_stream,
            rx,
            close_notify,
            error_tx: Some(error_tx),
            shutdown_ready_tx: Some(shutdown_ready_tx),
            shutdown_ack_rx,
            shutdown_sent: false,
        },
    )
}

pub(super) struct H2Upgraded {
    ping: Recorder,
    send_stream: UpgradedSendStreamBridge,
    recv_stream: RecvStream,
    buf: Bytes,
}

struct UpgradedSendStreamBridge {
    tx: mpsc::Sender<Cursor<Box<[u8]>>>,
    error_rx: oneshot::Receiver<crate::Error>,
    close_notify: Arc<UpgradedCloseNotify>,
    shutdown_ready_rx: oneshot::Receiver<()>,
    shutdown_ack_tx: Option<oneshot::Sender<()>>,
    shutdown_complete: bool,
}

impl Drop for UpgradedSendStreamBridge {
    fn drop(&mut self) {
        if !self.shutdown_complete {
            self.close_notify.abort();
        }
    }
}

struct UpgradedCloseNotify {
    action: AtomicU8,
    task: AtomicWaker,
}

const CLOSE_OPEN: u8 = 0;
const CLOSE_GRACEFUL: u8 = 1;
const CLOSE_ABORT: u8 = 2;

impl UpgradedCloseNotify {
    fn new() -> Self {
        Self {
            action: AtomicU8::new(CLOSE_OPEN),
            task: AtomicWaker::new(),
        }
    }

    fn graceful(&self) {
        let _ = self.action.compare_exchange(
            CLOSE_OPEN,
            CLOSE_GRACEFUL,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.task.wake();
    }

    fn abort(&self) {
        self.action.store(CLOSE_ABORT, Ordering::Release);
        self.task.wake();
    }

    fn poll_action(&self, cx: &mut Context<'_>) -> u8 {
        self.task.register(cx.waker());
        self.action.load(Ordering::Acquire)
    }
}

pin_project! {
    #[must_use = "futures do nothing unless polled"]
    pub struct UpgradedSendStreamTask<B> {
        #[pin]
        h2_tx: SendStream<SendBuf<B>>,
        #[pin]
        rx: mpsc::Receiver<Cursor<Box<[u8]>>>,
        close_notify: Arc<UpgradedCloseNotify>,
        error_tx: Option<oneshot::Sender<crate::Error>>,
        shutdown_ready_tx: Option<oneshot::Sender<()>>,
        #[pin]
        shutdown_ack_rx: oneshot::Receiver<()>,
        shutdown_sent: bool,
    }
}

// ===== impl UpgradedSendStreamTask =====

impl<B> UpgradedSendStreamTask<B>
where
    B: Buf,
{
    fn tick(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
        let mut me = self.project();

        // this is a manual `select()` over 3 "futures", so we always need
        // to be sure they are ready and/or we are waiting notification of
        // one of the sides hanging up, so the task doesn't live around
        // longer than it's meant to.
        loop {
            let close_action = me.close_notify.poll_action(cx);
            if close_action == CLOSE_ABORT {
                me.h2_tx.send_reset(Reason::CANCEL);
                return Poll::Ready(Ok(()));
            }
            if *me.shutdown_sent {
                return match me.shutdown_ack_rx.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(_)) => {
                        me.h2_tx.send_reset(Reason::CANCEL);
                        Poll::Ready(Ok(()))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }

            // we don't have the next chunk of data yet, so just reserve 1 byte to make
            // sure there's some capacity available. h2 will handle the capacity management
            // for the actual body chunk.
            me.h2_tx.reserve_capacity(1);

            let h2_has_capacity = if me.h2_tx.capacity() == 0 {
                // poll_capacity oddly needs a loop
                loop {
                    match me.h2_tx.poll_capacity(cx) {
                        Poll::Ready(Some(Ok(0))) => {}
                        Poll::Ready(Some(Ok(_))) => break true,
                        Poll::Ready(Some(Err(e))) => {
                            return Poll::Ready(Err(crate::Error::new_body_write(e)))
                        }
                        Poll::Ready(None) => {
                            // None means the stream is no longer in a
                            // streaming state, we either finished it
                            // somehow, or the remote reset us.
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                        Poll::Pending => break false,
                    }
                }
            } else {
                true
            };

            match me.h2_tx.poll_reset(cx) {
                Poll::Ready(Ok(reason)) => {
                    trace!("stream received RST_STREAM: {:?}", reason);
                    return Poll::Ready(Err(crate::Error::new_body_write(::h2::Error::from(
                        reason,
                    ))));
                }
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(crate::Error::new_body_write(err)))
                }
                Poll::Pending => (),
            }

            // If h2 has no capacity, don't pull another item from the mpsc
            // receiver. That would free a channel slot and let the writer
            // enqueue more data without h2 backpressure.
            //
            // Graceful shutdown preserves accepted writes by placing END_STREAM
            // behind any bytes already buffered by h2.
            if !h2_has_capacity {
                if close_action == CLOSE_GRACEFUL && me.rx.size_hint().0 == 0 {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    if let Some(ready) = me.shutdown_ready_tx.take() {
                        let _ = ready.send(());
                    }
                    *me.shutdown_sent = true;
                    continue;
                }

                return Poll::Pending;
            }

            match me.rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(cursor)) => {
                    me.h2_tx
                        .send_data(SendBuf::Cursor(cursor), false)
                        .map_err(crate::Error::new_body_write)?;
                }
                Poll::Ready(None) => {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    if let Some(ready) = me.shutdown_ready_tx.take() {
                        let _ = ready.send(());
                    }
                    *me.shutdown_sent = true;
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<B> Future for UpgradedSendStreamTask<B>
where
    B: Buf,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().tick(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Ready(Err(err)) => {
                if let Some(tx) = self.error_tx.take() {
                    let _oh_well = tx.send(err);
                }
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== impl H2Upgraded =====

impl Read for H2Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut read_buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.buf.is_empty() {
            self.buf = loop {
                match ready!(self.recv_stream.poll_data(cx)) {
                    None => return Poll::Ready(Ok(())),
                    Some(Ok(buf)) if buf.is_empty() && !self.recv_stream.is_end_stream() => {}
                    Some(Ok(buf)) => {
                        self.ping.record_data(buf.len());
                        break buf;
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(match e.reason() {
                            Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => Ok(()),
                            Some(Reason::STREAM_CLOSED) => {
                                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                            }
                            _ => Err(h2_to_io_error(e)),
                        })
                    }
                }
            };
        }
        let cnt = std::cmp::min(self.buf.len(), read_buf.remaining());
        read_buf.put_slice(&self.buf[..cnt]);
        self.buf.advance(cnt);
        let _ = self.recv_stream.flow_control().release_capacity(cnt);
        Poll::Ready(Ok(()))
    }
}

impl Write for H2Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_task_dropped)) => {
                // if the task dropped, check if there was an error
                // otherwise i guess its a broken pipe
                return match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => {
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }
            Poll::Pending => return Poll::Pending,
        }

        let n = buf.len();
        match self.send_stream.tx.start_send(Cursor::new(buf.into())) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_task_dropped) => {
                // if the task dropped, check if there was an error
                // otherwise i guess its a broken pipe
                match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => {
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_task_dropped)) => {
                // if the task dropped, check if there was an error
                // otherwise it was a clean close
                match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
                    Poll::Pending => Poll::Pending,
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.send_stream.tx.close_channel();
        self.send_stream.close_notify.graceful();
        match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => {
                self.send_stream.shutdown_complete = true;
                return Poll::Ready(Err(io_error(reason)));
            }
            Poll::Ready(Err(_task_dropped)) => {
                self.send_stream.shutdown_complete = true;
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => {}
        }
        match Pin::new(&mut self.send_stream.shutdown_ready_rx).poll(cx) {
            Poll::Ready(Ok(())) => {
                if let Some(ack) = self.send_stream.shutdown_ack_tx.take() {
                    let _ = ack.send(());
                }
                self.send_stream.shutdown_complete = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) | Poll::Pending => Poll::Pending,
        }
    }
}

fn io_error(e: crate::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

fn h2_to_io_error(e: h2::Error) -> std::io::Error {
    if e.is_io() {
        e.into_io()
            .expect("h2 error reported io cause without an underlying io error")
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}
