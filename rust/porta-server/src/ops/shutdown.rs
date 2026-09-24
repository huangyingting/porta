use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct Drain {
    inner: Arc<DrainInner>,
}

#[derive(Debug)]
struct DrainInner {
    accepting: AtomicBool,
    active: AtomicUsize,
    idle: Notify,
    cancelled: CancellationToken,
}

#[derive(Debug)]
pub struct RequestGuard {
    inner: Arc<DrainInner>,
}

impl Drain {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DrainInner {
                accepting: AtomicBool::new(true),
                active: AtomicUsize::new(0),
                idle: Notify::new(),
                cancelled: CancellationToken::new(),
            }),
        }
    }

    pub fn begin_request(&self) -> Option<RequestGuard> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return None;
        }
        self.inner.active.fetch_add(1, Ordering::AcqRel);
        if !self.inner.accepting.load(Ordering::Acquire) {
            if self.inner.active.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.inner.idle.notify_waiters();
            }
            return None;
        }
        Some(RequestGuard {
            inner: self.inner.clone(),
        })
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.inner.cancelled.clone()
    }

    pub fn stop(&self) {
        self.inner.accepting.store(false, Ordering::Release);
        self.inner.cancelled.cancel();
        if self.inner.active.load(Ordering::Acquire) == 0 {
            self.inner.idle.notify_waiters();
        }
    }

    pub async fn wait(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                let notified = self.inner.idle.notified();
                tokio::pin!(notified);
                if self.inner.active.load(Ordering::Acquire) == 0 {
                    break;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }

    pub fn active(&self) -> usize {
        self.inner.active.load(Ordering::Acquire)
    }
}

impl Default for Drain {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.inner.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_rejects_new_requests_and_waits_for_active_request() {
        let drain = Drain::new();
        let request = drain.begin_request().unwrap();
        drain.stop();
        assert!(drain.begin_request().is_none());
        assert_eq!(drain.active(), 1);
        assert!(!drain.wait(Duration::from_millis(1)).await);
        drop(request);
        assert!(drain.wait(Duration::from_secs(1)).await);
        assert!(drain.cancellation().is_cancelled());
    }
}
