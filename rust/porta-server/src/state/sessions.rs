use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionKey {
    pub account_id: String,
    pub device_id: String,
}

impl SessionKey {
    pub fn new(account_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            device_id: device_id.into(),
        }
    }
}

struct ActiveSession {
    cancellation: CancellationToken,
    finished: CancellationToken,
}

struct SessionsInner {
    sessions: Mutex<HashMap<SessionKey, HashMap<u64, Arc<ActiveSession>>>>,
    next_id: AtomicU64,
}

#[derive(Clone)]
pub struct LiveSessions {
    inner: Arc<SessionsInner>,
}

impl Default for LiveSessions {
    fn default() -> Self {
        Self {
            inner: Arc::new(SessionsInner {
                sessions: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
        }
    }
}

pub struct SessionRegistration {
    pub cancellation: CancellationToken,
    guard: Option<SessionGuard>,
}

impl SessionRegistration {
    pub fn guard_mut(&mut self) -> &mut SessionGuard {
        self.guard.as_mut().expect("session guard is present")
    }

    pub fn into_parts(mut self) -> (CancellationToken, SessionGuard) {
        (
            self.cancellation.clone(),
            self.guard.take().expect("session guard is present"),
        )
    }

    pub fn finish(mut self) {
        self.guard.take();
    }
}

pub struct SessionGuard {
    inner: Weak<SessionsInner>,
    key: SessionKey,
    id: u64,
    session: Arc<ActiveSession>,
}

impl SessionGuard {
    pub fn cancellation(&self) -> &CancellationToken {
        &self.session.cancellation
    }

    pub fn finish(self) {}
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut sessions = inner.sessions.lock();
            if let Some(active) = sessions.get_mut(&self.key) {
                active.remove(&self.id);
                if active.is_empty() {
                    sessions.remove(&self.key);
                }
            }
        }
        self.session.finished.cancel();
    }
}

impl LiveSessions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        account_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> SessionRegistration {
        let key = SessionKey::new(account_id, device_id);
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(ActiveSession {
            cancellation: CancellationToken::new(),
            finished: CancellationToken::new(),
        });
        self.inner
            .sessions
            .lock()
            .entry(key.clone())
            .or_default()
            .insert(id, session.clone());
        SessionRegistration {
            cancellation: session.cancellation.clone(),
            guard: Some(SessionGuard {
                inner: Arc::downgrade(&self.inner),
                key,
                id,
                session,
            }),
        }
    }

    pub fn active_count(&self, account_id: &str, device_id: Option<&str>) -> usize {
        let sessions = self.inner.sessions.lock();
        sessions
            .iter()
            .filter(|(key, _)| {
                key.account_id == account_id
                    && device_id.is_none_or(|device_id| key.device_id == device_id)
            })
            .map(|(_, active)| active.len())
            .sum()
    }

    pub async fn cancel_account(&self, account_id: &str) -> usize {
        self.cancel_and_drain(account_id, None).await
    }

    pub async fn cancel_device(&self, account_id: &str, device_id: &str) -> usize {
        self.cancel_and_drain(account_id, Some(device_id)).await
    }

    pub async fn cancel_and_drain(&self, account_id: &str, device_id: Option<&str>) -> usize {
        let active = {
            let sessions = self.inner.sessions.lock();
            sessions
                .iter()
                .filter(|(key, _)| {
                    key.account_id == account_id
                        && device_id.is_none_or(|device_id| key.device_id == device_id)
                })
                .flat_map(|(_, active)| active.values().cloned())
                .collect::<Vec<_>>()
        };

        for session in &active {
            session.cancellation.cancel();
        }
        for session in &active {
            session.finished.cancelled().await;
        }
        active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancellation_signals_every_session_before_drain_waits() {
        let sessions = LiveSessions::new();
        let first = sessions.register("account", "phone");
        let second = sessions.register("account", "phone");
        let other = sessions.register("account", "laptop");
        let first_cancelled = first.cancellation.clone();
        let second_cancelled = second.cancellation.clone();
        let other_cancelled = other.cancellation.clone();

        let draining = {
            let sessions = sessions.clone();
            tokio::spawn(async move { sessions.cancel_device("account", "phone").await })
        };
        tokio::time::timeout(Duration::from_secs(1), first_cancelled.cancelled())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), second_cancelled.cancelled())
            .await
            .unwrap();
        assert!(!other_cancelled.is_cancelled());
        assert!(!draining.is_finished());

        drop(first);
        assert!(!draining.is_finished());
        drop(second);
        assert_eq!(draining.await.unwrap(), 2);
        assert_eq!(sessions.active_count("account", None), 1);
        drop(other);
    }

    #[tokio::test]
    async fn account_cancellation_is_scoped_and_registration_is_o_one() {
        let sessions = LiveSessions::new();
        let first = sessions.register("first", "shared-device");
        let second = sessions.register("second", "shared-device");
        let first_cancelled = first.cancellation.clone();
        let second_cancelled = second.cancellation.clone();

        let draining = {
            let sessions = sessions.clone();
            tokio::spawn(async move { sessions.cancel_account("first").await })
        };
        first_cancelled.cancelled().await;
        assert!(!second_cancelled.is_cancelled());
        drop(first);
        assert_eq!(draining.await.unwrap(), 1);
        drop(second);
    }

    #[test]
    fn dropping_registration_releases_session() {
        let sessions = LiveSessions::new();
        let registration = sessions.register("account", "device");
        assert_eq!(sessions.active_count("account", Some("device")), 1);
        registration.finish();
        assert_eq!(sessions.active_count("account", Some("device")), 0);
    }
}
