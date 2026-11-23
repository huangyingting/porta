//! Per-account throughput limits.
//!
//! Each account has one token bucket per direction, shared by all of its
//! devices and transport lanes. Packets beyond the configured rate are
//! dropped (policing); tunneled TCP adapts to the loss like it would to a
//! slower link.

use crate::ops::metrics::Metrics;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Smallest burst allowance: enough for several full-size packets so that
/// low limits still carry interactive traffic.
const MIN_BURST_BYTES: f64 = 64.0 * 1024.0;
/// Burst allowance as a fraction of one second of the configured rate.
const BURST_SECONDS: f64 = 0.2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Uplink,
    Downlink,
}

#[derive(Default)]
pub struct RateLimiters {
    accounts: RwLock<HashMap<String, Arc<AccountRateLimiter>>>,
    /// Lets the packet path skip lookups while no account is limited.
    any_limited: AtomicBool,
    metrics: Option<Arc<Metrics>>,
}

impl RateLimiters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn with_metrics(metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            metrics: Some(metrics),
            ..Self::default()
        })
    }

    pub fn any_limited(&self) -> bool {
        self.any_limited.load(Ordering::Relaxed)
    }

    /// Returns the account's shared limiter, creating an unlimited one.
    pub fn limiter(&self, account_id: &str) -> Arc<AccountRateLimiter> {
        if let Some(limiter) = self.accounts.read().get(account_id) {
            return limiter.clone();
        }
        self.accounts
            .write()
            .entry(account_id.to_owned())
            .or_default()
            .clone()
    }

    /// Applies the configured limits; accounts not listed become unlimited.
    pub fn configure(&self, limits: impl IntoIterator<Item = (String, Option<u32>)>) {
        let mut configured = HashMap::new();
        for (account_id, kbps) in limits {
            configured.insert(account_id, kbps);
        }
        let mut any = false;
        {
            let mut accounts = self.accounts.write();
            for (account_id, kbps) in &configured {
                if let Some(kbps) = kbps {
                    any = true;
                    accounts
                        .entry(account_id.clone())
                        .or_default()
                        .set_rate_kbps(*kbps);
                }
            }
            accounts.retain(|account_id, limiter| {
                if !configured
                    .get(account_id)
                    .is_some_and(|kbps| kbps.is_some())
                {
                    limiter.set_rate_kbps(0);
                }
                // Keep limiters that live sessions still reference.
                configured.contains_key(account_id) || Arc::strong_count(limiter) > 1
            });
        }
        self.any_limited.store(any, Ordering::Relaxed);
    }

    pub fn record_drop(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.queue_drop("rate_limited");
        }
    }
}

#[derive(Default)]
pub struct AccountRateLimiter {
    /// Bytes per second; zero means unlimited.
    rate: AtomicU64,
    uplink: Mutex<Bucket>,
    downlink: Mutex<Bucket>,
}

#[derive(Default)]
struct Bucket {
    tokens: f64,
    updated: Option<Instant>,
}

impl AccountRateLimiter {
    fn set_rate_kbps(&self, kbps: u32) {
        self.rate
            .store(u64::from(kbps) * 1000 / 8, Ordering::Relaxed);
    }

    pub fn is_limited(&self) -> bool {
        self.rate.load(Ordering::Relaxed) != 0
    }

    /// Consumes `bytes` from the direction's bucket, or returns false when
    /// the packet exceeds the account's rate.
    pub fn allow(&self, direction: Direction, bytes: usize) -> bool {
        self.allow_at(direction, bytes, Instant::now())
    }

    fn allow_at(&self, direction: Direction, bytes: usize, now: Instant) -> bool {
        let rate = self.rate.load(Ordering::Relaxed);
        if rate == 0 {
            return true;
        }
        let rate = rate as f64;
        let burst = (rate * BURST_SECONDS).max(MIN_BURST_BYTES);
        let mut bucket = match direction {
            Direction::Uplink => self.uplink.lock(),
            Direction::Downlink => self.downlink.lock(),
        };
        bucket.tokens = match bucket.updated {
            Some(updated) => (bucket.tokens
                + now.saturating_duration_since(updated).as_secs_f64() * rate)
                .min(burst),
            None => burst,
        };
        bucket.updated = Some(now);
        let bytes = bytes as f64;
        if bucket.tokens >= bytes {
            bucket.tokens -= bytes;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unlimited_accounts_pass_without_configuration() {
        let limiters = RateLimiters::new();
        let limiter = limiters.limiter("a");
        assert!(!limiters.any_limited());
        for _ in 0..10_000 {
            assert!(limiter.allow(Direction::Uplink, 1500));
        }
    }

    #[test]
    fn policing_enforces_the_rate_after_the_burst() {
        let limiters = RateLimiters::new();
        limiters.configure([("a".to_owned(), Some(8_000))]);
        assert!(limiters.any_limited());
        let limiter = limiters.limiter("a");
        // 8 Mbit/s = 1 MB/s; burst is 200 kB.
        let start = Instant::now();
        let mut sent = 0;
        while limiter.allow_at(Direction::Downlink, 1000, start) {
            sent += 1000;
        }
        assert_eq!(sent, 200_000);
        assert!(!limiter.allow_at(Direction::Downlink, 1000, start));
        // 100 ms refills 100 kB.
        let later = start + Duration::from_millis(100);
        let mut refilled = 0;
        while limiter.allow_at(Direction::Downlink, 1000, later) {
            refilled += 1000;
        }
        assert_eq!(refilled, 100_000);
        // Directions are independent.
        assert!(limiter.allow_at(Direction::Uplink, 1000, start));
    }

    #[test]
    fn small_limits_keep_a_minimum_burst_and_removal_unlimits_live_sessions() {
        let limiters = RateLimiters::new();
        limiters.configure([("a".to_owned(), Some(64))]);
        let limiter = limiters.limiter("a");
        let now = Instant::now();
        let mut sent = 0;
        while limiter.allow_at(Direction::Uplink, 1500, now) {
            sent += 1500;
        }
        assert!(sent >= 64 * 1024 - 1500);
        limiters.configure([("a".to_owned(), None)]);
        assert!(!limiters.any_limited());
        assert!(!limiter.is_limited());
        assert!(limiter.allow_at(Direction::Uplink, 1500, now));
        // Accounts that disappear keep their limiter while sessions use it.
        limiters.configure(Vec::new());
        assert!(Arc::ptr_eq(&limiter, &limiters.limiter("a")));
    }
}
