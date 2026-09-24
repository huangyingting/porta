use crate::ops::metrics::Metrics;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SHARDS: usize = 64;
const SURFACES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(usize)]
pub enum Surface {
    Native = 0,
    Proxy = 1,
    Portal = 2,
    Invitation = 3,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Proxy => "proxy",
            Self::Portal => "portal",
            Self::Invitation => "invitation",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub burst: u32,
    pub refill_interval: Duration,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
    last_seen: Instant,
}

#[derive(Debug)]
struct Shard {
    entries: HashMap<(Surface, IpAddr), Bucket>,
    overflow: [Option<Bucket>; SURFACES],
    next_prune: Instant,
}

pub struct AbuseGuard {
    shards: Box<[Mutex<Shard>]>,
    policies: [Policy; SURFACES],
    entries: AtomicUsize,
    max_entries: usize,
    idle_expiry: Duration,
    metrics: Arc<Metrics>,
}

pub struct Reservation<'a> {
    guard: &'a AbuseGuard,
    surface: Surface,
    address: IpAddr,
    shard: usize,
    overflow: bool,
    released: bool,
}

impl AbuseGuard {
    pub fn default_with_metrics(metrics: Arc<Metrics>) -> Self {
        Self::new(
            [
                Policy {
                    burst: 32,
                    refill_interval: Duration::from_secs(2),
                },
                Policy {
                    burst: 32,
                    refill_interval: Duration::from_secs(5),
                },
                Policy {
                    burst: 12,
                    refill_interval: Duration::from_secs(10),
                },
                Policy {
                    burst: 12,
                    refill_interval: Duration::from_secs(10),
                },
            ],
            4096,
            Duration::from_secs(15 * 60),
            metrics,
        )
    }

    pub fn new(
        policies: [Policy; SURFACES],
        max_entries: usize,
        idle_expiry: Duration,
        metrics: Arc<Metrics>,
    ) -> Self {
        assert!(max_entries > 0);
        assert!(!idle_expiry.is_zero());
        for policy in policies {
            assert!(policy.burst > 0);
            assert!(!policy.refill_interval.is_zero());
        }
        let now = Instant::now();
        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    entries: HashMap::with_capacity(max_entries.div_ceil(SHARDS)),
                    overflow: [None; SURFACES],
                    next_prune: now,
                })
            })
            .collect();
        Self {
            shards,
            policies,
            entries: AtomicUsize::new(0),
            max_entries,
            idle_expiry,
            metrics,
        }
    }

    pub fn reserve(&self, surface: Surface, address: IpAddr) -> Option<Reservation<'_>> {
        let address = normalize_address(address);
        let shard_index = address_shard(address);
        let now = Instant::now();
        let mut shard = self.shards[shard_index].lock();
        let key = (surface, address);
        let overflow = if shard.entries.contains_key(&key) {
            false
        } else {
            if now >= shard.next_prune {
                let expiry = self.idle_expiry;
                let previous_len = shard.entries.len();
                shard
                    .entries
                    .retain(|_, bucket| now.duration_since(bucket.last_seen) < expiry);
                self.entries
                    .fetch_sub(previous_len - shard.entries.len(), Ordering::Relaxed);
                shard.next_prune = now + self.idle_expiry.min(Duration::from_secs(60));
            }
            let reserved = self
                .entries
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |entries| {
                    (entries < self.max_entries).then_some(entries + 1)
                })
                .is_ok();
            if reserved {
                let policy = self.policies[surface as usize];
                shard.entries.insert(
                    key,
                    Bucket {
                        tokens: f64::from(policy.burst),
                        updated: now,
                        last_seen: now,
                    },
                );
                false
            } else {
                true
            }
        };
        let bucket = if overflow {
            shard.overflow[surface as usize].get_or_insert(Bucket {
                tokens: f64::from(self.policies[surface as usize].burst),
                updated: now,
                last_seen: now,
            })
        } else {
            shard.entries.get_mut(&key).expect("entry was inserted")
        };
        let policy = self.policies[surface as usize];
        refill(bucket, policy, now);
        bucket.last_seen = now;
        if bucket.tokens < 1.0 {
            drop(shard);
            self.metrics.abuse_rejected(surface.as_str());
            return None;
        }
        bucket.tokens -= 1.0;
        Some(Reservation {
            guard: self,
            surface,
            address,
            shard: shard_index,
            overflow,
            released: false,
        })
    }
}

impl Reservation<'_> {
    pub fn refund(mut self) {
        self.refund_inner();
    }

    fn refund_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let now = Instant::now();
        let policy = self.guard.policies[self.surface as usize];
        let mut shard = self.guard.shards[self.shard].lock();
        let bucket = if self.overflow {
            shard.overflow[self.surface as usize].as_mut()
        } else {
            shard.entries.get_mut(&(self.surface, self.address))
        };
        if let Some(bucket) = bucket {
            refill(bucket, policy, now);
            bucket.tokens = bucket.tokens.min(f64::from(policy.burst) - 1.0) + 1.0;
            bucket.last_seen = now;
        }
    }
}

fn refill(bucket: &mut Bucket, policy: Policy, now: Instant) {
    let elapsed = now.saturating_duration_since(bucket.updated);
    bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() / policy.refill_interval.as_secs_f64())
        .min(f64::from(policy.burst));
    bucket.updated = now;
}

fn normalize_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn address_shard(address: IpAddr) -> usize {
    let mut hash = 2166136261u32;
    match address {
        IpAddr::V4(address) => {
            for value in address.octets() {
                hash = (hash ^ u32::from(value)).wrapping_mul(16777619);
            }
        }
        IpAddr::V6(address) => {
            for value in address.octets() {
                hash = (hash ^ u32::from(value)).wrapping_mul(16777619);
            }
        }
    }
    hash as usize % SHARDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn only_explicit_refund_restores_capacity() {
        let metrics = Arc::new(Metrics::default());
        let guard = AbuseGuard::new(
            [Policy {
                burst: 1,
                refill_interval: Duration::from_secs(60),
            }; SURFACES],
            64,
            Duration::from_secs(60),
            metrics,
        );
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        {
            let _reservation = guard.reserve(Surface::Native, address).unwrap();
            assert!(guard.reserve(Surface::Native, address).is_none());
        }
        assert!(guard.reserve(Surface::Native, address).is_none());

        let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let reservation = guard.reserve(Surface::Native, other).unwrap();
        reservation.refund();
        assert!(guard.reserve(Surface::Native, other).is_some());
    }
}
