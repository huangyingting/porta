use crate::ops::metrics::Metrics;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

const SOURCE_SHARDS: usize = 64;
const RETRY_BUCKETS: usize = 4096;
const RETRY_BUCKETS_PER_SHARD: usize = RETRY_BUCKETS / SOURCE_SHARDS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejection {
    Global,
    Source,
    Unverified,
}

impl Rejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Source => "source",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transport {
    Tcp,
    Quic,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }
}

pub struct ConnectionAdmission {
    inner: Arc<AdmissionInner>,
}

struct AdmissionInner {
    active_tcp: AtomicUsize,
    active_quic: AtomicUsize,
    unverified_quic: AtomicUsize,
    tcp_sources: Box<[Mutex<HashMap<IpAddr, usize>>]>,
    quic_sources: Box<[Mutex<HashMap<IpAddr, usize>>]>,
    max_global: usize,
    max_per_source: usize,
    max_unverified: usize,
    retry_threshold: usize,
    metrics: Arc<Metrics>,
}

pub struct AdmissionPermit {
    inner: Arc<AdmissionInner>,
    transport: Transport,
    source: Option<IpAddr>,
    verified: bool,
}

impl ConnectionAdmission {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self::with_limits(4096, 256, 512, 384, metrics)
    }

    pub fn with_limits(
        max_global: usize,
        max_per_source: usize,
        max_unverified: usize,
        retry_threshold: usize,
        metrics: Arc<Metrics>,
    ) -> Self {
        assert!(max_global > 0 && max_unverified > 0);
        let sources = || {
            (0..SOURCE_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect()
        };
        Self {
            inner: Arc::new(AdmissionInner {
                active_tcp: AtomicUsize::new(0),
                active_quic: AtomicUsize::new(0),
                unverified_quic: AtomicUsize::new(0),
                tcp_sources: sources(),
                quic_sources: sources(),
                max_global,
                max_per_source,
                max_unverified,
                retry_threshold,
                metrics,
            }),
        }
    }

    pub fn admit_tcp(&self, remote: SocketAddr) -> Result<AdmissionPermit, Rejection> {
        self.admit(Transport::Tcp, remote.ip(), true)
    }

    pub fn admit_quic(
        &self,
        remote: SocketAddr,
        verified: bool,
    ) -> Result<AdmissionPermit, Rejection> {
        self.admit(Transport::Quic, remote.ip(), verified)
    }

    pub fn under_unverified_pressure(&self) -> bool {
        self.inner.unverified_quic.load(Ordering::Relaxed) >= self.inner.retry_threshold
    }

    fn admit(
        &self,
        transport: Transport,
        source: IpAddr,
        verified: bool,
    ) -> Result<AdmissionPermit, Rejection> {
        let active = match transport {
            Transport::Tcp => &self.inner.active_tcp,
            Transport::Quic => &self.inner.active_quic,
        };
        if active.fetch_add(1, Ordering::AcqRel) >= self.inner.max_global {
            active.fetch_sub(1, Ordering::AcqRel);
            self.reject(transport, Rejection::Global);
            return Err(Rejection::Global);
        }
        if transport == Transport::Quic
            && !verified
            && self.inner.unverified_quic.fetch_add(1, Ordering::AcqRel)
                >= self.inner.max_unverified
        {
            self.inner.unverified_quic.fetch_sub(1, Ordering::AcqRel);
            active.fetch_sub(1, Ordering::AcqRel);
            self.reject(transport, Rejection::Unverified);
            return Err(Rejection::Unverified);
        }
        let source = normalize_address(source);
        if verified && self.inner.max_per_source > 0 {
            let shards = match transport {
                Transport::Tcp => &self.inner.tcp_sources,
                Transport::Quic => &self.inner.quic_sources,
            };
            let mut shard = shards[address_shard(source, SOURCE_SHARDS)].lock();
            let count = shard.entry(source).or_default();
            if *count >= self.inner.max_per_source {
                active.fetch_sub(1, Ordering::AcqRel);
                self.reject(transport, Rejection::Source);
                return Err(Rejection::Source);
            }
            *count += 1;
        }
        self.inner
            .metrics
            .public_connection_opened(transport.as_str());
        Ok(AdmissionPermit {
            inner: self.inner.clone(),
            transport,
            source: verified.then_some(source),
            verified,
        })
    }

    fn reject(&self, transport: Transport, rejection: Rejection) {
        self.inner
            .metrics
            .public_connection_rejected(transport.as_str(), rejection.as_str());
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let active = match self.transport {
            Transport::Tcp => &self.inner.active_tcp,
            Transport::Quic => &self.inner.active_quic,
        };
        active.fetch_sub(1, Ordering::AcqRel);
        if self.transport == Transport::Quic && !self.verified {
            self.inner.unverified_quic.fetch_sub(1, Ordering::AcqRel);
        }

        if let Some(source) = self.source {
            let shards = match self.transport {
                Transport::Tcp => &self.inner.tcp_sources,
                Transport::Quic => &self.inner.quic_sources,
            };
            let mut shard = shards[address_shard(source, SOURCE_SHARDS)].lock();
            if let Some(count) = shard.get_mut(&source) {
                *count -= 1;
                if *count == 0 {
                    shard.remove(&source);
                }
            }
        }
        self.inner
            .metrics
            .public_connection_closed(self.transport.as_str());
    }
}

impl AdmissionPermit {
    pub fn mark_verified(&mut self, remote: SocketAddr) -> Result<(), Rejection> {
        if self.transport != Transport::Quic || self.verified {
            return Ok(());
        }
        let source = normalize_address(remote.ip());
        if self.inner.max_per_source > 0 {
            let mut shard = self.inner.quic_sources[address_shard(source, SOURCE_SHARDS)].lock();
            let count = shard.entry(source).or_default();
            if *count >= self.inner.max_per_source {
                self.inner
                    .metrics
                    .public_connection_rejected("quic", Rejection::Source.as_str());
                return Err(Rejection::Source);
            }
            *count += 1;
        }
        self.inner.unverified_quic.fetch_sub(1, Ordering::AcqRel);
        self.source = Some(source);
        self.verified = true;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct RetryBucket {
    tokens: f64,
    updated: Instant,
}

pub struct RetryController {
    global: Mutex<RetryBucket>,
    sources: Box<[Mutex<[Option<RetryBucket>; RETRY_BUCKETS_PER_SHARD]>]>,
    admission: Arc<AdmissionInner>,
    metrics: Arc<Metrics>,
    rate: f64,
    burst: f64,
    source_burst: f64,
}

impl RetryController {
    pub fn new(admission: &ConnectionAdmission, metrics: Arc<Metrics>) -> Self {
        let now = Instant::now();
        Self {
            global: Mutex::new(RetryBucket {
                tokens: 1000.0,
                updated: now,
            }),
            sources: (0..SOURCE_SHARDS)
                .map(|_| Mutex::new([None; RETRY_BUCKETS_PER_SHARD]))
                .collect(),
            admission: admission.inner.clone(),
            metrics,
            rate: 500.0,
            burst: 1000.0,
            source_burst: 8.0,
        }
    }

    pub fn should_retry(&self, remote: SocketAddr) -> bool {
        if self.admission.unverified_quic.load(Ordering::Relaxed) >= self.admission.retry_threshold
        {
            self.metrics.quic_retry();
            return true;
        }
        let now = Instant::now();
        let global_allowed = {
            let mut bucket = self.global.lock();
            refill_retry(&mut bucket, self.rate, self.burst, now);
            let allowed = bucket.tokens >= 1.0;
            if allowed {
                bucket.tokens -= 1.0;
            }
            allowed
        };
        let bucket_index = address_shard(normalize_address(remote.ip()), RETRY_BUCKETS);
        let shard_index = bucket_index / RETRY_BUCKETS_PER_SHARD;
        let local_index = bucket_index % RETRY_BUCKETS_PER_SHARD;
        let source_allowed = {
            let mut shard = self.sources[shard_index].lock();
            let bucket = shard[local_index].get_or_insert(RetryBucket {
                tokens: self.source_burst,
                updated: now,
            });
            let allowed = bucket.tokens >= 1.0;
            if allowed {
                bucket.tokens -= 1.0;
            }
            allowed
        };
        let retry = !global_allowed || !source_allowed;
        if retry {
            self.metrics.quic_retry();
        }
        retry
    }
}

fn refill_retry(bucket: &mut RetryBucket, rate: f64, burst: f64, now: Instant) {
    let elapsed = now.saturating_duration_since(bucket.updated);
    bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * rate).min(burst);
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

fn address_shard(address: IpAddr, shards: usize) -> usize {
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
    hash as usize % shards
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn enforces_and_releases_per_source_limit() {
        let metrics = Arc::new(Metrics::default());
        let admission = ConnectionAdmission::with_limits(4, 1, 2, 1, metrics);
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234));
        let permit = admission.admit_tcp(remote).unwrap();
        assert!(matches!(
            admission.admit_tcp(remote),
            Err(Rejection::Source)
        ));
        drop(permit);
        assert!(admission.admit_tcp(remote).is_ok());
    }

    #[test]
    fn unverified_pressure_requests_retry() {
        let metrics = Arc::new(Metrics::default());
        let admission = ConnectionAdmission::with_limits(4, 4, 2, 1, metrics.clone());
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234));
        let _permit = admission.admit_quic(remote, false).unwrap();
        let retry = RetryController::new(&admission, metrics);
        assert!(retry.should_retry(remote));
    }

    #[test]
    fn quic_permit_transitions_to_verified_source_accounting() {
        let metrics = Arc::new(Metrics::default());
        let admission = ConnectionAdmission::with_limits(4, 1, 2, 2, metrics);
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234));
        let mut first = admission.admit_quic(remote, false).unwrap();
        first.mark_verified(remote).unwrap();
        let mut second = admission.admit_quic(remote, false).unwrap();
        assert_eq!(second.mark_verified(remote), Err(Rejection::Source));
        drop(first);
        second.mark_verified(remote).unwrap();
    }
}
