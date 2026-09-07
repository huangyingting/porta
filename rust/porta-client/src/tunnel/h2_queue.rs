use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use porta_wire::ip::{PacketClass, PacketMetadata};
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const DEFAULT_MAX_PACKETS: usize = 96;
const DEFAULT_MAX_BYTES: usize = 128 << 10;

#[derive(Clone, Copy)]
struct QueueConfig {
    max_packets: usize,
    max_bytes: usize,
    tcp_max_age: Duration,
    datagram_max_age: Duration,
    control_max_age: Duration,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_packets: DEFAULT_MAX_PACKETS,
            max_bytes: DEFAULT_MAX_BYTES,
            tcp_max_age: Duration::from_millis(500),
            datagram_max_age: Duration::from_millis(150),
            control_max_age: Duration::from_millis(250),
        }
    }
}

#[derive(Default)]
struct QueueStats {
    oldest_drops: AtomicU64,
    full_drops: AtomicU64,
    tail_drops: AtomicU64,
    expired_drops: AtomicU64,
    current_bytes: AtomicI64,
    high_water: AtomicU64,
}

struct QueuedPacket {
    data: Bytes,
    class: PacketClass,
    enqueued: Instant,
}

struct QueueState {
    items: VecDeque<QueuedPacket>,
    bytes: usize,
    closed: bool,
    active: bool,
}

pub(super) struct UploadQueue {
    state: Mutex<QueueState>,
    ready: Notify,
    config: QueueConfig,
    stats: QueueStats,
}

impl UploadQueue {
    pub(super) fn new() -> Self {
        Self::with_config(QueueConfig::default())
    }

    fn with_config(config: QueueConfig) -> Self {
        Self {
            state: Mutex::new(QueueState {
                items: VecDeque::with_capacity(config.max_packets),
                bytes: 0,
                closed: false,
                active: true,
            }),
            ready: Notify::new(),
            config,
            stats: QueueStats::default(),
        }
    }

    #[cfg(test)]
    pub(super) fn with_limits(max_packets: usize, max_bytes: usize) -> Self {
        Self::with_config(QueueConfig {
            max_packets,
            max_bytes,
            tcp_max_age: Duration::from_secs(60),
            datagram_max_age: Duration::from_secs(60),
            control_max_age: Duration::from_secs(60),
        })
    }

    pub(super) fn activate(&self) {
        let mut state = self.state.lock().expect("HTTP/2 upload queue poisoned");
        if !state.closed {
            state.active = true;
        }
    }

    pub(super) fn deactivate_and_clear(&self) {
        let mut state = self.state.lock().expect("HTTP/2 upload queue poisoned");
        state.active = false;
        self.clear_locked(&mut state);
    }

    pub(super) fn close(&self) {
        let mut state = self.state.lock().expect("HTTP/2 upload queue poisoned");
        if state.closed {
            return;
        }
        state.closed = true;
        state.active = false;
        self.clear_locked(&mut state);
        drop(state);
        self.ready.notify_waiters();
    }

    pub(super) fn enqueue(
        &self,
        packet: Bytes,
        metadata: PacketMetadata,
        now: Instant,
    ) -> Result<(), Bytes> {
        let mut state = self.state.lock().expect("HTTP/2 upload queue poisoned");
        if state.closed || !state.active {
            return Err(packet);
        }
        self.drop_expired_locked(&mut state, now);
        if packet.len() > self.config.max_bytes || self.config.max_packets == 0 {
            self.record_rejected(metadata.class);
            return Err(packet);
        }
        while !self.fits_locked(&state, packet.len()) {
            let Some(victim) = self.oldest_replaceable_locked(&state, metadata.class) else {
                self.record_rejected(metadata.class);
                return Err(packet);
            };
            let removed = state
                .items
                .remove(victim)
                .expect("selected queue victim exists");
            self.adjust_bytes_locked(&mut state, -(removed.data.len() as isize));
            self.stats.oldest_drops.fetch_add(1, Ordering::Relaxed);
        }
        let was_empty = state.items.is_empty();
        self.adjust_bytes_locked(&mut state, packet.len() as isize);
        state.items.push_back(QueuedPacket {
            data: packet,
            class: metadata.class,
            enqueued: now,
        });
        drop(state);
        if was_empty {
            self.ready.notify_one();
        }
        Ok(())
    }

    pub(super) async fn take_batch(
        &self,
        cancellation: &CancellationToken,
        max_packets: usize,
        max_bytes: usize,
    ) -> Option<Vec<Bytes>> {
        loop {
            let notified = self.ready.notified();
            {
                let mut state = self.state.lock().expect("HTTP/2 upload queue poisoned");
                self.drop_expired_locked(&mut state, Instant::now());
                if !state.items.is_empty() {
                    let mut batch = Vec::with_capacity(max_packets.min(state.items.len()));
                    let mut bytes = 0;
                    while batch.len() < max_packets {
                        let Some(next) = state.items.front() else {
                            break;
                        };
                        if !batch.is_empty() && bytes + next.data.len() > max_bytes {
                            break;
                        }
                        let packet = state.items.pop_front().expect("front packet exists");
                        bytes += packet.data.len();
                        batch.push(packet.data);
                    }
                    self.adjust_bytes_locked(&mut state, -(bytes as isize));
                    return Some(batch);
                }
                if state.closed {
                    return None;
                }
            }
            tokio::select! {
                _ = cancellation.cancelled() => return None,
                _ = notified => {}
            }
        }
    }

    pub(super) fn queued_bytes_at(&self, now: Instant) -> usize {
        let mut state = self.state.lock().expect("HTTP/2 upload queue poisoned");
        self.drop_expired_locked(&mut state, now);
        state.bytes
    }

    fn fits_locked(&self, state: &QueueState, packet_bytes: usize) -> bool {
        state.items.len() < self.config.max_packets
            && state.bytes + packet_bytes <= self.config.max_bytes
    }

    fn drop_expired_locked(&self, state: &mut QueueState, now: Instant) {
        let mut index = 0;
        while index < state.items.len() {
            let item = &state.items[index];
            if now.duration_since(item.enqueued) < self.max_age(item.class) {
                index += 1;
                continue;
            }
            let removed = state
                .items
                .remove(index)
                .expect("expired queue item exists");
            self.adjust_bytes_locked(state, -(removed.data.len() as isize));
            self.stats.expired_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn max_age(&self, class: PacketClass) -> Duration {
        match class {
            PacketClass::Tcp => self.config.tcp_max_age,
            PacketClass::Control => self.config.control_max_age,
            PacketClass::Datagram => self.config.datagram_max_age,
        }
    }

    fn oldest_replaceable_locked(
        &self,
        state: &QueueState,
        incoming: PacketClass,
    ) -> Option<usize> {
        state
            .items
            .iter()
            .position(|item| item.class == PacketClass::Datagram)
            .or_else(|| {
                (incoming == PacketClass::Control)
                    .then(|| {
                        state
                            .items
                            .iter()
                            .position(|item| item.class == PacketClass::Control)
                    })
                    .flatten()
            })
    }

    fn record_rejected(&self, class: PacketClass) {
        if class == PacketClass::Tcp {
            self.stats.tail_drops.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.full_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn adjust_bytes_locked(&self, state: &mut QueueState, delta: isize) {
        state.bytes = state.bytes.saturating_add_signed(delta);
        let current = self
            .stats
            .current_bytes
            .fetch_add(delta as i64, Ordering::Relaxed)
            + delta as i64;
        if current < 0 {
            self.stats.current_bytes.store(0, Ordering::Relaxed);
            return;
        }
        self.stats
            .high_water
            .fetch_max(current as u64, Ordering::Relaxed);
    }

    fn clear_locked(&self, state: &mut QueueState) {
        state.items.clear();
        state.bytes = 0;
        self.stats.current_bytes.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(class: PacketClass) -> PacketMetadata {
        PacketMetadata {
            class,
            ..PacketMetadata::default()
        }
    }

    #[test]
    fn overflow_preserves_tcp_prefix_and_evicts_datagrams() {
        let queue = UploadQueue::with_config(QueueConfig {
            max_packets: 2,
            max_bytes: 256,
            ..QueueConfig::default()
        });
        let now = Instant::now();
        assert!(queue
            .enqueue(Bytes::from_static(&[1]), metadata(PacketClass::Tcp), now)
            .is_ok());
        assert!(queue
            .enqueue(Bytes::from_static(&[2]), metadata(PacketClass::Tcp), now)
            .is_ok());
        assert!(queue
            .enqueue(Bytes::from_static(&[3]), metadata(PacketClass::Tcp), now)
            .is_err());
        assert_eq!(queue.stats.tail_drops.load(Ordering::Relaxed), 1);

        queue.deactivate_and_clear();
        queue.activate();
        assert!(queue
            .enqueue(
                Bytes::from_static(&[4]),
                metadata(PacketClass::Datagram),
                now
            )
            .is_ok());
        assert!(queue
            .enqueue(Bytes::from_static(&[5]), metadata(PacketClass::Tcp), now)
            .is_ok());
        assert!(queue
            .enqueue(
                Bytes::from_static(&[6]),
                metadata(PacketClass::Control),
                now
            )
            .is_ok());
        assert_eq!(queue.stats.oldest_drops.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn batches_are_bounded_and_expired_packets_are_discarded() {
        let queue = UploadQueue::with_config(QueueConfig {
            max_packets: 8,
            max_bytes: 1024,
            datagram_max_age: Duration::from_millis(1),
            ..QueueConfig::default()
        });
        let old = Instant::now() - Duration::from_millis(10);
        assert!(queue
            .enqueue(
                Bytes::from(vec![1; 20]),
                metadata(PacketClass::Datagram),
                old
            )
            .is_ok());
        let now = Instant::now();
        for marker in 2..=4 {
            assert!(queue
                .enqueue(
                    Bytes::from(vec![marker; 60]),
                    metadata(PacketClass::Tcp),
                    now
                )
                .is_ok());
        }
        let cancellation = CancellationToken::new();
        let first = queue.take_batch(&cancellation, 2, 100).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0][0], 2);
        let second = queue.take_batch(&cancellation, 2, 120).await.unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(queue.stats.expired_drops.load(Ordering::Relaxed), 1);
        assert_eq!(queue.stats.current_bytes.load(Ordering::Relaxed), 0);
    }
}
