use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub const DEFAULT_MAX_PACKETS: usize = 96;
pub const DEFAULT_MAX_BYTES: usize = 128 << 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuePolicy {
    ClassAware,
    DropOldest,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DropReason {
    QueueOldest,
    QueueFull,
    QueueTail,
    QueueExpired,
    SessionClosed,
    InvalidTunPacket,
    NoSession,
}

pub trait DataMetrics: Send + Sync + 'static {
    fn dropped(&self, _reason: DropReason) {}
    fn adjust_queue_bytes(&self, _lane: usize, _delta: isize) {}
    fn lane_collapsed(&self) {}
}

#[derive(Clone, Debug)]
pub struct QueueConfig {
    pub max_packets: usize,
    pub max_bytes: usize,
    pub tcp_max_age: Duration,
    pub datagram_max_age: Duration,
    pub control_max_age: Duration,
    pub policy: QueuePolicy,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_packets: DEFAULT_MAX_PACKETS,
            max_bytes: DEFAULT_MAX_BYTES,
            tcp_max_age: Duration::from_millis(500),
            datagram_max_age: Duration::from_millis(150),
            control_max_age: Duration::from_millis(250),
            policy: QueuePolicy::ClassAware,
        }
    }
}

impl QueueConfig {
    pub fn masque() -> Self {
        Self {
            max_packets: 256,
            max_bytes: 256 * 9000,
            tcp_max_age: Duration::ZERO,
            datagram_max_age: Duration::ZERO,
            control_max_age: Duration::ZERO,
            policy: QueuePolicy::DropOldest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueResult {
    Accepted,
    DroppedFull,
    DroppedTail,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PacketClass {
    Tcp,
    Datagram,
    Control,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FlowKey {
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    fragment_id: u16,
    protocol: u8,
    fragmented: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PacketMetadata {
    pub class: PacketClass,
    pub flow: FlowKey,
    pub hash: u32,
}

struct QueuedPacket {
    data: Bytes,
    class: PacketClass,
    enqueued: Instant,
}

#[derive(Default)]
struct QueueState {
    items: VecDeque<QueuedPacket>,
    bytes: usize,
    closed: bool,
}

pub struct PacketQueue {
    state: Mutex<QueueState>,
    config: QueueConfig,
    metrics: Option<Arc<dyn DataMetrics>>,
    lane: Option<usize>,
    queued_bytes: AtomicUsize,
    queued_packets: AtomicUsize,
    ready: Notify,
}

impl PacketQueue {
    pub fn new(
        config: QueueConfig,
        metrics: Option<Arc<dyn DataMetrics>>,
        lane: Option<usize>,
    ) -> Self {
        Self {
            state: Mutex::new(QueueState {
                items: VecDeque::with_capacity(config.max_packets),
                ..QueueState::default()
            }),
            config,
            metrics,
            lane,
            queued_bytes: AtomicUsize::new(0),
            queued_packets: AtomicUsize::new(0),
            ready: Notify::new(),
        }
    }

    pub fn enqueue(&self, packet: Bytes) -> EnqueueResult {
        self.enqueue_at(packet, Instant::now())
    }

    pub fn try_dequeue(&self) -> Option<Bytes> {
        self.dequeue_at(Instant::now())
    }

    pub async fn recv(&self) -> Option<Bytes> {
        self.recv_with_hook(|| {}).await
    }

    async fn recv_with_hook(&self, mut before_wait: impl FnMut()) -> Option<Bytes> {
        loop {
            let ready = self.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            if let Some(packet) = self.try_dequeue() {
                return Some(packet);
            }
            if self.is_closed() {
                return None;
            }
            before_wait();
            ready.await;
        }
    }

    pub fn close(&self) {
        let removed_bytes = {
            let mut state = self.state.lock();
            if state.closed {
                return;
            }
            state.closed = true;
            let removed = state.bytes;
            state.items.clear();
            state.bytes = 0;
            removed
        };
        self.queued_bytes.store(0, Ordering::Release);
        self.queued_packets.store(0, Ordering::Release);
        self.adjust_bytes(-(removed_bytes as isize));
        self.ready.notify_waiters();
        self.ready.notify_one();
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().closed
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::Acquire)
    }

    pub fn queued_packets(&self) -> usize {
        self.queued_packets.load(Ordering::Acquire)
    }

    fn enqueue_at(&self, packet: Bytes, now: Instant) -> EnqueueResult {
        let metadata = classify_ipv4(&packet);
        let mut state = self.state.lock();
        if state.closed {
            return EnqueueResult::Closed;
        }
        self.drop_expired_locked(&mut state, now);
        if self.fits(&state, packet.len()) {
            self.append_locked(&mut state, packet, metadata.class, now);
            return EnqueueResult::Accepted;
        }

        while !self.fits(&state, packet.len()) {
            let victim = match self.config.policy {
                QueuePolicy::DropOldest => (!state.items.is_empty()).then_some(0),
                QueuePolicy::ClassAware => oldest_replaceable(&state.items, metadata.class),
            };
            let Some(victim) = victim else {
                let result = if metadata.class == PacketClass::Tcp {
                    self.record_drop(DropReason::QueueTail);
                    EnqueueResult::DroppedTail
                } else {
                    self.record_drop(DropReason::QueueFull);
                    EnqueueResult::DroppedFull
                };
                return result;
            };
            self.remove_locked(&mut state, victim);
            self.record_drop(DropReason::QueueOldest);
        }

        self.append_locked(&mut state, packet, metadata.class, now);
        EnqueueResult::Accepted
    }

    fn dequeue_at(&self, now: Instant) -> Option<Bytes> {
        let mut state = self.state.lock();
        if state.closed {
            return None;
        }
        self.drop_expired_locked(&mut state, now);
        let item = state.items.pop_front()?;
        state.bytes -= item.data.len();
        self.publish_load(&state);
        self.adjust_bytes(-(item.data.len() as isize));
        Some(item.data)
    }

    fn fits(&self, state: &QueueState, packet_bytes: usize) -> bool {
        state.items.len() < self.config.max_packets
            && state
                .bytes
                .checked_add(packet_bytes)
                .is_some_and(|bytes| bytes <= self.config.max_bytes)
    }

    fn append_locked(&self, state: &mut QueueState, data: Bytes, class: PacketClass, now: Instant) {
        let was_empty = state.items.is_empty();
        let size = data.len();
        state.items.push_back(QueuedPacket {
            data,
            class,
            enqueued: now,
        });
        state.bytes += size;
        self.publish_load(state);
        self.adjust_bytes(size as isize);
        if was_empty {
            self.ready.notify_one();
        }
    }

    fn remove_locked(&self, state: &mut QueueState, index: usize) {
        if let Some(item) = state.items.remove(index) {
            state.bytes -= item.data.len();
            self.publish_load(state);
            self.adjust_bytes(-(item.data.len() as isize));
        }
    }

    fn drop_expired_locked(&self, state: &mut QueueState, now: Instant) {
        let mut index = 0;
        while index < state.items.len() {
            let item = &state.items[index];
            let max_age = match item.class {
                PacketClass::Tcp => self.config.tcp_max_age,
                PacketClass::Datagram => self.config.datagram_max_age,
                PacketClass::Control => self.config.control_max_age,
            };
            if max_age.is_zero() || now.saturating_duration_since(item.enqueued) < max_age {
                index += 1;
                continue;
            }
            self.remove_locked(state, index);
            self.record_drop(DropReason::QueueExpired);
        }
    }

    fn publish_load(&self, state: &QueueState) {
        self.queued_bytes.store(state.bytes, Ordering::Release);
        self.queued_packets
            .store(state.items.len(), Ordering::Release);
    }

    fn adjust_bytes(&self, delta: isize) {
        if delta != 0 {
            if let (Some(metrics), Some(lane)) = (&self.metrics, self.lane) {
                metrics.adjust_queue_bytes(lane, delta);
            }
        }
    }

    fn record_drop(&self, reason: DropReason) {
        if let Some(metrics) = &self.metrics {
            metrics.dropped(reason);
        }
    }
}

impl Drop for PacketQueue {
    fn drop(&mut self) {
        self.close();
    }
}

fn oldest_replaceable(items: &VecDeque<QueuedPacket>, incoming: PacketClass) -> Option<usize> {
    items
        .iter()
        .position(|item| item.class == PacketClass::Datagram)
        .or_else(|| {
            (incoming == PacketClass::Control)
                .then(|| {
                    items
                        .iter()
                        .position(|item| item.class == PacketClass::Control)
                })
                .flatten()
        })
}

pub(crate) fn classify_ipv4(packet: &[u8]) -> PacketMetadata {
    let mut metadata = PacketMetadata {
        class: PacketClass::Datagram,
        flow: FlowKey {
            source: [0; 4],
            destination: [0; 4],
            source_port: 0,
            destination_port: 0,
            fragment_id: 0,
            protocol: 0,
            fragmented: false,
        },
        hash: 0,
    };
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return metadata;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return metadata;
    }
    metadata.flow.source.copy_from_slice(&packet[12..16]);
    metadata.flow.destination.copy_from_slice(&packet[16..20]);
    metadata.flow.protocol = packet[9];
    let flags_and_offset = u16::from_be_bytes([packet[6], packet[7]]);
    metadata.flow.fragmented = flags_and_offset & 0x3fff != 0;
    if metadata.flow.fragmented {
        metadata.flow.fragment_id = u16::from_be_bytes([packet[4], packet[5]]);
    }
    let has_ports = !metadata.flow.fragmented
        && matches!(metadata.flow.protocol, 6 | 17)
        && packet.len() >= header_length + 4;
    if has_ports {
        metadata.flow.source_port =
            u16::from_be_bytes([packet[header_length], packet[header_length + 1]]);
        metadata.flow.destination_port =
            u16::from_be_bytes([packet[header_length + 2], packet[header_length + 3]]);
    }
    metadata.class = match metadata.flow.protocol {
        1 => PacketClass::Control,
        6 if has_ports
            && (metadata.flow.source_port == 53
                || metadata.flow.destination_port == 53
                || tcp_ack_only(packet, header_length)) =>
        {
            PacketClass::Control
        }
        6 => PacketClass::Tcp,
        17 if has_ports
            && (metadata.flow.source_port == 53
                || metadata.flow.destination_port == 53
                || packet.len() <= 256) =>
        {
            PacketClass::Control
        }
        _ => PacketClass::Datagram,
    };
    metadata.hash = hash_flow(metadata.flow);
    metadata
}

fn tcp_ack_only(packet: &[u8], ip_header_length: usize) -> bool {
    if packet.len() < ip_header_length + 20 {
        return false;
    }
    let tcp_header_length = usize::from(packet[ip_header_length + 12] >> 4) * 4;
    if tcp_header_length < 20 || packet.len() < ip_header_length + tcp_header_length {
        return false;
    }
    let flags = packet[ip_header_length + 13];
    flags & 0x10 != 0
        && flags & (0x01 | 0x02 | 0x04) == 0
        && packet.len() == ip_header_length + tcp_header_length
}

fn hash_flow(flow: FlowKey) -> u32 {
    let mut hash = 2_166_136_261_u32;
    for value in flow
        .source
        .into_iter()
        .chain(flow.destination)
        .chain(flow.source_port.to_be_bytes())
        .chain(flow.destination_port.to_be_bytes())
        .chain(flow.fragment_id.to_be_bytes())
        .chain([flow.protocol, u8::from(flow.fragmented)])
    {
        hash ^= u32::from(value);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct TestMetrics {
        drops: Mutex<HashMap<DropReason, u64>>,
        current: AtomicUsize,
        high_water: AtomicUsize,
    }

    impl DataMetrics for TestMetrics {
        fn dropped(&self, reason: DropReason) {
            *self.drops.lock().entry(reason).or_default() += 1;
        }

        fn adjust_queue_bytes(&self, _lane: usize, delta: isize) {
            let current = if delta >= 0 {
                self.current.fetch_add(delta as usize, Ordering::Relaxed) + delta as usize
            } else {
                self.current.fetch_sub((-delta) as usize, Ordering::Relaxed) - (-delta) as usize
            };
            self.high_water.fetch_max(current, Ordering::Relaxed);
        }
    }

    fn tcp(marker: u8) -> Bytes {
        let mut packet = vec![0; 80];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[4] = marker;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x18;
        packet.into()
    }

    fn udp(size: usize, marker: u8) -> Bytes {
        let mut packet = vec![0; size.max(28)];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[4] = marker;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet.into()
    }

    fn count(metrics: &TestMetrics, reason: DropReason) -> u64 {
        metrics.drops.lock().get(&reason).copied().unwrap_or(0)
    }

    #[test]
    fn evicts_oldest_replaceable_datagram() {
        let metrics = Arc::new(TestMetrics::default());
        let queue = PacketQueue::new(
            QueueConfig {
                max_packets: 2,
                max_bytes: 4096,
                ..QueueConfig::default()
            },
            Some(metrics.clone()),
            Some(0),
        );
        let now = Instant::now();
        assert_eq!(queue.enqueue_at(udp(300, 1), now), EnqueueResult::Accepted);
        assert_eq!(queue.enqueue_at(udp(300, 2), now), EnqueueResult::Accepted);
        assert_eq!(queue.enqueue_at(tcp(3), now), EnqueueResult::Accepted);
        assert_eq!(queue.dequeue_at(now).unwrap()[4], 2);
        assert_eq!(queue.dequeue_at(now).unwrap()[4], 3);
        assert_eq!(count(&metrics, DropReason::QueueOldest), 1);
    }

    #[test]
    fn tail_drops_tcp_to_preserve_prefix_and_control() {
        let metrics = Arc::new(TestMetrics::default());
        let queue = PacketQueue::new(
            QueueConfig {
                max_packets: 2,
                max_bytes: 4096,
                ..QueueConfig::default()
            },
            Some(metrics.clone()),
            Some(0),
        );
        let now = Instant::now();
        assert_eq!(queue.enqueue_at(tcp(1), now), EnqueueResult::Accepted);
        assert_eq!(queue.enqueue_at(tcp(2), now), EnqueueResult::Accepted);
        assert_eq!(queue.enqueue_at(tcp(3), now), EnqueueResult::DroppedTail);
        assert_eq!(queue.dequeue_at(now).unwrap()[4], 1);
        assert_eq!(queue.dequeue_at(now).unwrap()[4], 2);
        assert_eq!(count(&metrics, DropReason::QueueTail), 1);
    }

    #[test]
    fn control_replaces_datagram_but_not_tcp() {
        let now = Instant::now();
        let config = QueueConfig {
            max_packets: 1,
            max_bytes: 4096,
            ..QueueConfig::default()
        };
        let queue = PacketQueue::new(config.clone(), None, None);
        assert_eq!(queue.enqueue_at(udp(300, 1), now), EnqueueResult::Accepted);
        assert_eq!(queue.enqueue_at(udp(28, 2), now), EnqueueResult::Accepted);
        assert_eq!(queue.dequeue_at(now).unwrap()[4], 2);

        let queue = PacketQueue::new(config, None, None);
        assert_eq!(queue.enqueue_at(tcp(1), now), EnqueueResult::Accepted);
        assert_eq!(
            queue.enqueue_at(udp(28, 2), now),
            EnqueueResult::DroppedFull
        );
        assert_eq!(queue.dequeue_at(now).unwrap()[4], 1);
    }

    #[test]
    fn byte_limit_uses_the_same_replacement_policy() {
        let now = Instant::now();
        let queue = PacketQueue::new(
            QueueConfig {
                max_packets: 8,
                max_bytes: 350,
                ..QueueConfig::default()
            },
            None,
            None,
        );
        assert_eq!(queue.enqueue_at(udp(300, 1), now), EnqueueResult::Accepted);
        assert_eq!(queue.enqueue_at(tcp(2), now), EnqueueResult::Accepted);
        assert_eq!(queue.queued_packets(), 1);
        assert_eq!(queue.queued_bytes(), 80);
        assert_eq!(queue.dequeue_at(now).unwrap()[4], 2);
    }

    #[test]
    fn ack_only_tcp_is_control_traffic() {
        let mut packet = tcp(1).to_vec();
        packet.truncate(40);
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[33] = 0x10;
        assert_eq!(classify_ipv4(&packet).class, PacketClass::Control);
        packet.push(1);
        packet[2..4].copy_from_slice(&41_u16.to_be_bytes());
        assert_eq!(classify_ipv4(&packet).class, PacketClass::Tcp);
    }

    #[test]
    fn expires_by_packet_class_and_tracks_load() {
        let metrics = Arc::new(TestMetrics::default());
        let queue = PacketQueue::new(
            QueueConfig {
                datagram_max_age: Duration::from_millis(10),
                control_max_age: Duration::from_millis(10),
                ..QueueConfig::default()
            },
            Some(metrics.clone()),
            Some(1),
        );
        let now = Instant::now();
        assert_eq!(queue.enqueue_at(udp(28, 1), now), EnqueueResult::Accepted);
        assert!(queue.dequeue_at(now + Duration::from_millis(11)).is_none());
        assert_eq!(count(&metrics, DropReason::QueueExpired), 1);
        assert_eq!(queue.queued_bytes(), 0);
        assert_eq!(metrics.current.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.high_water.load(Ordering::Relaxed), 28);
    }

    #[test]
    fn drop_oldest_policy_has_no_expiry() {
        let now = Instant::now();
        let queue = PacketQueue::new(
            QueueConfig {
                max_packets: 2,
                ..QueueConfig::masque()
            },
            None,
            None,
        );
        for marker in 1..=3 {
            assert_eq!(queue.enqueue_at(tcp(marker), now), EnqueueResult::Accepted);
        }
        assert_eq!(
            queue.dequeue_at(now + Duration::from_secs(3600)).unwrap()[4],
            2
        );
        assert_eq!(
            queue.dequeue_at(now + Duration::from_secs(3600)).unwrap()[4],
            3
        );
    }

    #[tokio::test]
    async fn recv_wakes_and_close_releases_storage() {
        let queue = Arc::new(PacketQueue::new(QueueConfig::default(), None, None));
        let waiter = {
            let queue = queue.clone();
            tokio::spawn(async move { queue.recv().await })
        };
        tokio::task::yield_now().await;
        queue.enqueue(tcp(1));
        assert_eq!(waiter.await.unwrap().unwrap()[4], 1);
        queue.enqueue(tcp(2));
        queue.close();
        assert_eq!(queue.queued_packets(), 0);
        assert_eq!(queue.queued_bytes(), 0);
        assert!(queue.recv().await.is_none());
    }

    #[tokio::test]
    async fn recv_does_not_lose_enqueue_between_check_and_wait() {
        let queue = Arc::new(PacketQueue::new(QueueConfig::default(), None, None));
        let enqueuer = queue.clone();
        let mut fired = false;
        let packet = tokio::time::timeout(
            Duration::from_secs(1),
            queue.recv_with_hook(|| {
                if !fired {
                    fired = true;
                    assert_eq!(enqueuer.enqueue(tcp(7)), EnqueueResult::Accepted);
                }
            }),
        )
        .await
        .expect("receive lost an enqueue notification")
        .expect("queue closed");
        assert_eq!(packet[4], 7);
    }
}
