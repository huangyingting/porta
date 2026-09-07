use super::queue::{
    classify_ipv4, DataMetrics, DropReason, EnqueueResult, FlowKey, PacketClass, PacketQueue,
    QueueConfig,
};
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const MIN_TUNNEL_LANES: usize = 2;
const MAX_TUNNEL_LANES: usize = 4;
const MAX_TRACKED_FLOWS: usize = 4096;
const FLOW_MAX_IDLE: Duration = Duration::from_secs(120);

pub trait PacketDevice: Send + Sync + 'static {
    fn read_packet(&self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>>;
    fn write_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;
    fn name(&self) -> &str;
}

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("router session group ID is required")]
    MissingGroupId,
    #[error("invalid router lane configuration")]
    InvalidLaneConfiguration,
    #[error("router lane count does not match existing group")]
    LaneCountMismatch,
    #[error("invalid IPv4 packet: {0}")]
    InvalidPacket(&'static str),
    #[error("packet source does not match tunnel lease: got {got} want {expected}")]
    SourceSpoofed { got: Ipv4Addr, expected: Ipv4Addr },
    #[error("packet device I/O: {0}")]
    Device(#[from] io::Error),
}

#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

struct SessionInner {
    address: Ipv4Addr,
    cancellation: CancellationToken,
    queue: PacketQueue,
    metrics: Option<Arc<dyn DataMetrics>>,
    closed: AtomicBool,
}

impl Session {
    pub fn address(&self) -> Ipv4Addr {
        self.inner.address
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    pub fn close(&self) {
        self.inner.close();
    }

    pub async fn recv(&self) -> Option<Bytes> {
        tokio::select! {
            biased;
            _ = self.inner.cancellation.cancelled() => None,
            packet = self.inner.queue.recv() => packet,
        }
    }

    pub fn try_recv(&self) -> Option<Bytes> {
        self.inner.queue.try_dequeue()
    }

    pub fn queued_bytes(&self) -> usize {
        self.inner.queue.queued_bytes()
    }

    fn enqueue(&self, packet: Bytes) {
        if self.inner.cancellation.is_cancelled() {
            self.inner.record_drop(DropReason::SessionClosed);
            return;
        }
        if self.inner.queue.enqueue(packet) == EnqueueResult::Closed {
            self.inner.record_drop(DropReason::SessionClosed);
        }
    }
}

impl SessionInner {
    fn close(&self) {
        if self
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.cancellation.cancel();
            self.queue.close();
        }
    }

    fn record_drop(&self, reason: DropReason) {
        if let Some(metrics) = &self.metrics {
            metrics.dropped(reason);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.close();
        }
    }
}

struct SessionGroup {
    id: String,
    lane_count: usize,
    lanes: HashMap<usize, Weak<SessionInner>>,
    lane_connections: HashMap<usize, String>,
    flows: Mutex<HashMap<FlowKey, FlowLane>>,
    collapse_warned: bool,
}

#[derive(Clone, Copy)]
struct FlowLane {
    lane: usize,
    last_seen: Instant,
}

struct RouterInner {
    device: Arc<dyn PacketDevice>,
    sessions: RwLock<HashMap<Ipv4Addr, SessionGroup>>,
    metrics: Option<Arc<dyn DataMetrics>>,
}

#[derive(Clone)]
pub struct Router {
    inner: Arc<RouterInner>,
}

impl Drop for Router {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) != 1 {
            return;
        }
        let groups = {
            let mut sessions = self.inner.sessions.write();
            sessions.drain().map(|(_, group)| group).collect::<Vec<_>>()
        };
        for group in groups {
            close_group(Some(group));
        }
    }
}

pub struct GroupRegistration {
    pub session: Session,
    pub collapsed: bool,
}

impl Router {
    pub fn new(device: Arc<dyn PacketDevice>, metrics: Option<Arc<dyn DataMetrics>>) -> Self {
        Self {
            inner: Arc::new(RouterInner {
                device,
                sessions: RwLock::new(HashMap::new()),
                metrics,
            }),
        }
    }

    pub fn register(&self, parent: &CancellationToken, address: Ipv4Addr) -> Session {
        let session = self.new_session(parent, address, None, QueueConfig::masque());
        let previous = self.inner.sessions.write().insert(
            address,
            SessionGroup {
                id: String::new(),
                lane_count: 1,
                lanes: HashMap::from([(0, Arc::downgrade(&session.inner))]),
                lane_connections: HashMap::new(),
                flows: Mutex::new(HashMap::new()),
                collapse_warned: false,
            },
        );
        close_group(previous);
        self.watch_session(address, String::new(), 0, &session);
        session
    }

    pub fn register_group(
        &self,
        parent: &CancellationToken,
        address: Ipv4Addr,
        group_id: impl Into<String>,
        lane_index: usize,
        lane_count: usize,
        outer_connection: impl Into<String>,
    ) -> Result<GroupRegistration, RouterError> {
        let group_id = group_id.into();
        if group_id.is_empty() {
            return Err(RouterError::MissingGroupId);
        }
        if !(MIN_TUNNEL_LANES..=MAX_TUNNEL_LANES).contains(&lane_count) || lane_index >= lane_count
        {
            return Err(RouterError::InvalidLaneConfiguration);
        }
        let session = self.new_session(parent, address, Some(lane_index), QueueConfig::default());
        let connection = outer_connection.into();
        let mut replaced_group = None;
        let replaced_lane;
        let collapsed;
        {
            let mut sessions = self.inner.sessions.write();
            let replace = sessions
                .get(&address)
                .is_none_or(|group| group.id != group_id);
            if replace {
                replaced_group = sessions.remove(&address);
                sessions.insert(
                    address,
                    SessionGroup {
                        id: group_id.clone(),
                        lane_count,
                        lanes: HashMap::with_capacity(lane_count),
                        lane_connections: HashMap::with_capacity(lane_count),
                        flows: Mutex::new(HashMap::new()),
                        collapse_warned: false,
                    },
                );
            } else if sessions[&address].lane_count != lane_count {
                session.close();
                return Err(RouterError::LaneCountMismatch);
            }
            let group = sessions.get_mut(&address).expect("group was inserted");
            replaced_lane = group
                .lanes
                .insert(lane_index, Arc::downgrade(&session.inner));
            group.lane_connections.insert(lane_index, connection);
            collapsed = collapsed_lane_group(group);
            if collapsed && !group.collapse_warned {
                group.collapse_warned = true;
                if let Some(metrics) = &self.inner.metrics {
                    metrics.lane_collapsed();
                }
            }
        }
        close_group(replaced_group);
        if let Some(previous) = replaced_lane {
            if let Some(previous) = previous.upgrade() {
                previous.close();
            }
        }
        self.watch_session(address, group_id, lane_index, &session);
        Ok(GroupRegistration { session, collapsed })
    }

    pub async fn inject(
        &self,
        cancellation: &CancellationToken,
        lease: Ipv4Addr,
        packet: &[u8],
    ) -> Result<(), RouterError> {
        let (source, _) = parse_ipv4(packet)?;
        if source != lease {
            return Err(RouterError::SourceSpoofed {
                got: source,
                expected: lease,
            });
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "router injection canceled").into()),
            result = self.inner.device.write_packet(packet) => result.map_err(Into::into),
        }
    }

    pub async fn inject_validated(
        &self,
        cancellation: &CancellationToken,
        packet: &[u8],
    ) -> Result<(), RouterError> {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "router injection canceled").into()),
            result = self.inner.device.write_packet(packet) => result.map_err(Into::into),
        }
    }

    pub async fn run(&self, cancellation: &CancellationToken) -> Result<(), RouterError> {
        loop {
            let packet = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                result = self.inner.device.read_packet() => match result {
                    Ok(packet) => packet,
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(error) => return Err(error.into()),
                },
            };
            let (_, destination) = match parse_ipv4(&packet) {
                Ok(addresses) => addresses,
                Err(_) => {
                    self.record_drop(DropReason::InvalidTunPacket);
                    continue;
                }
            };
            let session = {
                let sessions = self.inner.sessions.read();
                sessions
                    .get(&destination)
                    .and_then(|group| select_lane(group, &packet))
            };
            let Some(session) = session else {
                self.record_drop(DropReason::NoSession);
                continue;
            };
            if cancellation.is_cancelled() {
                return Ok(());
            }
            session.enqueue(Bytes::from(packet));
        }
    }

    pub fn device_name(&self) -> &str {
        self.inner.device.name()
    }

    fn new_session(
        &self,
        parent: &CancellationToken,
        address: Ipv4Addr,
        lane: Option<usize>,
        queue_config: QueueConfig,
    ) -> Session {
        Session {
            inner: Arc::new(SessionInner {
                address,
                cancellation: parent.child_token(),
                queue: PacketQueue::new(queue_config, self.inner.metrics.clone(), lane),
                metrics: self.inner.metrics.clone(),
                closed: AtomicBool::new(false),
            }),
        }
    }

    fn watch_session(
        &self,
        address: Ipv4Addr,
        group_id: String,
        lane_index: usize,
        session: &Session,
    ) {
        let router = Arc::downgrade(&self.inner);
        let watched = Arc::downgrade(&session.inner);
        let cancellation = session.inner.cancellation.clone();
        tokio::spawn(async move {
            cancellation.cancelled().await;
            if let Some(watched) = watched.upgrade() {
                watched.close();
            }
            remove_session(router, address, &group_id, lane_index, &watched);
        });
    }

    fn record_drop(&self, reason: DropReason) {
        if let Some(metrics) = &self.inner.metrics {
            metrics.dropped(reason);
        }
    }
}

fn remove_session(
    router: Weak<RouterInner>,
    address: Ipv4Addr,
    group_id: &str,
    lane_index: usize,
    session: &Weak<SessionInner>,
) {
    let Some(router) = router.upgrade() else {
        return;
    };
    let mut sessions = router.sessions.write();
    let remove_group = if let Some(group) = sessions.get_mut(&address) {
        if group.id == group_id
            && group
                .lanes
                .get(&lane_index)
                .is_some_and(|current| Weak::ptr_eq(current, session))
        {
            group.lanes.remove(&lane_index);
            group.lane_connections.remove(&lane_index);
        }
        group.lanes.is_empty()
    } else {
        false
    };
    if remove_group {
        sessions.remove(&address);
    }
}

fn close_group(group: Option<SessionGroup>) {
    if let Some(group) = group {
        for session in group.lanes.into_values() {
            if let Some(session) = session.upgrade() {
                session.close();
            }
        }
    }
}

fn select_lane(group: &SessionGroup, packet: &[u8]) -> Option<Session> {
    if group.lanes.is_empty() {
        return None;
    }
    let metadata = classify_ipv4(packet);
    let preferred = if metadata.class == PacketClass::Control {
        0
    } else {
        select_data_lane(group, metadata.flow, metadata.hash)
    };
    group
        .lanes
        .get(&preferred)
        .and_then(Weak::upgrade)
        .map(|inner| Session { inner })
        .or_else(|| {
            (0..group.lane_count).find_map(|lane| {
                group
                    .lanes
                    .get(&lane)
                    .and_then(Weak::upgrade)
                    .map(|inner| Session { inner })
            })
        })
}

fn select_data_lane(group: &SessionGroup, flow: FlowKey, hash: u32) -> usize {
    if group.lane_count <= 1 {
        return 0;
    }
    let mut flows = group.flows.lock();
    let now = Instant::now();
    if let Some(assignment) = flows.get_mut(&flow) {
        if group
            .lanes
            .get(&assignment.lane)
            .is_some_and(|session| session.strong_count() != 0)
        {
            assignment.last_seen = now;
            return assignment.lane;
        }
        flows.remove(&flow);
    }
    if flows.len() >= MAX_TRACKED_FLOWS {
        let mut oldest = None;
        flows.retain(|key, assignment| {
            if now.saturating_duration_since(assignment.last_seen) >= FLOW_MAX_IDLE {
                false
            } else {
                if oldest.is_none_or(|(_, seen)| assignment.last_seen < seen) {
                    oldest = Some((*key, assignment.last_seen));
                }
                true
            }
        });
        if flows.len() >= MAX_TRACKED_FLOWS {
            if let Some((flow, _)) = oldest {
                flows.remove(&flow);
            }
        }
    }
    let data_lanes = group.lane_count - 1;
    let start = hash as usize % data_lanes;
    let mut selected = None;
    let mut selected_bytes = usize::MAX;
    for offset in 0..data_lanes {
        let lane = 1 + (start + offset) % data_lanes;
        if let Some(session) = group.lanes.get(&lane).and_then(Weak::upgrade) {
            let queued = session.queue.queued_bytes();
            if queued < selected_bytes {
                selected = Some(lane);
                selected_bytes = queued;
            }
        }
    }
    let Some(selected) = selected else {
        return 0;
    };
    flows.insert(
        flow,
        FlowLane {
            lane: selected,
            last_seen: now,
        },
    );
    selected
}

fn collapsed_lane_group(group: &SessionGroup) -> bool {
    if group.lanes.len() < 2 {
        return false;
    }
    let connections: HashSet<_> = group
        .lanes
        .keys()
        .filter_map(|lane| {
            group
                .lane_connections
                .get(lane)
                .filter(|connection| !connection.is_empty())
        })
        .collect();
    !connections.is_empty() && connections.len() < group.lanes.len()
}

pub fn packet_lane(packet: &[u8], lane_count: usize) -> usize {
    if lane_count <= 1 {
        return 0;
    }
    let metadata = classify_ipv4(packet);
    if metadata.class == PacketClass::Control {
        0
    } else {
        1 + metadata.hash as usize % (lane_count - 1)
    }
}

fn parse_ipv4(packet: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr), RouterError> {
    if packet.len() < 20 {
        return Err(RouterError::InvalidPacket(
            "header is shorter than 20 bytes",
        ));
    }
    if packet[0] >> 4 != 4 {
        return Err(RouterError::InvalidPacket("packet is not IPv4"));
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return Err(RouterError::InvalidPacket("invalid IPv4 header length"));
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length < header_length || total_length != packet.len() {
        return Err(RouterError::InvalidPacket("IPv4 total length mismatch"));
    }
    Ok((
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::{Mutex as AsyncMutex, Notify};

    #[derive(Default)]
    struct FakeDevice {
        reads: AsyncMutex<VecDeque<io::Result<Vec<u8>>>>,
        written: AsyncMutex<Vec<Vec<u8>>>,
        ready: Notify,
    }

    impl FakeDevice {
        async fn push(&self, packet: io::Result<Vec<u8>>) {
            self.reads.lock().await.push_back(packet);
            self.ready.notify_one();
        }
    }

    impl PacketDevice for FakeDevice {
        fn read_packet(&self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>> {
            Box::pin(async move {
                loop {
                    if let Some(packet) = self.reads.lock().await.pop_front() {
                        return packet;
                    }
                    self.ready.notified().await;
                }
            })
        }

        fn write_packet<'a>(
            &'a self,
            packet: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.written.lock().await.push(packet.to_vec());
                Ok(())
            })
        }

        fn name(&self) -> &str {
            "fake0"
        }
    }

    #[derive(Default)]
    struct TestMetrics {
        invalid: AtomicUsize,
        no_session: AtomicUsize,
        closed: AtomicUsize,
        collapsed: AtomicUsize,
    }

    impl DataMetrics for TestMetrics {
        fn dropped(&self, reason: DropReason) {
            match reason {
                DropReason::InvalidTunPacket => &self.invalid,
                DropReason::NoSession => &self.no_session,
                DropReason::SessionClosed => &self.closed,
                _ => return,
            }
            .fetch_add(1, Ordering::Relaxed);
        }

        fn lane_collapsed(&self) {
            self.collapsed.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn udp(source: [u8; 4], destination: [u8; 4], size: usize) -> Vec<u8> {
        let mut packet = vec![0; size.max(28)];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet
    }

    #[tokio::test]
    async fn routes_owned_downlink_packet_by_destination() {
        let device = Arc::new(FakeDevice::default());
        let router = Router::new(device.clone(), None);
        let cancellation = CancellationToken::new();
        let address = Ipv4Addr::new(10, 66, 0, 2);
        let session = router.register(&cancellation, address);
        let packet = udp([1, 1, 1, 1], address.octets(), 300);
        device.push(Ok(packet.clone())).await;
        let runner = tokio::spawn({
            let router = router.clone();
            let cancellation = cancellation.clone();
            async move { router.run(&cancellation).await }
        });
        assert_eq!(session.recv().await.unwrap().as_ref(), packet);
        cancellation.cancel();
        assert!(runner.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn validates_uplink_source_before_device_write() {
        let device = Arc::new(FakeDevice::default());
        let router = Router::new(device.clone(), None);
        let cancellation = CancellationToken::new();
        let lease = Ipv4Addr::new(10, 66, 0, 2);
        let packet = udp([10, 66, 0, 3], [1, 1, 1, 1], 300);
        assert!(matches!(
            router.inject(&cancellation, lease, &packet).await,
            Err(RouterError::SourceSpoofed { .. })
        ));
        assert!(device.written.lock().await.is_empty());
        let packet = udp(lease.octets(), [1, 1, 1, 1], 300);
        router.inject(&cancellation, lease, &packet).await.unwrap();
        assert_eq!(device.written.lock().await.as_slice(), &[packet]);
    }

    #[tokio::test]
    async fn duplicate_registration_is_replaced_and_cleanup_is_fenced() {
        let router = Router::new(Arc::new(FakeDevice::default()), None);
        let parent = CancellationToken::new();
        let address = Ipv4Addr::new(10, 66, 0, 2);
        let first = router.register(&parent, address);
        let second = router.register(&parent, address);
        first.cancellation().cancelled().await;
        tokio::task::yield_now().await;
        let packet = udp([1, 1, 1, 1], address.octets(), 300);
        let selected = {
            let sessions = router.inner.sessions.read();
            select_lane(&sessions[&address], &packet).unwrap()
        };
        assert!(Arc::ptr_eq(&selected.inner, &second.inner));
        assert!(!second.cancellation().is_cancelled());
    }

    #[tokio::test]
    async fn canceled_session_stops_receiving_and_is_removed() {
        let router = Router::new(Arc::new(FakeDevice::default()), None);
        let parent = CancellationToken::new();
        let address = Ipv4Addr::new(10, 66, 0, 2);
        let session = router.register(&parent, address);
        session.close();
        assert!(session.recv().await.is_none());
        for _ in 0..100 {
            if !router.inner.sessions.read().contains_key(&address) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!router.inner.sessions.read().contains_key(&address));
    }

    #[tokio::test]
    async fn dropping_transport_session_closes_and_removes_route() {
        let router = Router::new(Arc::new(FakeDevice::default()), None);
        let parent = CancellationToken::new();
        let address = Ipv4Addr::new(10, 66, 0, 2);
        let session = router.register(&parent, address);
        let cancellation = session.cancellation();
        drop(session);
        tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
            .await
            .expect("dropping the transport session did not cancel it");
        for _ in 0..100 {
            if !router.inner.sessions.read().contains_key(&address) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!router.inner.sessions.read().contains_key(&address));
    }

    #[tokio::test]
    async fn grouped_lanes_replace_only_matching_lane_and_detect_collapse() {
        let metrics = Arc::new(TestMetrics::default());
        let router = Router::new(Arc::new(FakeDevice::default()), Some(metrics.clone()));
        let parent = CancellationToken::new();
        let address = Ipv4Addr::new(10, 66, 0, 2);
        let first = router
            .register_group(&parent, address, "group", 0, 4, "proxy:443")
            .unwrap();
        assert!(!first.collapsed);
        let second = router
            .register_group(&parent, address, "group", 1, 4, "proxy:443")
            .unwrap();
        assert!(second.collapsed);
        let replacement = router
            .register_group(&parent, address, "group", 0, 4, "proxy:444")
            .unwrap();
        first.session.cancellation().cancelled().await;
        assert!(!second.session.cancellation().is_cancelled());
        assert!(!replacement.session.cancellation().is_cancelled());
        assert_eq!(metrics.collapsed.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn control_uses_lane_zero_and_flow_stays_on_least_loaded_lane() {
        let router = Router::new(Arc::new(FakeDevice::default()), None);
        let parent = CancellationToken::new();
        let address = Ipv4Addr::new(10, 66, 0, 2);
        let mut lanes = Vec::new();
        for lane in 0..4 {
            lanes.push(
                router
                    .register_group(&parent, address, "group", lane, 4, format!("peer:{lane}"))
                    .unwrap()
                    .session,
            );
        }
        lanes[1].inner.queue.enqueue(Bytes::from(vec![0; 100]));
        lanes[2].inner.queue.enqueue(Bytes::from(vec![0; 50]));
        let data = udp([1, 1, 1, 1], address.octets(), 300);
        let group = router.inner.sessions.read();
        let first = select_lane(&group[&address], &data).unwrap();
        assert!(Arc::ptr_eq(&first.inner, &lanes[3].inner));
        lanes[3].inner.queue.enqueue(Bytes::from(vec![0; 200]));
        let second = select_lane(&group[&address], &data).unwrap();
        assert!(Arc::ptr_eq(&second.inner, &lanes[3].inner));
        drop(group);

        let mut dns = udp([1, 1, 1, 1], address.octets(), 28);
        dns[22..24].copy_from_slice(&53_u16.to_be_bytes());
        assert_eq!(packet_lane(&dns, 4), 0);
    }

    #[test]
    fn fragments_stay_on_one_data_lane() {
        let mut packet = udp([10, 66, 0, 2], [1, 1, 1, 1], 300);
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        let expected = packet_lane(&packet, 4);
        assert_ne!(expected, 0);
        for offset in [0x2001_u16, 0x0002] {
            packet[6..8].copy_from_slice(&offset.to_be_bytes());
            for value in 0..=255 {
                packet[20] = value;
                packet[22] = 255 - value;
                assert_eq!(packet_lane(&packet, 4), expected);
            }
        }
    }

    #[tokio::test]
    async fn run_drops_invalid_and_unleased_packets_then_cancels() {
        let metrics = Arc::new(TestMetrics::default());
        let device = Arc::new(FakeDevice::default());
        let router = Router::new(device.clone(), Some(metrics.clone()));
        let cancellation = CancellationToken::new();
        device.push(Ok(vec![1, 2, 3])).await;
        device
            .push(Ok(udp([1, 1, 1, 1], [10, 66, 0, 99], 300)))
            .await;
        let runner = tokio::spawn({
            let router = router.clone();
            let cancellation = cancellation.clone();
            async move { router.run(&cancellation).await }
        });
        while metrics.no_session.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        assert!(runner.await.unwrap().is_ok());
        assert_eq!(metrics.invalid.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.no_session.load(Ordering::Relaxed), 1);
    }
}
