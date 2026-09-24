//! Adaptive IPv4 datagram budgets, fragmentation, and bounded ICMP feedback.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::ip::{classify_ipv4, internet_checksum, parse_ipv4, set_ipv4_header_checksum, FlowKey};

const MIN_IPV4_MTU: usize = 68;
const MAX_FEEDBACK_FLOWS: usize = 128;
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const ICMP_INTERVAL: Duration = Duration::from_millis(100);
const MIN_FEEDBACK_REQUESTS: u8 = 3;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MtuError {
    #[error("invalid IPv4 packet")]
    InvalidPacket,
    #[error("IPv4 fragmentation needed")]
    FragmentationNeeded,
    #[error("ICMP response suppressed")]
    IcmpSuppressed,
    #[error("invalid MTU")]
    InvalidMtu,
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpContext {
    pub gateway: Ipv4Addr,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

/// Returns the IP payload budget of an HTTP/3 datagram without allocating.
///
/// Quinn's capacity already excludes QUIC framing; only the quarter-stream-ID
/// and the one-byte CONNECT-IP context ID remain to be subtracted.
/// A present capacity too small for those headers yields zero, not unavailable.
pub fn ip_datagram_capacity(quic_capacity: Option<usize>, stream_id: u64) -> Option<usize> {
    let stream_id_length = match stream_id / 4 {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    };
    quic_capacity.map(|capacity| capacity.saturating_sub(stream_id_length + 1))
}

/// A connection's IPv4 datagram limit, which never grows during its lifetime.
#[derive(Clone, Copy, Debug)]
pub struct DatagramMtu {
    limit: usize,
}

impl DatagramMtu {
    /// Starts at a negotiated IPv4 ceiling.
    ///
    /// # Panics
    ///
    /// Panics if the ceiling is below IPv4's minimum MTU of 68 bytes.
    pub fn new(ceiling: u16) -> Self {
        assert!(usize::from(ceiling) >= MIN_IPV4_MTU);
        Self {
            limit: usize::from(ceiling),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Rejects unusable paths without changing the last usable limit.
    pub fn update(&mut self, ip_capacity: usize) -> Result<bool, MtuError> {
        if ip_capacity < MIN_IPV4_MTU {
            return Err(MtuError::InvalidMtu);
        }
        let limit = self.limit.min(ip_capacity);
        let changed = limit != self.limit;
        self.limit = limit;
        Ok(changed)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FeedbackDecision {
    pub send_icmp: bool,
    pub use_capsule: bool,
}

struct FlowFeedback {
    flow: FlowKey,
    mtu: usize,
    last_seen: Instant,
    first_feedback: Option<Instant>,
    feedback_requests: u8,
}

impl FlowFeedback {
    fn new(flow: FlowKey, mtu: usize, now: Instant) -> Self {
        Self {
            flow,
            mtu,
            last_seen: now,
            first_feedback: None,
            feedback_requests: 0,
        }
    }
}

/// A bounded convergence heuristic, not proof that a peer blocks ICMP.
///
/// Only oversized traffic updates flow state; fitting packets such as TCP ACKs
/// must not erase evidence that a flow continues to ignore its effective MTU.
#[derive(Default)]
pub struct FeedbackPolicy {
    flows: Vec<FlowFeedback>,
    last_feedback: Option<Instant>,
}

impl FeedbackPolicy {
    /// Decides how to handle a validated oversized DF packet whose ICMP response
    /// is not suppressed. Callers must use independently bounded output writers.
    ///
    /// Rate-limited drops do not count as feedback requests. Capsule fallback
    /// requires three prior feedback requests and 2-10 seconds of grace, scaled
    /// to four RTTs, and must fit the negotiated interface MTU (`capsule_ceiling`).
    /// Larger packets keep requesting globally rate-limited ICMP after grace.
    /// A lower effective MTU starts a new feedback attempt.
    pub fn on_oversized(
        &mut self,
        packet: &[u8],
        effective_mtu: usize,
        capsule_ceiling: usize,
        now: Instant,
        rtt: Duration,
    ) -> FeedbackDecision {
        if packet.len() <= effective_mtu || effective_mtu < MIN_IPV4_MTU {
            return FeedbackDecision::default();
        }
        self.flows
            .retain(|state| now.saturating_duration_since(state.last_seen) < FLOW_IDLE_TIMEOUT);
        let flow = classify_ipv4(packet).flow;
        let index = match self.flows.iter().position(|state| state.flow == flow) {
            Some(index) => index,
            None => {
                if self.flows.len() == MAX_FEEDBACK_FLOWS {
                    // Vec order breaks timestamp ties by insertion order.
                    let oldest = self
                        .flows
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, state)| state.last_seen)
                        .map(|(index, _)| index)
                        .expect("the flow table is full");
                    self.flows.remove(oldest);
                }
                self.flows.push(FlowFeedback::new(flow, effective_mtu, now));
                self.flows.len() - 1
            }
        };
        let state = &mut self.flows[index];
        if effective_mtu < state.mtu {
            *state = FlowFeedback::new(flow, effective_mtu, now);
        }
        state.last_seen = now;
        let grace = rtt
            .saturating_mul(4)
            .clamp(Duration::from_secs(2), Duration::from_secs(10));
        if packet.len() <= capsule_ceiling
            && state.feedback_requests >= MIN_FEEDBACK_REQUESTS
            && state
                .first_feedback
                .is_some_and(|first| now.saturating_duration_since(first) >= grace)
        {
            return FeedbackDecision {
                send_icmp: false,
                use_capsule: true,
            };
        }
        if self
            .last_feedback
            .is_some_and(|last| now.saturating_duration_since(last) < ICMP_INTERVAL)
        {
            return FeedbackDecision::default();
        }
        self.last_feedback = Some(now);
        state.first_feedback.get_or_insert(now);
        state.feedback_requests = (state.feedback_requests + 1).min(MIN_FEEDBACK_REQUESTS);
        FeedbackDecision {
            send_icmp: true,
            use_capsule: false,
        }
    }
}

pub fn fragment_ipv4(packet: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, MtuError> {
    if !(MIN_IPV4_MTU..=u16::MAX as usize).contains(&mtu) {
        return Err(MtuError::InvalidMtu);
    }
    let info = parse_ipv4(packet).map_err(|_| MtuError::InvalidPacket)?;
    if internet_checksum(&packet[..info.header_length]) != 0 {
        return Err(MtuError::InvalidPacket);
    }
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    if flags & 0x8000 != 0 {
        return Err(MtuError::InvalidPacket);
    }
    if packet.len() <= mtu {
        return Ok(vec![packet.to_vec()]);
    }
    if flags & 0x4000 != 0 {
        return Err(MtuError::FragmentationNeeded);
    }
    let copied_options = copied_ipv4_options(&packet[20..info.header_length])?;
    let payload = &packet[info.header_length..];
    let mut absolute_offset = usize::from(flags & 0x1fff) * 8;
    if (flags & 0x2000 != 0 && !payload.len().is_multiple_of(8))
        || (flags & 0x3fff != 0 && payload.is_empty())
        || 20 + copied_options.len() + absolute_offset + payload.len() > u16::MAX as usize
    {
        return Err(MtuError::InvalidPacket);
    }
    let mut consumed = 0;
    let mut fragments = Vec::with_capacity(2);
    while consumed < payload.len() {
        let options = if absolute_offset == 0 {
            &packet[20..info.header_length]
        } else {
            copied_options.as_slice()
        };
        let header_length = 20 + options.len();
        if mtu < header_length + 8 {
            return Err(MtuError::InvalidMtu);
        }
        let remaining = payload.len() - consumed;
        let length = if remaining > mtu - header_length {
            (mtu - header_length) & !7
        } else {
            remaining
        };
        let mut fragment = vec![0; header_length + length];
        fragment[..20].copy_from_slice(&packet[..20]);
        fragment[20..header_length].copy_from_slice(options);
        fragment[0] = 0x40 | (header_length / 4) as u8;
        let total = fragment.len() as u16;
        fragment[2..4].copy_from_slice(&total.to_be_bytes());
        let mut new_flags = (absolute_offset / 8) as u16;
        if consumed + length < payload.len() || flags & 0x2000 != 0 {
            new_flags |= 0x2000;
        }
        fragment[6..8].copy_from_slice(&new_flags.to_be_bytes());
        fragment[header_length..].copy_from_slice(&payload[consumed..consumed + length]);
        set_ipv4_header_checksum(&mut fragment).map_err(|_| MtuError::InvalidPacket)?;
        fragments.push(fragment);
        consumed += length;
        absolute_offset += length;
    }
    Ok(fragments)
}

fn copied_ipv4_options(options: &[u8]) -> Result<Vec<u8>, MtuError> {
    let mut copied = Vec::with_capacity(options.len());
    let mut index = 0;
    while index < options.len() {
        match options[index] {
            0 => {
                if options[index..].iter().any(|value| *value != 0) {
                    return Err(MtuError::InvalidPacket);
                }
                break;
            }
            1 => index += 1,
            kind => {
                let length = *options.get(index + 1).ok_or(MtuError::InvalidPacket)? as usize;
                if length < 2 || index + length > options.len() {
                    return Err(MtuError::InvalidPacket);
                }
                if kind & 0x80 != 0 {
                    while copied.len() % 4 != index % 4 {
                        copied.push(1);
                    }
                    copied.extend_from_slice(&options[index..index + length]);
                }
                index += length;
            }
        }
    }
    copied.resize((copied.len() + 3) & !3, 0);
    Ok(copied)
}

pub fn icmp_fragmentation_needed(
    packet: &[u8],
    context: IcmpContext,
    mtu: usize,
    identification: u16,
) -> Result<Vec<u8>, MtuError> {
    if !(MIN_IPV4_MTU..=u16::MAX as usize).contains(&mtu) {
        return Err(MtuError::InvalidMtu);
    }
    if context.prefix_len > 32 {
        return Err(MtuError::InvalidPacket);
    }
    let info = parse_ipv4(packet).map_err(|_| MtuError::InvalidPacket)?;
    if internet_checksum(&packet[..info.header_length]) != 0 {
        return Err(MtuError::InvalidPacket);
    }
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    if flags & 0x8000 != 0 {
        return Err(MtuError::InvalidPacket);
    }
    if packet.len() <= mtu
        || flags & 0x1fff != 0
        || flags & 0x4000 == 0
        || !unicast(context.gateway)
        || !unicast(info.source)
        || !unicast(info.destination)
        || subnet_broadcast(info.source, context)
        || subnet_broadcast(info.destination, context)
    {
        return Err(MtuError::IcmpSuppressed);
    }
    if packet[9] == 1 {
        if packet.len() - info.header_length < 8 {
            return Err(MtuError::IcmpSuppressed);
        }
        let icmp_type = *packet
            .get(info.header_length)
            .ok_or(MtuError::IcmpSuppressed)?;
        if !matches!(
            icmp_type,
            0 | 8 | 9 | 10 | 13 | 14 | 15 | 16 | 17 | 18 | 42 | 43
        ) {
            return Err(MtuError::IcmpSuppressed);
        }
    }
    let quote_length = packet.len().min(info.header_length + 8);
    let mut response = vec![0; 28 + quote_length];
    response[0] = 0x45;
    let total = response.len() as u16;
    response[2..4].copy_from_slice(&total.to_be_bytes());
    response[4..6].copy_from_slice(&identification.to_be_bytes());
    response[8] = 64;
    response[9] = 1;
    response[12..16].copy_from_slice(&context.gateway.octets());
    response[16..20].copy_from_slice(&info.source.octets());
    response[20] = 3;
    response[21] = 4;
    response[26..28].copy_from_slice(&(mtu as u16).to_be_bytes());
    response[28..].copy_from_slice(&packet[..quote_length]);
    let icmp_checksum = internet_checksum(&response[20..]).to_be_bytes();
    response[22..24].copy_from_slice(&icmp_checksum);
    set_ipv4_header_checksum(&mut response).map_err(|_| MtuError::InvalidPacket)?;
    Ok(response)
}

fn unicast(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    first != 0 && first != 127 && first < 224
}

fn subnet_broadcast(address: Ipv4Addr, context: IcmpContext) -> bool {
    if context.prefix_len >= 31 {
        return false;
    }
    let address = u32::from(address);
    let leased = u32::from(context.address);
    let host_mask = u32::MAX >> context.prefix_len;
    address & !host_mask == leased & !host_mask && address & host_mask == host_mask
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEND_ICMP: FeedbackDecision = FeedbackDecision {
        send_icmp: true,
        use_capsule: false,
    };
    const USE_CAPSULE: FeedbackDecision = FeedbackDecision {
        send_icmp: false,
        use_capsule: true,
    };
    const DROP: FeedbackDecision = FeedbackDecision {
        send_icmp: false,
        use_capsule: false,
    };

    fn packet(length: usize, flags: u16, options: &[u8]) -> Vec<u8> {
        assert!(options.len().is_multiple_of(4));
        let header_length = 20 + options.len();
        let mut packet = vec![0; length];
        packet[0] = 0x40 | (header_length / 4) as u8;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&flags.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[8, 8, 8, 8]);
        packet[16..20].copy_from_slice(&[10, 66, 0, 2]);
        packet[20..header_length].copy_from_slice(options);
        for (index, byte) in packet[header_length..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        set_ipv4_header_checksum(&mut packet).unwrap();
        packet
    }

    fn flow_packet(port: u16) -> Vec<u8> {
        let mut packet = packet(1300, 0x4000, &[]);
        packet[20..22].copy_from_slice(&port.to_be_bytes());
        packet
    }

    fn context() -> IcmpContext {
        IcmpContext {
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            address: Ipv4Addr::new(10, 66, 0, 2),
            prefix_len: 24,
        }
    }

    fn assert_reconstruction(original: &[u8], fragments: &[Vec<u8>], mtu: usize) {
        let info = parse_ipv4(original).unwrap();
        let flags = u16::from_be_bytes([original[6], original[7]]);
        let mut offset = usize::from(flags & 0x1fff) * 8;
        let mut reconstructed = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            let fragment_info = parse_ipv4(fragment).unwrap();
            let fragment_flags = u16::from_be_bytes([fragment[6], fragment[7]]);
            assert!(fragment.len() <= mtu);
            assert_eq!(
                internet_checksum(&fragment[..fragment_info.header_length]),
                0
            );
            assert_eq!(&fragment[4..6], &original[4..6]);
            assert_eq!(&fragment[8..10], &original[8..10]);
            assert_eq!(&fragment[12..20], &original[12..20]);
            assert_eq!(usize::from(fragment_flags & 0x1fff) * 8, offset);
            assert_eq!(fragment_flags & 0xc000, 0);
            assert_eq!(
                fragment_flags & 0x2000 != 0,
                index + 1 < fragments.len() || flags & 0x2000 != 0
            );
            let payload = &fragment[fragment_info.header_length..];
            if fragment_flags & 0x2000 != 0 {
                assert!(payload.len().is_multiple_of(8));
            }
            offset += payload.len();
            reconstructed.extend_from_slice(payload);
        }
        assert_eq!(reconstructed, original[info.header_length..]);
    }

    #[test]
    fn datagram_budget_subtracts_only_http3_context_and_quarter_stream_id() {
        for (stream_id, overhead) in [
            (0, 2),
            (252, 2),
            (255, 2),
            (256, 3),
            (65_532, 3),
            (65_536, 5),
            ((1 << 32) - 4, 5),
            (1 << 32, 9),
            (u64::MAX, 9),
        ] {
            assert_eq!(
                ip_datagram_capacity(Some(1400), stream_id),
                Some(1400 - overhead)
            );
            assert_eq!(ip_datagram_capacity(Some(overhead), stream_id), Some(0));
            assert_eq!(ip_datagram_capacity(Some(overhead - 1), stream_id), Some(0));
            assert_eq!(ip_datagram_capacity(None, stream_id), None);
        }
        assert_eq!(ip_datagram_capacity(Some(0), 0), Some(0));
    }

    #[test]
    fn datagram_limit_only_decreases_and_rejects_unusable_capacity() {
        let mut mtu = DatagramMtu::new(1400);
        assert_eq!(mtu.limit(), 1400);
        assert_eq!(mtu.update(1400), Ok(false));
        assert_eq!(mtu.update(1160), Ok(true));
        assert_eq!(mtu.limit(), 1160);
        assert_eq!(mtu.update(1400), Ok(false));
        assert_eq!(mtu.update(usize::MAX), Ok(false));
        assert_eq!(mtu.limit(), 1160);
        for capacity in [0, 1, 67] {
            assert_eq!(mtu.update(capacity), Err(MtuError::InvalidMtu));
            assert_eq!(mtu.limit(), 1160);
        }
        assert_eq!(mtu.update(68), Ok(true));
        assert_eq!(mtu.limit(), 68);
        assert_eq!(mtu.update(68), Ok(false));
    }

    #[test]
    #[should_panic]
    fn datagram_limit_requires_a_usable_initial_ceiling() {
        DatagramMtu::new(67);
    }

    #[test]
    fn fragments_and_df_feedback_preserve_the_original_packet() {
        let original = packet(1300, 0, &[]);
        let unchanged = original.clone();
        let fragments = fragment_ipv4(&original, 1100).unwrap();
        assert_eq!(fragments.len(), 2);
        assert_reconstruction(&original, &fragments, 1100);
        assert_eq!(original, unchanged);
        assert_eq!(fragment_ipv4(&original, 1300).unwrap(), [original]);

        let df = packet(1300, 0x4000, &[]);
        assert_eq!(fragment_ipv4(&df, 1100), Err(MtuError::FragmentationNeeded));
        assert_eq!(fragment_ipv4(&df, 1300).unwrap(), [df]);
    }

    #[test]
    fn fragmentation_preserves_first_options_and_copies_aligned_options() {
        let options = [0x44, 4, 7, 8, 1, 0x83, 3, 0xaa, 0, 0, 0, 0];
        let original = packet(332, 0, &options);
        let fragments = fragment_ipv4(&original, 100).unwrap();
        assert_eq!(&fragments[0][20..32], &options);
        for fragment in &fragments[1..] {
            assert_eq!(fragment[0], 0x46);
            assert_eq!(&fragment[20..24], &[1, 0x83, 3, 0xaa]);
        }
        assert_reconstruction(&original, &fragments, 100);
    }

    #[test]
    fn refragmentation_preserves_existing_offsets_options_and_more_fragments() {
        let options = [0x44, 4, 7, 8, 1, 0x83, 3, 0xaa, 0, 0, 0, 0];
        for (flags, payload_length) in [(13, 301), (0x2000 | 13, 304)] {
            let original = packet(32 + payload_length, flags, &options);
            let fragments = fragment_ipv4(&original, 100).unwrap();
            for fragment in &fragments {
                assert_eq!(fragment[0], 0x46);
                assert_eq!(&fragment[20..24], &[1, 0x83, 3, 0xaa]);
            }
            assert_reconstruction(&original, &fragments, 100);
        }
    }

    #[test]
    fn repeated_fragmentation_reconstructs_the_complete_payload() {
        let options = [0x44, 4, 7, 8, 1, 0x83, 3, 0xaa];
        let original = packet(1300, 0, &options);
        let fragments: Vec<_> = fragment_ipv4(&original, 300)
            .unwrap()
            .iter()
            .flat_map(|fragment| fragment_ipv4(fragment, 100).unwrap())
            .collect();
        assert_reconstruction(&original, &fragments, 100);
        assert_eq!(&fragments[0][20..28], &options);
    }

    #[test]
    fn minimum_mtu_handles_a_maximum_length_ipv4_header() {
        let original = packet(190, 0, &[1; 40]);
        let fragments = fragment_ipv4(&original, 68).unwrap();
        assert_eq!(fragments[0].len(), 68);
        assert_eq!(fragments[0][0], 0x4f);
        assert!(fragments[1..].iter().all(|fragment| fragment[0] == 0x45));
        assert_reconstruction(&original, &fragments, 68);
    }

    #[test]
    fn fragmentation_and_icmp_reject_invalid_packets_and_mtus() {
        let original = packet(1300, 0x4000, &[]);
        for mtu in [0, 67, 65_536, usize::MAX] {
            assert_eq!(fragment_ipv4(&original, mtu), Err(MtuError::InvalidMtu));
            assert_eq!(
                icmp_fragmentation_needed(&original, context(), mtu, 0),
                Err(MtuError::InvalidMtu)
            );
        }
        let mut malformed = vec![vec![], vec![0; 19]];
        for (index, value) in [(0, 0x65), (0, 0x44), (2, 0), (8, 32), (6, 0xc0)] {
            let mut candidate = original.clone();
            candidate[index] = value;
            if index == 6 {
                set_ipv4_header_checksum(&mut candidate).unwrap();
            }
            malformed.push(candidate);
        }
        for candidate in malformed {
            assert_eq!(
                fragment_ipv4(&candidate, 1100),
                Err(MtuError::InvalidPacket)
            );
            assert_eq!(
                icmp_fragmentation_needed(&candidate, context(), 1100, 0),
                Err(MtuError::InvalidPacket)
            );
        }
    }

    #[test]
    fn fragmentation_rejects_malformed_options_and_impossible_offsets() {
        for options in [
            [0, 1, 0, 0],
            [0x82, 0, 0, 0],
            [0x82, 1, 0, 0],
            [0x82, 5, 0, 0],
            [1, 1, 1, 0x82],
        ] {
            assert_eq!(
                fragment_ipv4(&packet(200, 0, &options), 100),
                Err(MtuError::InvalidPacket)
            );
        }
        assert_eq!(
            fragment_ipv4(&packet(201, 0x2000, &[]), 100),
            Err(MtuError::InvalidPacket)
        );
        assert_eq!(
            fragment_ipv4(&packet(200, 0x1fff, &[]), 100),
            Err(MtuError::InvalidPacket)
        );
    }

    #[test]
    fn icmp_feedback_quotes_header_options_and_eight_bytes_with_valid_checksums() {
        let original = packet(1300, 0x4000, &[0x44, 4, 7, 8, 1, 0x83, 3, 0xaa]);
        let unchanged = original.clone();
        let reply = icmp_fragmentation_needed(&original, context(), 1100, 7).unwrap();
        let info = parse_ipv4(&reply).unwrap();
        assert_eq!(info.source, context().gateway);
        assert_eq!(info.destination, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(reply.len(), 28 + 28 + 8);
        assert_eq!(&reply[4..6], &7_u16.to_be_bytes());
        assert_eq!(&reply[20..22], &[3, 4]);
        assert_eq!(&reply[24..26], &[0, 0]);
        assert_eq!(&reply[26..28], &1100_u16.to_be_bytes());
        assert_eq!(&reply[28..], &original[..36]);
        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
        assert_eq!(original, unchanged);
    }

    #[test]
    fn icmp_is_suppressed_for_noninitial_fragments_no_df_and_fitting_packets() {
        for (flags, mtu) in [(0, 1100), (0x4001, 1100), (0x6001, 1100), (0x4000, 1300)] {
            assert_eq!(
                icmp_fragmentation_needed(&packet(1300, flags, &[]), context(), mtu, 0),
                Err(MtuError::IcmpSuppressed)
            );
        }
    }

    #[test]
    fn icmp_is_suppressed_for_multicast_broadcast_and_nonunicast_addresses() {
        for address in [
            [0, 0, 0, 0],
            [0, 1, 2, 3],
            [127, 0, 0, 1],
            [224, 0, 0, 1],
            [239, 1, 2, 3],
            [240, 0, 0, 1],
            [255, 255, 255, 255],
            [10, 66, 0, 255],
        ] {
            for offset in [12, 16] {
                let mut original = packet(1300, 0x4000, &[]);
                original[offset..offset + 4].copy_from_slice(&address);
                set_ipv4_header_checksum(&mut original).unwrap();
                assert_eq!(
                    icmp_fragmentation_needed(&original, context(), 1100, 0),
                    Err(MtuError::IcmpSuppressed)
                );
            }
        }
        for gateway in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
        ] {
            assert_eq!(
                icmp_fragmentation_needed(
                    &packet(1300, 0x4000, &[]),
                    IcmpContext {
                        gateway,
                        ..context()
                    },
                    1100,
                    0
                ),
                Err(MtuError::IcmpSuppressed)
            );
        }
    }

    #[test]
    fn icmp_never_answers_errors_or_unknown_icmp_types() {
        let mut original = packet(1300, 0x4000, &[]);
        original[9] = 1;
        set_ipv4_header_checksum(&mut original).unwrap();
        for icmp_type in 0..=u8::MAX {
            original[20] = icmp_type;
            let reply = icmp_fragmentation_needed(&original, context(), 1100, 0);
            if matches!(
                icmp_type,
                0 | 8 | 9 | 10 | 13 | 14 | 15 | 16 | 17 | 18 | 42 | 43
            ) {
                assert!(reply.is_ok(), "ICMP type {icmp_type}");
            } else {
                assert_eq!(
                    reply,
                    Err(MtuError::IcmpSuppressed),
                    "ICMP type {icmp_type}"
                );
            }
        }
    }

    #[test]
    fn icmp_context_rejects_invalid_prefixes_and_handles_host_prefixes() {
        let mut original = packet(1300, 0x4000, &[]);
        original[16..20].copy_from_slice(&[10, 66, 0, 255]);
        set_ipv4_header_checksum(&mut original).unwrap();
        for prefix_len in [0, 31, 32] {
            assert!(icmp_fragmentation_needed(
                &original,
                IcmpContext {
                    prefix_len,
                    ..context()
                },
                1100,
                0
            )
            .is_ok());
        }
        for prefix_len in [33, 64, 255] {
            assert_eq!(
                icmp_fragmentation_needed(
                    &original,
                    IcmpContext {
                        prefix_len,
                        ..context()
                    },
                    1100,
                    0
                ),
                Err(MtuError::InvalidPacket)
            );
        }
    }

    #[test]
    fn icmp_host_route_context_allows_leased_source_and_off_prefix_gateway() {
        let context = IcmpContext {
            prefix_len: 32,
            ..context()
        };
        let mut original = packet(1300, 0x4000, &[]);
        original[12..16].copy_from_slice(&context.address.octets());
        original[16..20].copy_from_slice(&[1, 1, 1, 1]);
        set_ipv4_header_checksum(&mut original).unwrap();
        let reply = icmp_fragmentation_needed(&original, context, 1160, 7).unwrap();
        let info = parse_ipv4(&reply).unwrap();
        assert_eq!(info.source, context.gateway);
        assert_eq!(info.destination, context.address);
        assert_eq!(&reply[28..], &original[..28]);
        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
    }

    #[test]
    fn feedback_requires_three_prior_requests_and_a_minimum_grace() {
        let mut policy = FeedbackPolicy::default();
        let packet = flow_packet(1);
        let now = Instant::now();
        let rtt = Duration::from_millis(10);
        for elapsed in [0, 100, 200, 1999] {
            assert_eq!(
                policy.on_oversized(
                    &packet,
                    1160,
                    1400,
                    now + Duration::from_millis(elapsed),
                    rtt
                ),
                SEND_ICMP
            );
        }
        assert_eq!(
            policy.on_oversized(&packet, 1160, 1400, now + Duration::from_secs(2), rtt),
            USE_CAPSULE
        );
        assert_eq!(policy.flows[0].feedback_requests, 3);
    }

    #[test]
    fn above_capsule_ceiling_keeps_globally_limited_feedback_after_grace() {
        let mut policy = FeedbackPolicy::default();
        let first = packet(1380, 0x4000, &[]);
        let mut second = first.clone();
        second[20..22].copy_from_slice(&2_u16.to_be_bytes());
        let now = Instant::now();
        let rtt = Duration::ZERO;
        for elapsed in [0, 100, 200, 2000, 2100, 10_000, 60_000] {
            let at = now + Duration::from_millis(elapsed);
            assert_eq!(policy.on_oversized(&first, 1100, 1100, at, rtt), SEND_ICMP);
            assert_eq!(policy.on_oversized(&first, 1100, 1100, at, rtt), DROP);
            assert_eq!(
                policy.on_oversized(&second, 1100, 1100, at + Duration::from_millis(99), rtt),
                DROP
            );
        }
    }

    #[test]
    fn capsule_ceiling_is_checked_for_each_packet_even_after_flow_fallback() {
        let mut policy = FeedbackPolicy::default();
        let within_ceiling = packet(1300, 0x4000, &[]);
        let now = Instant::now();
        let rtt = Duration::ZERO;
        for elapsed in [0, 100, 200] {
            assert_eq!(
                policy.on_oversized(
                    &within_ceiling,
                    1160,
                    1300,
                    now + Duration::from_millis(elapsed),
                    rtt
                ),
                SEND_ICMP
            );
        }
        for (index, length) in [1301, 1380].into_iter().enumerate() {
            let at = now + Duration::from_millis(2000 + index as u64 * 100);
            assert_eq!(
                policy.on_oversized(&within_ceiling, 1160, 1300, at, rtt),
                USE_CAPSULE
            );
            let above_ceiling = packet(length, 0x4000, &[]);
            assert_eq!(
                classify_ipv4(&within_ceiling).flow,
                classify_ipv4(&above_ceiling).flow
            );
            assert_eq!(
                policy.on_oversized(&above_ceiling, 1160, 1300, at, rtt),
                SEND_ICMP
            );
            assert_eq!(
                policy.on_oversized(&above_ceiling, 1160, 1300, at, rtt),
                DROP
            );
        }
    }

    #[test]
    fn feedback_grace_scales_with_rtt_and_is_capped_at_ten_seconds() {
        let packet = flow_packet(1);
        let now = Instant::now();
        for (rtt, grace_ms) in [
            (Duration::ZERO, 2000),
            (Duration::from_secs(1), 4000),
            (Duration::from_secs(30), 10_000),
            (Duration::MAX, 10_000),
        ] {
            let mut policy = FeedbackPolicy::default();
            for elapsed in [0, 100, 200, grace_ms - 1] {
                assert_eq!(
                    policy.on_oversized(
                        &packet,
                        1160,
                        1400,
                        now + Duration::from_millis(elapsed),
                        rtt
                    ),
                    SEND_ICMP
                );
            }
            assert_eq!(
                policy.on_oversized(
                    &packet,
                    1160,
                    1400,
                    now + Duration::from_millis(grace_ms),
                    rtt
                ),
                USE_CAPSULE
            );
        }
    }

    #[test]
    fn rate_limited_packets_do_not_count_as_prior_feedback() {
        let mut policy = FeedbackPolicy::default();
        let packet = flow_packet(1);
        let now = Instant::now();
        let rtt = Duration::ZERO;
        assert_eq!(
            policy.on_oversized(&packet, 1160, 1400, now, rtt),
            SEND_ICMP
        );
        for elapsed in 0..100 {
            assert_eq!(
                policy.on_oversized(
                    &packet,
                    1160,
                    1400,
                    now + Duration::from_millis(elapsed),
                    rtt
                ),
                DROP
            );
        }
        assert_eq!(policy.flows[0].feedback_requests, 1);
        assert_eq!(
            policy.on_oversized(&packet, 1160, 1400, now + Duration::from_secs(3), rtt),
            SEND_ICMP
        );
        assert_eq!(
            policy.on_oversized(&packet, 1160, 1400, now + Duration::from_secs(4), rtt),
            SEND_ICMP
        );
        assert_eq!(
            policy.on_oversized(&packet, 1160, 1400, now + Duration::from_secs(4), rtt),
            USE_CAPSULE
        );
    }

    #[test]
    fn feedback_rate_limit_is_connection_wide_but_fallback_is_per_flow() {
        let mut policy = FeedbackPolicy::default();
        let first = flow_packet(1);
        let second = flow_packet(2);
        let now = Instant::now();
        let rtt = Duration::ZERO;
        for elapsed in [0, 100, 200] {
            let at = now + Duration::from_millis(elapsed);
            assert_eq!(policy.on_oversized(&first, 1160, 1400, at, rtt), SEND_ICMP);
            assert_eq!(policy.on_oversized(&second, 1160, 1400, at, rtt), DROP);
        }
        let at = now + Duration::from_secs(2);
        assert_eq!(
            policy.on_oversized(&first, 1160, 1400, at, rtt),
            USE_CAPSULE
        );
        assert_eq!(policy.on_oversized(&second, 1160, 1400, at, rtt), SEND_ICMP);
        assert_eq!(
            policy.on_oversized(&first, 1160, 1400, at, rtt),
            USE_CAPSULE
        );
        assert_eq!(policy.flows.len(), 2);
        let second = policy
            .flows
            .iter()
            .find(|state| state.flow.source_port == 2)
            .unwrap();
        assert_eq!(second.feedback_requests, 1);
        assert_eq!(second.first_feedback, Some(at));
    }

    #[test]
    fn a_lower_mtu_resets_only_that_flows_feedback_and_preserves_the_global_gate() {
        let mut policy = FeedbackPolicy::default();
        let first = flow_packet(1);
        let second = flow_packet(2);
        let now = Instant::now();
        let rtt = Duration::ZERO;
        for elapsed in [0, 200, 400] {
            assert_eq!(
                policy.on_oversized(
                    &first,
                    1160,
                    1400,
                    now + Duration::from_millis(elapsed),
                    rtt
                ),
                SEND_ICMP
            );
            assert_eq!(
                policy.on_oversized(
                    &second,
                    1160,
                    1400,
                    now + Duration::from_millis(elapsed + 100),
                    rtt
                ),
                SEND_ICMP
            );
        }
        let later = now + Duration::from_secs(3);
        assert_eq!(
            policy.on_oversized(&first, 1160, 1400, later, rtt),
            USE_CAPSULE
        );
        assert_eq!(
            policy.on_oversized(&second, 1160, 1400, later, rtt),
            USE_CAPSULE
        );
        assert_eq!(
            policy.on_oversized(&first, 1100, 1400, later, rtt),
            SEND_ICMP
        );
        assert_eq!(
            policy.on_oversized(&second, 1160, 1400, later, rtt),
            USE_CAPSULE
        );
        assert_eq!(policy.on_oversized(&first, 1000, 1400, later, rtt), DROP);
        for elapsed in [100, 200, 300, 2099] {
            assert_eq!(
                policy.on_oversized(
                    &first,
                    1000,
                    1400,
                    later + Duration::from_millis(elapsed),
                    rtt
                ),
                SEND_ICMP
            );
        }
        assert_eq!(
            policy.on_oversized(&first, 1000, 1400, later + Duration::from_millis(2100), rtt),
            USE_CAPSULE
        );
    }

    #[test]
    fn fitting_acks_do_not_reset_or_refresh_nonconvergence() {
        let mut policy = FeedbackPolicy::default();
        let mut oversized = flow_packet(1);
        oversized[9] = 6;
        oversized[32] = 5 << 4;
        oversized[33] = 0x10;
        set_ipv4_header_checksum(&mut oversized).unwrap();
        let mut ack = oversized[..40].to_vec();
        ack[2..4].copy_from_slice(&40_u16.to_be_bytes());
        set_ipv4_header_checksum(&mut ack).unwrap();
        assert_eq!(classify_ipv4(&ack).flow, classify_ipv4(&oversized).flow);
        let now = Instant::now();
        let rtt = Duration::ZERO;
        for elapsed in [0, 100, 200] {
            assert_eq!(
                policy.on_oversized(
                    &oversized,
                    1160,
                    1400,
                    now + Duration::from_millis(elapsed),
                    rtt
                ),
                SEND_ICMP
            );
        }
        assert_eq!(
            policy.on_oversized(&ack, 1100, 1400, now + Duration::from_secs(1), rtt),
            DROP
        );
        assert_eq!(policy.flows[0].mtu, 1160);
        assert_eq!(policy.flows[0].last_seen, now + Duration::from_millis(200));
        assert_eq!(
            policy.on_oversized(&oversized, 1160, 1400, now + Duration::from_secs(2), rtt),
            USE_CAPSULE
        );
    }

    #[test]
    fn flow_state_expires_after_sixty_seconds_without_oversized_packets() {
        let mut policy = FeedbackPolicy::default();
        let first = flow_packet(1);
        let second = flow_packet(2);
        let now = Instant::now();
        let rtt = Duration::ZERO;
        for elapsed in [0, 100, 200] {
            policy.on_oversized(
                &first,
                1160,
                1400,
                now + Duration::from_millis(elapsed),
                rtt,
            );
        }
        let last_seen = now + Duration::from_millis(200);
        let before_expiry = last_seen + Duration::from_millis(59_999);
        assert_eq!(
            policy.on_oversized(&second, 1160, 1400, before_expiry, rtt),
            SEND_ICMP
        );
        assert_eq!(policy.flows.len(), 2);
        let expiry = last_seen + Duration::from_secs(60);
        assert_eq!(policy.on_oversized(&first, 1160, 1400, expiry, rtt), DROP);
        let state = policy
            .flows
            .iter()
            .find(|state| state.flow.source_port == 1)
            .unwrap();
        assert_eq!(state.feedback_requests, 0);
        assert_eq!(state.first_feedback, None);
        assert_eq!(policy.flows.len(), 2);
        assert_eq!(
            policy.on_oversized(&first, 1160, 1400, expiry + ICMP_INTERVAL, rtt),
            SEND_ICMP
        );
    }

    #[test]
    fn full_flow_table_evicts_least_recently_seen_with_deterministic_ties() {
        let mut policy = FeedbackPolicy::default();
        let now = Instant::now();
        let rtt = Duration::ZERO;
        for port in 0..128 {
            policy.on_oversized(&flow_packet(port), 1160, 1400, now, rtt);
        }
        assert_eq!(policy.flows.len(), 128);
        policy.on_oversized(&flow_packet(0), 1160, 1400, now + ICMP_INTERVAL, rtt);
        policy.on_oversized(&flow_packet(128), 1160, 1400, now + ICMP_INTERVAL, rtt);
        assert_eq!(policy.flows.len(), 128);
        assert!(policy.flows.iter().any(|state| state.flow.source_port == 0));
        assert!(!policy.flows.iter().any(|state| state.flow.source_port == 1));
        policy.on_oversized(&flow_packet(129), 1160, 1400, now + ICMP_INTERVAL, rtt);
        assert!(!policy.flows.iter().any(|state| state.flow.source_port == 2));
        for port in 130..1000 {
            policy.on_oversized(&flow_packet(port), 1160, 1400, now + ICMP_INTERVAL, rtt);
            assert_eq!(policy.flows.len(), 128);
        }
    }
}
