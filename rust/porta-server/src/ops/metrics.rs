use std::fmt::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

const PUBLIC_TRANSPORTS: usize = 2;
const PUBLIC_REJECTIONS: usize = 5;
const ABUSE_SURFACES: usize = 4;
const TUNNEL_LANES: usize = 4;

#[derive(Debug, Default)]
pub struct Metrics {
    active_tunnels: AtomicI64,
    connections_total: AtomicU64,
    auth_failures: AtomicU64,
    public_connections: [AtomicI64; PUBLIC_TRANSPORTS],
    public_connections_total: [AtomicU64; PUBLIC_TRANSPORTS],
    public_connection_rejected: [AtomicU64; PUBLIC_REJECTIONS],
    quic_retries: AtomicU64,
    abuse_rejected: [AtomicU64; ABUSE_SURFACES],
    packets_from_client: AtomicU64,
    packets_to_client: AtomicU64,
    dropped_packets_from_client: AtomicU64,
    datagram_oversize: AtomicU64,
    queue_oldest_drops: AtomicU64,
    queue_full_drops: AtomicU64,
    queue_tail_drops: AtomicU64,
    queue_expired_drops: AtomicU64,
    lane_collapsed_groups: AtomicU64,
    queue_bytes_current: [AtomicI64; TUNNEL_LANES],
    queue_bytes_high_water: [AtomicU64; TUNNEL_LANES],
    closed_session_drops: AtomicU64,
    invalid_tun_drops: AtomicU64,
    no_session_drops: AtomicU64,
    mtu_fragmented: AtomicU64,
    mtu_icmp_sent: AtomicU64,
    mtu_icmp_suppressed: AtomicU64,
    mtu_icmp_rate_limited: AtomicU64,
}

impl Metrics {
    pub fn public_connection_opened(&self, transport: &str) {
        if let Some(index) = public_transport_index(transport) {
            self.public_connections[index].fetch_add(1, Ordering::Relaxed);
            self.public_connections_total[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn public_connection_closed(&self, transport: &str) {
        if let Some(index) = public_transport_index(transport) {
            self.public_connections[index].fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn public_connection_rejected(&self, transport: &str, reason: &str) {
        let index = match (transport, reason) {
            ("tcp", "global") => 0,
            ("tcp", "source") => 1,
            ("quic", "global") => 2,
            ("quic", "source") => 3,
            ("quic", "unverified") => 4,
            _ => return,
        };
        self.public_connection_rejected[index].fetch_add(1, Ordering::Relaxed);
    }

    pub fn quic_retry(&self) {
        self.quic_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn abuse_rejected(&self, surface: &str) {
        let index = match surface {
            "native" => 0,
            "proxy" => 1,
            "portal" => 2,
            "invitation" => 3,
            _ => return,
        };
        self.abuse_rejected[index].fetch_add(1, Ordering::Relaxed);
    }

    pub fn connected(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.active_tunnels.fetch_add(1, Ordering::Relaxed);
    }

    pub fn disconnected(&self) {
        self.active_tunnels.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn authentication_failed(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn received_from_client(&self) {
        self.packets_from_client.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sent_to_client(&self) {
        self.packets_to_client.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dropped_from_client(&self) {
        self.dropped_packets_from_client
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn datagram_oversize(&self) {
        self.datagram_oversize.fetch_add(1, Ordering::Relaxed);
    }

    pub fn queue_drop(&self, reason: &str) {
        let target = match reason {
            "queue_oldest" => &self.queue_oldest_drops,
            "queue_full" => &self.queue_full_drops,
            "queue_tail" => &self.queue_tail_drops,
            "queue_expired" => &self.queue_expired_drops,
            "session_closed" => &self.closed_session_drops,
            "invalid_tun_packet" => &self.invalid_tun_drops,
            "no_session" => &self.no_session_drops,
            _ => return,
        };
        target.fetch_add(1, Ordering::Relaxed);
    }

    pub fn lane_collapsed(&self) {
        self.lane_collapsed_groups.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mtu_action(&self, action: &str) {
        let target = match action {
            "fragmented" => &self.mtu_fragmented,
            "icmp_sent" => &self.mtu_icmp_sent,
            "icmp_suppressed" => &self.mtu_icmp_suppressed,
            "icmp_rate_limited" => &self.mtu_icmp_rate_limited,
            _ => return,
        };
        target.fetch_add(1, Ordering::Relaxed);
    }

    pub fn adjust_queue_bytes(&self, lane: usize, delta: i64) {
        let Some(current) = self.queue_bytes_current.get(lane) else {
            return;
        };
        let value = current.fetch_add(delta, Ordering::Relaxed) + delta;
        let value = if value < 0 {
            current.store(0, Ordering::Relaxed);
            0
        } else {
            value as u64
        };
        let high_water = &self.queue_bytes_high_water[lane];
        let mut previous = high_water.load(Ordering::Relaxed);
        while value > previous {
            match high_water.compare_exchange_weak(
                previous,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => previous = next,
            }
        }
    }

    pub fn render_prometheus(&self) -> String {
        let mut output = String::with_capacity(4096);
        metric(
            &mut output,
            "porta_active_tunnels",
            "gauge",
            "Current authenticated tunnel connections.",
            self.active_tunnels.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "porta_connections_total",
            "counter",
            "Authenticated tunnel connections accepted.",
            self.connections_total.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "porta_auth_failures_total",
            "counter",
            "Rejected tunnel authentication attempts.",
            self.auth_failures.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "porta_packets_from_client_total",
            "counter",
            "IPv4 packets accepted from tunnel clients.",
            self.packets_from_client.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "porta_packets_to_client_total",
            "counter",
            "IPv4 packets sent to tunnel clients.",
            self.packets_to_client.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "porta_dropped_packets_from_client_total",
            "counter",
            "Invalid or source-mismatched packets dropped from tunnel clients.",
            self.dropped_packets_from_client.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "porta_datagram_oversize_total",
            "counter",
            "Outgoing datagram payload-limit errors requiring capsule fallback.",
            self.datagram_oversize.load(Ordering::Relaxed),
        );
        family(
            &mut output,
            "porta_public_connections",
            "gauge",
            "Current accepted public transport connections.",
            ["tcp", "quic"]
                .into_iter()
                .enumerate()
                .map(|(index, label)| {
                    (
                        format!("transport={label:?}"),
                        self.public_connections[index].load(Ordering::Relaxed),
                    )
                }),
        );
        family(
            &mut output,
            "porta_public_connections_total",
            "counter",
            "Accepted public transport connections.",
            ["tcp", "quic"]
                .into_iter()
                .enumerate()
                .map(|(index, label)| {
                    (
                        format!("transport={label:?}"),
                        self.public_connections_total[index].load(Ordering::Relaxed),
                    )
                }),
        );
        family(
            &mut output,
            "porta_public_connection_rejections_total",
            "counter",
            "Public transport connections rejected by admission controls.",
            [
                ("tcp", "global"),
                ("tcp", "source"),
                ("quic", "global"),
                ("quic", "source"),
                ("quic", "unverified"),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (transport, reason))| {
                (
                    format!("transport={transport:?},reason={reason:?}"),
                    self.public_connection_rejected[index].load(Ordering::Relaxed),
                )
            }),
        );
        metric(
            &mut output,
            "porta_quic_retries_total",
            "counter",
            "QUIC handshakes required to validate their source address under pressure.",
            self.quic_retries.load(Ordering::Relaxed),
        );
        family(
            &mut output,
            "porta_abuse_rejections_total",
            "counter",
            "Authentication attempts rejected by the bounded failure limiter.",
            ["native", "proxy", "portal", "invitation"]
                .into_iter()
                .enumerate()
                .map(|(index, surface)| {
                    (
                        format!("surface={surface:?}"),
                        self.abuse_rejected[index].load(Ordering::Relaxed),
                    )
                }),
        );
        family(
            &mut output,
            "porta_router_dropped_packets_total",
            "counter",
            "Packets dropped by the gateway router by reason.",
            [
                ("queue_oldest", &self.queue_oldest_drops),
                ("queue_full", &self.queue_full_drops),
                ("queue_tail", &self.queue_tail_drops),
                ("queue_expired", &self.queue_expired_drops),
                ("session_closed", &self.closed_session_drops),
                ("invalid_tun_packet", &self.invalid_tun_drops),
                ("no_session", &self.no_session_drops),
            ]
            .into_iter()
            .map(|(reason, value)| (format!("reason={reason:?}"), value.load(Ordering::Relaxed))),
        );
        family(
            &mut output,
            "porta_router_queue_bytes",
            "gauge",
            "Current queued packet bytes by HTTP/2 lane.",
            self.queue_bytes_current
                .iter()
                .enumerate()
                .map(|(lane, value)| {
                    (
                        format!("lane={:?}", lane.to_string()),
                        value.load(Ordering::Relaxed),
                    )
                }),
        );
        family(
            &mut output,
            "porta_router_queue_bytes_high_water",
            "gauge",
            "Largest observed aggregate packet queue size by HTTP/2 lane.",
            self.queue_bytes_high_water
                .iter()
                .enumerate()
                .map(|(lane, value)| {
                    (
                        format!("lane={:?}", lane.to_string()),
                        value.load(Ordering::Relaxed),
                    )
                }),
        );
        metric(
            &mut output,
            "porta_http2_collapsed_lane_groups_total",
            "counter",
            "HTTP/2 lane groups observed on fewer backend TCP connections than lanes.",
            self.lane_collapsed_groups.load(Ordering::Relaxed),
        );
        family(
            &mut output,
            "porta_mtu_packets_total",
            "counter",
            "Oversized downlink packets handled by action.",
            [
                ("fragmented", &self.mtu_fragmented),
                ("icmp_sent", &self.mtu_icmp_sent),
                ("icmp_suppressed", &self.mtu_icmp_suppressed),
                ("icmp_rate_limited", &self.mtu_icmp_rate_limited),
            ]
            .into_iter()
            .map(|(action, value)| (format!("action={action:?}"), value.load(Ordering::Relaxed))),
        );
        output.push('\n');
        output
    }
}

fn public_transport_index(transport: &str) -> Option<usize> {
    match transport {
        "tcp" => Some(0),
        "quic" => Some(1),
        _ => None,
    }
}

fn metric(output: &mut String, name: &str, kind: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(output, "# HELP {name} {help}");
    let _ = writeln!(output, "# TYPE {name} {kind}");
    let _ = writeln!(output, "{name} {value}");
}

fn family<V>(
    output: &mut String,
    name: &str,
    kind: &str,
    help: &str,
    values: impl IntoIterator<Item = (String, V)>,
) where
    V: std::fmt::Display,
{
    let _ = writeln!(output, "# HELP {name} {help}");
    let _ = writeln!(output, "# TYPE {name} {kind}");
    for (labels, value) in values {
        let _ = writeln!(output, "{name}{{{labels}}} {value}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_compatible_metric_names() {
        let metrics = Metrics::default();
        metrics.public_connection_opened("tcp");
        metrics.connected();
        metrics.adjust_queue_bytes(1, 4096);
        let output = metrics.render_prometheus();
        assert!(output.contains("porta_active_tunnels 1"));
        assert!(output.contains("porta_public_connections{transport=\"tcp\"} 1"));
    }
}
