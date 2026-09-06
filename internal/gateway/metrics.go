package gateway

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
)

type Metrics struct {
	activeTunnels            atomic.Int64
	connectionsTotal         atomic.Uint64
	authFailures             atomic.Uint64
	publicConnections        [2]atomic.Int64
	publicConnectionsTotal   [2]atomic.Uint64
	publicConnectionRejected [5]atomic.Uint64
	quicRetries              atomic.Uint64
	abuseRejected            [4]atomic.Uint64
	packetsFromClient        atomic.Uint64
	packetsToClient          atomic.Uint64
	droppedPacketsFromClient atomic.Uint64
	datagramOversize         atomic.Uint64
	queueOldestDrops         atomic.Uint64
	queueFullDrops           atomic.Uint64
	queueTailDrops           atomic.Uint64
	queueExpiredDrops        atomic.Uint64
	laneCollapsedGroups      atomic.Uint64
	queueBytesCurrent        [maxTunnelLanes]atomic.Int64
	queueBytesHighWater      [maxTunnelLanes]atomic.Uint64
	closedSessionDrops       atomic.Uint64
	invalidTUNDrops          atomic.Uint64
	noSessionDrops           atomic.Uint64
	mtuFragmented            atomic.Uint64
	mtuICMPSent              atomic.Uint64
	mtuICMPSuppressed        atomic.Uint64
	mtuICMPRateLimited       atomic.Uint64
}

func (m *Metrics) PublicConnectionOpened(transport string) {
	if index := publicTransportIndex(transport); index >= 0 {
		m.publicConnections[index].Add(1)
		m.publicConnectionsTotal[index].Add(1)
	}
}

func (m *Metrics) PublicConnectionClosed(transport string) {
	if index := publicTransportIndex(transport); index >= 0 {
		m.publicConnections[index].Add(-1)
	}
}

func (m *Metrics) PublicConnectionRejected(transport, reason string) {
	switch transport + ":" + reason {
	case "tcp:global":
		m.publicConnectionRejected[0].Add(1)
	case "tcp:source":
		m.publicConnectionRejected[1].Add(1)
	case "quic:global":
		m.publicConnectionRejected[2].Add(1)
	case "quic:source":
		m.publicConnectionRejected[3].Add(1)
	case "quic:unverified":
		m.publicConnectionRejected[4].Add(1)
	}
}

func (m *Metrics) QUICRetry() {
	m.quicRetries.Add(1)
}

func (m *Metrics) AbuseRejected(surface string) {
	switch surface {
	case "native":
		m.abuseRejected[0].Add(1)
	case "proxy":
		m.abuseRejected[1].Add(1)
	case "portal":
		m.abuseRejected[2].Add(1)
	case "invitation":
		m.abuseRejected[3].Add(1)
	}
}

func publicTransportIndex(transport string) int {
	switch transport {
	case "tcp":
		return 0
	case "quic":
		return 1
	default:
		return -1
	}
}

// DatagramOversize records a datagram payload-limit error requiring capsule
// fallback. It does not count a packet drop.
func (m *Metrics) DatagramOversize() {
	m.datagramOversize.Add(1)
}

func (m *Metrics) connected() {
	m.connectionsTotal.Add(1)
	m.activeTunnels.Add(1)
}

func (m *Metrics) disconnected() {
	m.activeTunnels.Add(-1)
}

func (m *Metrics) authenticationFailed() {
	m.authFailures.Add(1)
}

func (m *Metrics) receivedFromClient() {
	m.packetsFromClient.Add(1)
}

func (m *Metrics) sentToClient() {
	m.packetsToClient.Add(1)
}

func (m *Metrics) droppedFromClient() {
	m.droppedPacketsFromClient.Add(1)
}

func (m *Metrics) adjustQueueBytes(lane int, delta int64) {
	if lane < 0 || lane >= len(m.queueBytesCurrent) {
		return
	}
	value := m.queueBytesCurrent[lane].Add(delta)
	if value < 0 {
		m.queueBytesCurrent[lane].Store(0)
		value = 0
	}
	for {
		previous := m.queueBytesHighWater[lane].Load()
		if uint64(value) <= previous || m.queueBytesHighWater[lane].CompareAndSwap(previous, uint64(value)) {
			return
		}
	}
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	metrics := []struct {
		name  string
		kind  string
		help  string
		value any
	}{
		{"porta_active_tunnels", "gauge", "Current authenticated tunnel connections.", m.activeTunnels.Load()},
		{"porta_connections_total", "counter", "Authenticated tunnel connections accepted.", m.connectionsTotal.Load()},
		{"porta_auth_failures_total", "counter", "Rejected tunnel authentication attempts.", m.authFailures.Load()},
		{"porta_packets_from_client_total", "counter", "IPv4 packets accepted from tunnel clients.", m.packetsFromClient.Load()},
		{"porta_packets_to_client_total", "counter", "IPv4 packets sent to tunnel clients.", m.packetsToClient.Load()},
		{"porta_dropped_packets_from_client_total", "counter", "Invalid or source-mismatched packets dropped from tunnel clients.", m.droppedPacketsFromClient.Load()},
		{"porta_datagram_oversize_total", "counter", "Outgoing datagram payload-limit errors requiring capsule fallback.", m.datagramOversize.Load()},
	}
	for _, metric := range metrics {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", metric.name, metric.help, metric.name, metric.kind, metric.name, metric.value)
	}
	_, _ = io.WriteString(w, "# HELP porta_public_connections Current accepted public transport connections.\n# TYPE porta_public_connections gauge\n")
	for index, transport := range []string{"tcp", "quic"} {
		_, _ = fmt.Fprintf(w, "porta_public_connections{transport=%q} %d\n", transport, m.publicConnections[index].Load())
	}
	_, _ = io.WriteString(w, "# HELP porta_public_connections_total Accepted public transport connections.\n# TYPE porta_public_connections_total counter\n")
	for index, transport := range []string{"tcp", "quic"} {
		_, _ = fmt.Fprintf(w, "porta_public_connections_total{transport=%q} %d\n", transport, m.publicConnectionsTotal[index].Load())
	}
	_, _ = io.WriteString(w, "# HELP porta_public_connection_rejections_total Public transport connections rejected by admission controls.\n# TYPE porta_public_connection_rejections_total counter\n")
	for index, rejection := range []struct {
		transport string
		reason    string
	}{
		{"tcp", "global"},
		{"tcp", "source"},
		{"quic", "global"},
		{"quic", "source"},
		{"quic", "unverified"},
	} {
		_, _ = fmt.Fprintf(
			w,
			"porta_public_connection_rejections_total{transport=%q,reason=%q} %d\n",
			rejection.transport,
			rejection.reason,
			m.publicConnectionRejected[index].Load(),
		)
	}
	_, _ = fmt.Fprintf(
		w,
		"# HELP porta_quic_retries_total QUIC handshakes required to validate their source address under pressure.\n"+
			"# TYPE porta_quic_retries_total counter\nporta_quic_retries_total %d\n",
		m.quicRetries.Load(),
	)
	_, _ = io.WriteString(w, "# HELP porta_abuse_rejections_total Authentication attempts rejected by the bounded failure limiter.\n# TYPE porta_abuse_rejections_total counter\n")
	for index, surface := range []string{"native", "proxy", "portal", "invitation"} {
		_, _ = fmt.Fprintf(w, "porta_abuse_rejections_total{surface=%q} %d\n", surface, m.abuseRejected[index].Load())
	}
	_, _ = io.WriteString(w, "# HELP porta_router_dropped_packets_total Packets dropped by the gateway router by reason.\n# TYPE porta_router_dropped_packets_total counter\n")
	for _, drop := range []struct {
		reason string
		count  uint64
	}{
		{"queue_oldest", m.queueOldestDrops.Load()},
		{"queue_full", m.queueFullDrops.Load()},
		{"queue_tail", m.queueTailDrops.Load()},
		{"queue_expired", m.queueExpiredDrops.Load()},
		{"session_closed", m.closedSessionDrops.Load()},
		{"invalid_tun_packet", m.invalidTUNDrops.Load()},
		{"no_session", m.noSessionDrops.Load()},
	} {
		_, _ = fmt.Fprintf(w, "porta_router_dropped_packets_total{reason=%q} %d\n", drop.reason, drop.count)
	}
	_, _ = io.WriteString(w, "# HELP porta_router_queue_bytes Current queued packet bytes by HTTP/2 lane.\n# TYPE porta_router_queue_bytes gauge\n")
	for lane := range m.queueBytesCurrent {
		_, _ = fmt.Fprintf(w, "porta_router_queue_bytes{lane=%q} %d\n", fmt.Sprint(lane), m.queueBytesCurrent[lane].Load())
	}
	_, _ = io.WriteString(w, "# HELP porta_router_queue_bytes_high_water Largest observed aggregate packet queue size by HTTP/2 lane.\n# TYPE porta_router_queue_bytes_high_water gauge\n")
	for lane := range m.queueBytesHighWater {
		_, _ = fmt.Fprintf(w, "porta_router_queue_bytes_high_water{lane=%q} %d\n", fmt.Sprint(lane), m.queueBytesHighWater[lane].Load())
	}
	_, _ = fmt.Fprintf(
		w,
		"# HELP porta_http2_collapsed_lane_groups_total HTTP/2 lane groups observed on fewer backend TCP connections than lanes.\n"+
			"# TYPE porta_http2_collapsed_lane_groups_total counter\n"+
			"porta_http2_collapsed_lane_groups_total %d\n",
		m.laneCollapsedGroups.Load(),
	)
	_, _ = io.WriteString(w, "# HELP porta_mtu_packets_total Oversized downlink packets handled by action.\n# TYPE porta_mtu_packets_total counter\n")
	for _, action := range []struct {
		name  string
		count uint64
	}{
		{"fragmented", m.mtuFragmented.Load()},
		{"icmp_sent", m.mtuICMPSent.Load()},
		{"icmp_suppressed", m.mtuICMPSuppressed.Load()},
		{"icmp_rate_limited", m.mtuICMPRateLimited.Load()},
	} {
		_, _ = fmt.Fprintf(w, "porta_mtu_packets_total{action=%q} %d\n", action.name, action.count)
	}
	_, _ = io.WriteString(w, "\n")
}
