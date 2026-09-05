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
	packetsFromClient        atomic.Uint64
	packetsToClient          atomic.Uint64
	droppedPacketsFromClient atomic.Uint64
	datagramOversize         atomic.Uint64
	queueOldestDrops         atomic.Uint64
	queueFullDrops           atomic.Uint64
	closedSessionDrops       atomic.Uint64
	invalidTUNDrops          atomic.Uint64
	noSessionDrops           atomic.Uint64
	mtuFragmented            atomic.Uint64
	mtuICMPSent              atomic.Uint64
	mtuICMPSuppressed        atomic.Uint64
	mtuICMPRateLimited       atomic.Uint64
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
	_, _ = io.WriteString(w, "# HELP porta_router_dropped_packets_total Packets dropped by the gateway router by reason.\n# TYPE porta_router_dropped_packets_total counter\n")
	for _, drop := range []struct {
		reason string
		count  uint64
	}{
		{"queue_oldest", m.queueOldestDrops.Load()},
		{"queue_full", m.queueFullDrops.Load()},
		{"session_closed", m.closedSessionDrops.Load()},
		{"invalid_tun_packet", m.invalidTUNDrops.Load()},
		{"no_session", m.noSessionDrops.Load()},
	} {
		_, _ = fmt.Fprintf(w, "porta_router_dropped_packets_total{reason=%q} %d\n", drop.reason, drop.count)
	}
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
