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
		{"htun_active_tunnels", "gauge", "Current authenticated tunnel connections.", m.activeTunnels.Load()},
		{"htun_connections_total", "counter", "Authenticated tunnel connections accepted.", m.connectionsTotal.Load()},
		{"htun_auth_failures_total", "counter", "Rejected tunnel authentication attempts.", m.authFailures.Load()},
		{"htun_packets_from_client_total", "counter", "IPv4 packets accepted from tunnel clients.", m.packetsFromClient.Load()},
		{"htun_packets_to_client_total", "counter", "IPv4 packets sent to tunnel clients.", m.packetsToClient.Load()},
		{"htun_dropped_packets_from_client_total", "counter", "Invalid or source-mismatched packets dropped from tunnel clients.", m.droppedPacketsFromClient.Load()},
	}
	for _, metric := range metrics {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", metric.name, metric.help, metric.name, metric.kind, metric.name, metric.value)
	}
	_, _ = io.WriteString(w, "\n")
}
