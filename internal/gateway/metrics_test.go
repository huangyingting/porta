package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsRenderPrometheusFormat(t *testing.T) {
	metrics := &Metrics{}
	metrics.connected()
	metrics.authenticationFailed()
	metrics.receivedFromClient()
	metrics.sentToClient()
	metrics.droppedFromClient()
	metrics.DatagramOversize()
	metrics.queueOldestDrops.Add(2)
	metrics.mtuFragmented.Add(3)

	recorder := httptest.NewRecorder()
	metrics.ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body := recorder.Body.String()
	for _, expected := range []string{
		"porta_active_tunnels 1",
		"porta_connections_total 1",
		"porta_auth_failures_total 1",
		"porta_packets_from_client_total 1",
		"porta_packets_to_client_total 1",
		"porta_dropped_packets_from_client_total 1",
		"porta_datagram_oversize_total 1",
		"# HELP porta_datagram_oversize_total Outgoing datagram payload-limit errors requiring capsule fallback.",
		`porta_router_dropped_packets_total{reason="queue_oldest"} 2`,
		`porta_router_dropped_packets_total{reason="queue_full"} 0`,
		`porta_router_dropped_packets_total{reason="session_closed"} 0`,
		`porta_router_dropped_packets_total{reason="invalid_tun_packet"} 0`,
		`porta_router_dropped_packets_total{reason="no_session"} 0`,
		`porta_mtu_packets_total{action="fragmented"} 3`,
		`porta_mtu_packets_total{action="icmp_sent"} 0`,
		`porta_mtu_packets_total{action="icmp_suppressed"} 0`,
		`porta_mtu_packets_total{action="icmp_rate_limited"} 0`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, body)
		}
	}
}
