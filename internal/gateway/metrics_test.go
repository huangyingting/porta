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
	metrics.PublicConnectionOpened("tcp")
	metrics.PublicConnectionOpened("quic")
	metrics.PublicConnectionClosed("quic")
	metrics.PublicConnectionRejected("tcp", "source")
	metrics.PublicConnectionRejected("quic", "global")
	metrics.PublicConnectionRejected("quic", "source")
	metrics.PublicConnectionRejected("quic", "unverified")
	metrics.QUICRetry()
	metrics.AbuseRejected("portal")
	metrics.receivedFromClient()
	metrics.sentToClient()
	metrics.droppedFromClient()
	metrics.DatagramOversize()
	metrics.queueOldestDrops.Add(2)
	metrics.queueTailDrops.Add(4)
	metrics.queueExpiredDrops.Add(5)
	metrics.adjustQueueBytes(2, 4096)
	metrics.laneCollapsedGroups.Add(1)
	metrics.mtuFragmented.Add(3)

	recorder := httptest.NewRecorder()
	metrics.ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body := recorder.Body.String()
	for _, expected := range []string{
		"porta_active_tunnels 1",
		"porta_connections_total 1",
		"porta_auth_failures_total 1",
		`porta_public_connections{transport="tcp"} 1`,
		`porta_public_connections{transport="quic"} 0`,
		`porta_public_connections_total{transport="quic"} 1`,
		`porta_public_connection_rejections_total{transport="tcp",reason="source"} 1`,
		`porta_public_connection_rejections_total{transport="quic",reason="global"} 1`,
		`porta_public_connection_rejections_total{transport="quic",reason="source"} 1`,
		`porta_public_connection_rejections_total{transport="quic",reason="unverified"} 1`,
		"porta_quic_retries_total 1",
		`porta_abuse_rejections_total{surface="portal"} 1`,
		"porta_packets_from_client_total 1",
		"porta_packets_to_client_total 1",
		"porta_dropped_packets_from_client_total 1",
		"porta_datagram_oversize_total 1",
		"# HELP porta_datagram_oversize_total Outgoing datagram payload-limit errors requiring capsule fallback.",
		`porta_router_dropped_packets_total{reason="queue_oldest"} 2`,
		`porta_router_dropped_packets_total{reason="queue_full"} 0`,
		`porta_router_dropped_packets_total{reason="queue_tail"} 4`,
		`porta_router_dropped_packets_total{reason="queue_expired"} 5`,
		`porta_router_dropped_packets_total{reason="session_closed"} 0`,
		`porta_router_dropped_packets_total{reason="invalid_tun_packet"} 0`,
		`porta_router_dropped_packets_total{reason="no_session"} 0`,
		`porta_router_queue_bytes{lane="2"} 4096`,
		`porta_router_queue_bytes_high_water{lane="2"} 4096`,
		`porta_http2_collapsed_lane_groups_total 1`,
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
