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

	recorder := httptest.NewRecorder()
	metrics.ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body := recorder.Body.String()
	for _, expected := range []string{
		"htun_active_tunnels 1",
		"htun_connections_total 1",
		"htun_auth_failures_total 1",
		"htun_packets_from_client_total 1",
		"htun_packets_to_client_total 1",
		"htun_dropped_packets_from_client_total 1",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, body)
		}
	}
}
