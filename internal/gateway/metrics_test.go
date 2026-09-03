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
		"porta_active_tunnels 1",
		"porta_connections_total 1",
		"porta_auth_failures_total 1",
		"porta_packets_from_client_total 1",
		"porta_packets_to_client_total 1",
		"porta_dropped_packets_from_client_total 1",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, body)
		}
	}
}
