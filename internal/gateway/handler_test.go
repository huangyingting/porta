package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientAddressTrustsProxyHeadersOnlyFromLoopback(t *testing.T) {
	request := httptest.NewRequest("GET", "https://vpn.example.com/healthz", nil)
	request.Header.Set("X-Forwarded-For", "192.0.2.123, 198.51.100.8")

	request.RemoteAddr = "127.0.0.1:1234"
	if got := clientAddress(request, true); got != "198.51.100.8" {
		t.Fatalf("trusted proxy address = %q, want 198.51.100.8", got)
	}

	request.RemoteAddr = "203.0.113.9:1234"
	if got := clientAddress(request, true); got != "203.0.113.9" {
		t.Fatalf("untrusted proxy address = %q, want 203.0.113.9", got)
	}

	request.RemoteAddr = "127.0.0.1:1234"
	if got := clientAddress(request, false); got != "127.0.0.1" {
		t.Fatalf("disabled proxy address = %q, want 127.0.0.1", got)
	}
}

func TestAuthorizedClientPrefersBoundCredential(t *testing.T) {
	config := HandlerConfig{
		Token: "fallback-token-0123456789",
		ClientTokens: map[string]string{
			"android-phone": "device-token-0123456789",
		},
	}
	if !config.authorizedClient("Bearer device-token-0123456789", "android-phone") {
		t.Fatal("bound device token was rejected")
	}
	if config.authorizedClient("Bearer fallback-token-0123456789", "android-phone") {
		t.Fatal("fallback token bypassed a bound device credential")
	}
	if !config.authorizedClient("Bearer fallback-token-0123456789", "unbound-client") {
		t.Fatal("fallback token was rejected for an unbound client")
	}
}

func TestMetricsRequireSeparateCredential(t *testing.T) {
	pool, err := NewPool("10.66.0.0/29")
	if err != nil {
		t.Fatal(err)
	}

	handler, err := NewHandler(HandlerConfig{
		Token:        "client-token-0123456789",
		MetricsToken: "metrics-token-0123456789",
		Pool:         pool,
		Router:       NewRouter(testPacketDevice{}, nil),
		MTU:          1300,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer client-token-0123456789")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("client credential status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	request = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer metrics-token-0123456789")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics credential status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestParseLaneConfig(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, TunnelPath, nil)
	if _, err := parseLaneConfig(request); err == nil {
		t.Fatal("missing lane config accepted")
	}

	request.Header.Set(laneSessionHeader, "session-1234567890")
	request.Header.Set(laneIndexHeader, "2")
	request.Header.Set(laneCountHeader, "4")
	config, err := parseLaneConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	if config.sessionID != "session-1234567890" || config.index != 2 || config.count != 4 {
		t.Fatalf("lane config = %#v", config)
	}

	request.Header.Set(laneIndexHeader, "4")
	if _, err := parseLaneConfig(request); err == nil {
		t.Fatal("out-of-range lane index accepted")
	}

	request.Header.Set(laneIndexHeader, "1")
	request.Header.Set(laneCountHeader, "2")
	if _, err := parseLaneConfig(request); err == nil {
		t.Fatal("non-four-lane configuration accepted")
	}
}

type testPacketDevice struct{}

func (testPacketDevice) ReadPacket(context.Context) ([]byte, error) {
	return nil, errors.New("not used")
}
func (testPacketDevice) WritePacket(context.Context, []byte) error { return nil }
func (testPacketDevice) Name() string                              { return "test0" }
func (testPacketDevice) Close() error                              { return nil }
