package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/huangyingting/porta/internal/protocol"
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
	want := ClientIdentity{AccountID: "account-a", LeaseID: "lease-a"}
	config := HandlerConfig{
		AuthorizeClient: func(token, deviceID string) (ClientIdentity, error) {
			if token == "device-token-0123456789" && deviceID == "android-phone" {
				return want, nil
			}
			return ClientIdentity{}, errors.New("unauthorized")
		},
	}
	identity, err := config.authorizeClient("Bearer device-token-0123456789", "android-phone")
	if err != nil || identity != want {
		t.Fatalf("authorized identity = %#v, %v", identity, err)
	}
	if _, err := config.authorizeClient("Bearer wrong-token-0123456789", "android-phone"); err == nil {
		t.Fatal("invalid token was accepted")
	}
	if _, err := config.authorizeClient("not-bearer", "android-phone"); err == nil {
		t.Fatal("invalid authorization scheme was accepted")
	}
}

func TestMetricsRequireSeparateCredential(t *testing.T) {
	pool, err := NewPool("10.66.0.0/29")
	if err != nil {
		t.Fatal(err)
	}

	handler, err := NewHandler(HandlerConfig{
		AuthorizeClient: func(string, string) (ClientIdentity, error) {
			return ClientIdentity{AccountID: "test", LeaseID: "test"}, nil
		},
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

func TestAdvertisedDNSValidation(t *testing.T) {
	pool, err := NewPool("10.66.0.0/29")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		dns   string
		valid bool
	}{
		{"", true}, {"1.1.1.1", true}, {"10.66.0.1", true},
		{"invalid", false}, {"::1", false}, {"127.0.0.53", false},
		{"169.254.1.1", false}, {"0.0.0.0", false}, {"224.0.0.1", false},
	} {
		_, err := NewHandler(HandlerConfig{
			AuthorizeClient: func(string, string) (ClientIdentity, error) { return ClientIdentity{}, nil },
			Pool:            pool, Router: NewRouter(testPacketDevice{}, nil), MTU: 1100, DNS: test.dns,
		})
		if (err == nil) != test.valid {
			t.Fatalf("DNS %q validity=%t, error=%v", test.dns, test.valid, err)
		}
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

func TestRequireProtocolVersion(t *testing.T) {
	request := httptest.NewRequest(http.MethodConnect, "/", nil)
	recorder := httptest.NewRecorder()
	if requireProtocolVersion(recorder, request) {
		t.Fatal("missing protocol version was accepted")
	}
	if recorder.Code != http.StatusUpgradeRequired {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUpgradeRequired)
	}
	if got := recorder.Header().Get(protocol.HeaderMinVersion); got != protocol.MinVersion {
		t.Fatalf("minimum protocol version = %q, want %q", got, protocol.MinVersion)
	}
	if got := recorder.Header().Get(protocol.HeaderMaxVersion); got != protocol.MaxVersion {
		t.Fatalf("maximum protocol version = %q, want %q", got, protocol.MaxVersion)
	}

	request.Header.Set(protocol.HeaderVersion, protocol.Version)
	recorder = httptest.NewRecorder()
	if !requireProtocolVersion(recorder, request) {
		t.Fatal("current protocol version was rejected")
	}
}

type testPacketDevice struct{}

func (testPacketDevice) ReadPacket(context.Context) ([]byte, error) {
	return nil, errors.New("not used")
}
func (testPacketDevice) WritePacket(context.Context, []byte) error { return nil }
func (testPacketDevice) Name() string                              { return "test0" }
func (testPacketDevice) Close() error                              { return nil }
