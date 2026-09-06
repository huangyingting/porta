package clientip

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestAddressTrustsForwardingHeadersOnlyFromLoopback(t *testing.T) {
	request := httptest.NewRequest("GET", "https://porta.example/", nil)
	request.Header.Set("X-Forwarded-For", "192.0.2.123, 198.51.100.8")

	request.RemoteAddr = "127.0.0.1:1234"
	if got := Address(request, true); got != netip.MustParseAddr("198.51.100.8") {
		t.Fatalf("trusted proxy address = %s", got)
	}

	request.RemoteAddr = "203.0.113.9:1234"
	if got := Address(request, true); got != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("untrusted proxy address = %s", got)
	}

	request.RemoteAddr = "127.0.0.1:1234"
	if got := Address(request, false); got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("disabled proxy address = %s", got)
	}
}

func TestAddressNormalizesMappedIPv4AndFallsBackToRealIP(t *testing.T) {
	request := httptest.NewRequest("GET", "https://porta.example/", nil)
	request.RemoteAddr = "[::ffff:127.0.0.1]:1234"
	request.Header.Set("X-Forwarded-For", "invalid")
	request.Header.Set("X-Real-IP", "::ffff:192.0.2.44")
	if got := Address(request, true); got != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("normalized address = %s", got)
	}
}
