package htunmobile

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/htun-project/htun/internal/tunnel"
)

type recordingProtector struct {
	fd     int32
	result string
}

func (p *recordingProtector) Prepare(fd int32) string {
	p.fd = fd
	return p.result
}

func TestEndpointAddressPreservesHostnameAndUsesNumericRemote(t *testing.T) {
	endpoint, address, err := endpointAddress("https://htun.i-csu.org:8443", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Hostname() != "htun.i-csu.org" {
		t.Fatalf("hostname = %q", endpoint.Hostname())
	}
	if want := netip.MustParseAddrPort("203.0.113.7:8443"); address != want {
		t.Fatalf("remote = %s, want %s", address, want)
	}
}

func TestProtectedPacketConnCallsProtector(t *testing.T) {
	protector := &recordingProtector{}
	conn, err := protectedPacketConn(netip.MustParseAddr("127.0.0.1"), protector)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if protector.fd <= 0 {
		t.Fatalf("protected fd = %d", protector.fd)
	}
}

func TestProtectedPacketConnRejectsFailedProtection(t *testing.T) {
	_, err := protectedPacketConn(
		netip.MustParseAddr("127.0.0.1"),
		&recordingProtector{result: "configuration: Android refused to protect the UDP socket"},
	)
	if err == nil || IsTransportUnavailable(err.Error()) {
		t.Fatalf("error = %v, want permanent protection error", err)
	}
}

func TestDialerCloseCancelsDial(t *testing.T) {
	dialer := NewDialer()
	dialer.Close()
	_, err := dialer.Dial(
		"https://htun.i-csu.org:8443",
		"0123456789abcdef",
		"android-test",
		"127.0.0.1",
		&recordingProtector{},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}

func TestDialErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		fallback bool
		retry    bool
	}{
		{"missing endpoint", &tunnel.GatewayResponseError{StatusCode: 404, Status: "404 Not Found"}, true, false},
		{"authentication", &tunnel.GatewayResponseError{StatusCode: 401, Status: "401 Unauthorized"}, false, false},
		{"server failure", &tunnel.GatewayResponseError{StatusCode: 500, Status: "500 Internal Server Error"}, false, true},
		{"extended connect", errors.New("gateway did not enable HTTP/3 Extended CONNECT"), true, false},
		{"lease failure", errors.New("invalid ADDRESS_ASSIGN"), false, false},
		{"lease timeout", fmt.Errorf("wait for ADDRESS_ASSIGN: %w", context.DeadlineExceeded), false, false},
		{"certificate", fmt.Errorf("dial QUIC: %w", x509.UnknownAuthorityError{}), false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classified := classifyDialError(test.err).Error()
			got := IsTransportUnavailable(classified)
			if got != test.fallback {
				t.Fatalf("fallback = %v, want %v", got, test.fallback)
			}
			if got := IsRetryable(classified); got != test.retry {
				t.Fatalf("retry = %v, want %v", got, test.retry)
			}
		})
	}
}
