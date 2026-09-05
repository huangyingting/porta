package portamobile

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/huangyingting/porta/internal/tunnel"
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
	endpoint, address, err := endpointAddress("https://vpn.example.com:8443", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}

	if endpoint.Hostname() != "vpn.example.com" {
		t.Fatalf("hostname = %q", endpoint.Hostname())
	}
	if want := netip.MustParseAddrPort("203.0.113.7:8443"); address != want {
		t.Fatalf("remote = %s, want %s", address, want)
	}
}

func TestEndpointAddressRejectsNonUnicastAddresses(t *testing.T) {
	for _, address := range []string{
		"0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255",
		"::ffff:0.0.0.0", "::ffff:224.0.0.1", "::ffff:255.255.255.255",
	} {
		t.Run(address, func(t *testing.T) {
			if _, _, err := endpointAddress("https://vpn.example.com", address); err == nil {
				t.Fatal("accepted non-unicast remote")
			}
		})
	}
}

func TestEndpointAddressUnmapsIPv4(t *testing.T) {
	_, address, err := endpointAddress("https://vpn.example.com", "::ffff:127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !address.Addr().Is4() {
		t.Fatalf("remote %s would incorrectly require an IPv6 socket", address)
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
	protector := &recordingProtector{}
	_, err := dialer.Dial(
		"https://vpn.example.com:8443",
		"0123456789abcdef",
		"android-test",
		"127.0.0.1",
		protector,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if protector.fd != 0 {
		t.Fatal("closed dialer created and protected a socket")
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
		{"wire protocol mismatch", &tunnel.GatewayResponseError{StatusCode: 426, ServerMinVersion: "3", ServerMaxVersion: "3"}, false, false},
		{"permanent protocol error", tunnel.PermanentError{Err: errors.New("gateway response did not enable the Capsule Protocol")}, false, false},
		{"transport upgrade", &tunnel.GatewayResponseError{StatusCode: 426, Status: "426 Upgrade Required"}, true, false},
		{"server failure", &tunnel.GatewayResponseError{StatusCode: 500, Status: "500 Internal Server Error"}, false, true},
		{"extended connect", errors.New("gateway did not enable HTTP/3 Extended CONNECT"), true, false},
		{"lease failure", errors.New("invalid ADDRESS_ASSIGN"), false, false},
		{"lease timeout", fmt.Errorf("wait for ADDRESS_ASSIGN: %w", context.DeadlineExceeded), false, true},
		{"lease canceled", fmt.Errorf("wait for ADDRESS_ASSIGN: %w", context.Canceled), false, false},
		{"dial canceled", fmt.Errorf("dial QUIC: %w", context.Canceled), false, false},
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

func TestSessionExposesReadOnlyConnectionMetadata(t *testing.T) {
	session := &Session{conn: &tunnel.Conn{
		Lease: tunnel.Lease{
			Address: netip.MustParsePrefix("10.66.0.2/32"),
			DNS:     netip.MustParseAddr("1.1.1.1"),
			MTU:     1360,
		},
		MTUAutomatic: true,
		MTUCeiling:   1400,
		Transport:    tunnel.TransportHTTP3,
		DeliveryMode: tunnel.DeliveryModeDatagram,
	}}

	if !session.AutomaticMTU() {
		t.Fatal("automatic MTU metadata not exposed")
	}
	if got := session.MaximumMTU(); got != 1400 {
		t.Fatalf("maximum MTU = %d", got)
	}
	if got := session.PacketDeliveryMode(); got != "datagram" {
		t.Fatalf("delivery mode = %q", got)
	}
}
