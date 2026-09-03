// Package portamobile exposes the small API surface used by the Android VPN
// service. The tunnel protocol implementation remains in internal/tunnel.
package portamobile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huangyingting/porta/internal/tunnel"
)

const transportUnavailablePrefix = "transport unavailable: "
const retryablePrefix = "retryable: "

// Protector is implemented by Android to protect the socket from the VPN and
// bind it to the selected underlying network. Prepare returns an empty string
// on success or a classified error message.
type Protector interface {
	Prepare(fd int32) string
}

// Session is an active native HTTP/3 CONNECT-IP tunnel.
type Session struct {
	conn       *tunnel.Conn
	packetConn net.PacketConn
	closeOnce  sync.Once
	closeErr   error
}

// Dialer owns cancellation for a pending native connection attempt.
type Dialer struct {
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

// NewDialer creates a cancellable native connection attempt.
func NewDialer() *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Dialer{ctx: ctx, cancel: cancel}
}

// Dial creates and protects a UDP socket before starting QUIC. remoteIP must
// be a numeric address resolved through Android's selected underlying Network.
func Dial(serverURL, token, clientID, remoteIP string, protector Protector) (*Session, error) {
	return dial(context.Background(), serverURL, token, clientID, remoteIP, protector)
}

// Dial creates a native session that is canceled when the Dialer is closed.
func (d *Dialer) Dial(serverURL, token, clientID, remoteIP string, protector Protector) (*Session, error) {
	if d == nil || d.ctx == nil {
		return nil, errors.New("configuration: dialer is closed")
	}
	return dial(d.ctx, serverURL, token, clientID, remoteIP, protector)
}

// Close cancels a pending Dial call.
func (d *Dialer) Close() {
	if d == nil || d.cancel == nil {
		return
	}
	d.once.Do(d.cancel)
}

func dial(ctx context.Context, serverURL, token, clientID, remoteIP string, protector Protector) (*Session, error) {
	endpoint, address, err := endpointAddress(serverURL, remoteIP)
	if err != nil {
		return nil, err
	}
	if protector == nil {
		return nil, errors.New("configuration: socket protector is required")
	}
	packetConn, err := protectedPacketConn(address.Addr(), protector)
	if err != nil {
		return nil, err
	}

	conn, err := tunnel.Dial(ctx, tunnel.Config{
		URL:        endpoint.String(),
		Token:      token,
		ClientID:   clientID,
		Transport:  tunnel.TransportHTTP3,
		TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname()},
		Timeout:    15 * time.Second,
		PacketConn: packetConn,
		RemoteAddr: net.UDPAddrFromAddrPort(address),
	})
	if err != nil {
		_ = packetConn.Close()
		return nil, classifyDialError(err)
	}
	return &Session{conn: conn, packetConn: packetConn}, nil
}

func (s *Session) Address() string {
	if s == nil || s.conn == nil {
		return ""
	}
	return s.conn.Lease.Address.String()
}

func (s *Session) DNS() string {
	if s == nil || s.conn == nil || !s.conn.Lease.DNS.IsValid() {
		return ""
	}
	return s.conn.Lease.DNS.String()
}

func (s *Session) MTU() int32 {
	if s == nil || s.conn == nil {
		return 0
	}
	return int32(s.conn.Lease.MTU)
}

func (s *Session) Send(packet []byte) error {
	if s == nil || s.conn == nil {
		return errors.New("tunnel is closed")
	}
	return s.conn.Send(packet)
}

func (s *Session) Receive() ([]byte, error) {
	if s == nil || s.conn == nil {
		return nil, errors.New("tunnel is closed")
	}
	return s.conn.Receive()
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.conn != nil {
			s.closeErr = s.conn.Close()
		}
		if s.packetConn != nil {
			if err := s.packetConn.Close(); s.closeErr == nil {
				s.closeErr = err
			}
		}
	})
	return s.closeErr
}

// IsTransportUnavailable reports whether Dial failed in a way that permits
// Android to fall back to its multi-lane HTTP/2 transport.
func IsTransportUnavailable(message string) bool {
	return strings.HasPrefix(message, transportUnavailablePrefix)
}

// IsRetryable reports a transient native failure that should be retried
// without falling back to another protocol.
func IsRetryable(message string) bool {
	return strings.HasPrefix(message, retryablePrefix)
}

func endpointAddress(serverURL, remoteIP string) (*url.URL, netip.AddrPort, error) {
	endpoint, err := url.Parse(serverURL)
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("configuration: parse gateway URL: %w", err)
	}
	if endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Hostname() == "" ||
		endpoint.User != nil || (endpoint.Path != "" && endpoint.Path != "/") ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, netip.AddrPort{}, errors.New("configuration: gateway URL must be an HTTPS origin")
	}
	ip, err := netip.ParseAddr(remoteIP)
	if err != nil || ip.IsUnspecified() {
		return nil, netip.AddrPort{}, errors.New("configuration: remote IP must be a numeric unicast address")
	}
	port := uint64(443)
	if endpoint.Port() != "" {
		port, err = strconv.ParseUint(endpoint.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, netip.AddrPort{}, errors.New("configuration: gateway URL has an invalid port")
		}
	}
	return endpoint, netip.AddrPortFrom(ip, uint16(port)), nil
}

func protectedPacketConn(remote netip.Addr, protector Protector) (*net.UDPConn, error) {
	network := "udp4"
	local := netip.IPv4Unspecified()
	if remote.Is6() {
		network = "udp6"
		local = netip.IPv6Unspecified()
	}
	conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		return nil, fmt.Errorf("%screate UDP socket: %w", transportUnavailablePrefix, err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("configuration: access UDP socket: %w", err)
	}
	var prepareError string
	if err := raw.Control(func(fd uintptr) {
		if fd <= uintptr(^uint32(0)>>1) {
			prepareError = protector.Prepare(int32(fd))
		} else {
			prepareError = "configuration: UDP socket descriptor is out of range"
		}
	}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("configuration: protect UDP socket: %w", err)
	}
	if prepareError != "" {
		_ = conn.Close()
		return nil, errors.New(prepareError)
	}
	return conn, nil
}

func classifyDialError(err error) error {
	message := err.Error()
	var responseError *tunnel.GatewayResponseError
	if errors.As(err, &responseError) {
		switch responseError.StatusCode {
		case 404, 405, 421, 426, 501, 505:
			return fmt.Errorf("%s%w", transportUnavailablePrefix, err)
		case 408, 425, 429, 500, 502, 503, 504:
			return fmt.Errorf("%s%w", retryablePrefix, err)
		default:
			return err
		}
	}
	var verificationError *tls.CertificateVerificationError
	if errors.As(err, &verificationError) {
		return err
	}
	var unknownAuthorityError x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var invalidCertificateError x509.CertificateInvalidError
	if errors.As(err, &unknownAuthorityError) ||
		errors.As(err, &hostnameError) ||
		errors.As(err, &invalidCertificateError) {
		return err
	}
	if strings.Contains(message, "ADDRESS_ASSIGN") {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s%w", transportUnavailablePrefix, err)
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return fmt.Errorf("%s%w", transportUnavailablePrefix, err)
	}
	lowerMessage := strings.ToLower(message)
	if strings.Contains(lowerMessage, "certificate") ||
		strings.Contains(lowerMessage, "unknown authority") {
		return err
	}
	if strings.Contains(message, "Extended CONNECT") ||
		strings.Contains(message, "Capsule Protocol") ||
		strings.Contains(message, "dial QUIC") {
		return fmt.Errorf("%s%w", transportUnavailablePrefix, err)
	}
	return err
}
