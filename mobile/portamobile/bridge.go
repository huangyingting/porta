// Package portamobile exposes the small API surface used by the Android VPN
// service. The tunnel protocol implementation remains in internal/tunnel.
package portamobile

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huangyingting/porta/internal/buildinfo"
	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/tunnel"
)

func Version() string {
	return buildinfo.Version
}

func DeviceID(publicKey []byte) (string, error) {
	return deviceauth.DeviceIDFromEncoded(publicKey)
}

func DeviceProofMessage(token, method, path, deviceID, deviceName, timestamp, nonce string) []byte {
	return deviceauth.Message(deviceauth.Proof{
		DeviceID: deviceID, Name: deviceName, Timestamp: timestamp, Nonce: nonce,
	}, token, method, path)
}

const transportUnavailablePrefix = "transport unavailable: "
const retryablePrefix = "retryable: "

// Protector is implemented by Android to protect the socket from the VPN and
// bind it to the selected underlying network. Prepare returns an empty string
// on success or a classified error message.
type Protector interface {
	Prepare(fd int32) string
}

// ProofProvider signs the requested HTTP method and path after TLS succeeds.
// Proof returns JSON with publicKey, timestamp, nonce, signature and deviceName,
// or returns an error. The key must remain stable throughout a connection.
type ProofProvider interface {
	Proof(method, path string) (string, error)
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
func Dial(serverURL, token, deviceName, publicKey, timestamp, nonce, signature, remoteIP string, protector Protector) (*Session, error) {
	return dial(context.Background(), serverURL, token, deviceName, publicKey, timestamp, nonce, signature, remoteIP, protector)
}

// Dial creates a native session that is canceled when the Dialer is closed.
func (d *Dialer) Dial(serverURL, token, deviceName, publicKey, timestamp, nonce, signature, remoteIP string, protector Protector) (*Session, error) {
	if d == nil || d.ctx == nil {
		return nil, errors.New("configuration: dialer is closed")
	}
	return dial(d.ctx, serverURL, token, deviceName, publicKey, timestamp, nonce, signature, remoteIP, protector)
}

// DialWithPlatform uses Android's trust policy and requests fresh device proofs
// only after the gateway's TLS identity has been verified.
func (d *Dialer) DialWithPlatform(serverURL, token, remoteIP string, protector Protector, verifier CertificateVerifier, provider ProofProvider) (*Session, error) {
	if d == nil || d.ctx == nil {
		return nil, errors.New("configuration: dialer is closed")
	}
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}
	if provider == nil || verifier == nil {
		return nil, errors.New("configuration: platform verifier and proof provider are required")
	}
	return dialWithProof(d.ctx, serverURL, token, remoteIP, protector, verifier, platformProof(provider))
}

func platformProof(provider ProofProvider) func(string, string) (deviceauth.Proof, error) {
	var identity string
	var mu sync.Mutex
	return func(method, path string) (deviceauth.Proof, error) {
		if method != http.MethodConnect || path != gateway.MasquePath {
			return deviceauth.Proof{}, errors.New("unexpected native device proof target")
		}
		encoded, err := provider.Proof(method, path)
		if err != nil {
			return deviceauth.Proof{}, fmt.Errorf("Android device proof: %w", err)
		}
		var value struct {
			PublicKey  string `json:"publicKey"`
			Timestamp  string `json:"timestamp"`
			Nonce      string `json:"nonce"`
			Signature  string `json:"signature"`
			DeviceName string `json:"deviceName"`
		}
		if err := json.Unmarshal([]byte(encoded), &value); err != nil {
			return deviceauth.Proof{}, errors.New("invalid Android device proof")
		}
		key, err := base64.RawURLEncoding.DecodeString(value.PublicKey)
		if err != nil {
			return deviceauth.Proof{}, errors.New("invalid Android device public key")
		}
		deviceID, err := deviceauth.DeviceIDFromEncoded(key)
		if err != nil {
			return deviceauth.Proof{}, err
		}
		mu.Lock()
		defer mu.Unlock()
		if identity != "" && identity != deviceID {
			return deviceauth.Proof{}, errors.New("Android device proof key changed during connection")
		}
		identity = deviceID
		if value.Timestamp == "" || value.Nonce == "" || value.Signature == "" || value.DeviceName == "" {
			return deviceauth.Proof{}, errors.New("incomplete Android device proof")
		}
		return deviceauth.Proof{
			DeviceID: deviceID, Name: value.DeviceName, PublicKey: value.PublicKey,
			Timestamp: value.Timestamp, Nonce: value.Nonce, Signature: value.Signature,
		}, nil
	}
}

// Close cancels a pending Dial call.
func (d *Dialer) Close() {
	if d == nil || d.cancel == nil {
		return
	}
	d.once.Do(d.cancel)
}

func dial(ctx context.Context, serverURL, token, deviceName, publicKey, timestamp, nonce, signature, remoteIP string, protector Protector) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encodedKey, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, errors.New("configuration: device public key is invalid")
	}
	clientID, err := deviceauth.DeviceIDFromEncoded(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("configuration: %w", err)
	}
	proof := deviceauth.Proof{
		DeviceID: clientID, Name: deviceName, PublicKey: publicKey,
		Timestamp: timestamp, Nonce: nonce, Signature: signature,
	}
	return dialWithProof(ctx, serverURL, token, remoteIP, protector, nil, func(method, path string) (deviceauth.Proof, error) {
		if method != http.MethodConnect || path != gateway.MasquePath {
			return deviceauth.Proof{}, errors.New("unexpected native device proof target")
		}
		return proof, nil
	})
}

func dialWithProof(ctx context.Context, serverURL, token, remoteIP string, protector Protector, verifier CertificateVerifier, proof func(string, string) (deviceauth.Proof, error)) (*Session, error) {
	endpoint, address, err := endpointAddress(serverURL, remoteIP)
	if err != nil {
		return nil, err
	}
	if protector == nil {
		return nil, errors.New("configuration: socket protector is required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname()}
	if verifier != nil {
		tlsConfig, err = platformTLSConfig(endpoint.Hostname(), verifier)
		if err != nil {
			return nil, err
		}
	}
	packetConn, err := protectedPacketConn(address.Addr(), protector)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = packetConn.Close()
		return nil, err
	}

	conn, err := tunnel.Dial(ctx, tunnel.Config{
		URL:         endpoint.String(),
		Token:       token,
		DeviceProof: proof,
		Transport:   tunnel.TransportHTTP3,
		TLSConfig:   tlsConfig,
		Timeout:     15 * time.Second,
		PacketConn:  packetConn,
		RemoteAddr:  net.UDPAddrFromAddrPort(address),
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

func (s *Session) AutomaticMTU() bool {
	if s == nil || s.conn == nil {
		return false
	}
	return s.conn.MTUAutomatic
}

func (s *Session) MaximumMTU() int32 {
	if s == nil || s.conn == nil {
		return 0
	}
	return int32(s.conn.MTUCeiling)
}

func (s *Session) PacketDeliveryMode() string {
	if s == nil || s.conn == nil {
		return ""
	}
	return string(s.conn.DeliveryMode)
}

func (s *Session) Send(packet []byte) error {
	if s == nil || s.conn == nil {
		return errors.New("tunnel is closed")
	}
	return classifySessionError(s.conn.Send(packet))
}

func (s *Session) Receive() ([]byte, error) {
	if s == nil || s.conn == nil {
		return nil, errors.New("tunnel is closed")
	}
	packet, err := s.conn.Receive()
	return packet, classifySessionError(err)
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

// IsRetryable reports a transient native failure. Check IsTransportUnavailable
// first to decide whether the attempt may fall back to another protocol.
func IsRetryable(message string) bool {
	return IsTransportUnavailable(message) || strings.HasPrefix(message, retryablePrefix) || message == "tunnel is closed"
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
	ip = ip.Unmap()
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
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
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	if tunnel.IsTransportUnavailable(err) {
		return fmt.Errorf("%s%w", transportUnavailablePrefix, err)
	}
	return classifySessionError(err)
}

func classifySessionError(err error) error {
	if err == nil {
		return err
	}
	var permanent tunnel.PermanentError
	var permanentPointer *tunnel.PermanentError
	canceled := errors.Is(err, context.Canceled) &&
		!errors.As(err, &permanent) && !errors.As(err, &permanentPointer)
	if tunnel.IsRetryable(err) || canceled {
		return fmt.Errorf("%s%w", retryablePrefix, err)
	}
	return err
}
