package tunnel_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/certutil"
	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const testToken = "0123456789abcdef0123456789abcdef"
const packetRoundTripTimeout = 10 * time.Second

func TestHTTP2MasquePacketRoundTrip(t *testing.T) {
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		t.Skip("set GODEBUG=http2xconnect=1 to exercise HTTP/2 Extended CONNECT")
	}
	handler, router, dev := testGateway(t, false)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	if err := http2.ConfigureServer(server.Config, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	testPacketRoundTrip(t, router, dev, tunnel.Config{
		URL:       server.URL,
		Token:     testToken,
		ClientID:  "h2-masque-test",
		Transport: tunnel.TransportHTTP2,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // test-only certificate
		Timeout:   3 * time.Second,
	})
}

func TestHTTP3MasqueDatagramPacketRoundTrip(t *testing.T) {
	testHTTP3MasqueRoundTrip(t, true, false)
}

func TestHTTP3MasqueCapsuleFallbackPacketRoundTrip(t *testing.T) {
	testHTTP3MasqueRoundTrip(t, false, false)
}

func TestHTTP3MasqueCallerOwnsPacketConn(t *testing.T) {
	testHTTP3MasqueRoundTrip(t, true, true)
}

func TestHTTP3OversizedPacketsKeepTunnelUsable(t *testing.T) {
	testHTTP3MasqueRoundTrip(t, true, false, 20, 8000, 20)
}

func testHTTP3MasqueRoundTrip(t *testing.T, enableDatagrams, supplyPacketConn bool, packetSizes ...int) {
	t.Helper()
	mtu := 1300
	for _, size := range packetSizes {
		mtu = max(mtu, size)
	}
	handler, router, dev := testGateway(t, enableDatagrams, mtu)
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")
	if err := certutil.Generate(certPath, keyPath, certutil.Options{Hosts: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		Handler:         handler,
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{certificate}},
		EnableDatagrams: enableDatagrams,
	}
	go func() {
		if serveErr := server.Serve(packetConn); serveErr != nil && serveErr.Error() != "http: Server closed" {
			t.Logf("HTTP/3 server stopped: %v", serveErr)
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = packetConn.Close()
	})

	config := tunnel.Config{
		URL:       "https://" + packetConn.LocalAddr().String(),
		Token:     testToken,
		ClientID:  "h3-masque-test",
		Transport: tunnel.TransportHTTP3,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // test-only certificate
		Timeout:   3 * time.Second,
	}
	if !supplyPacketConn {
		_, port, err := net.SplitHostPort(packetConn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		config.URL = "https://vpn.example.invalid:" + port
		config.DialAddress = packetConn.LocalAddr().String()
		config.TLSConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if state.ServerName != "vpn.example.invalid" {
				return fmt.Errorf("pinned QUIC connection lost TLS hostname: %q", state.ServerName)
			}
			return nil
		}
	}
	if supplyPacketConn {
		udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tracked := &trackingPacketConn{PacketConn: udpConn}
		t.Cleanup(func() {
			if tracked.closeCalls != 0 {
				t.Errorf("caller-owned packet connection closed %d times by tunnel", tracked.closeCalls)
			}
			_ = tracked.Close()
		})
		config.PacketConn = tracked
		config.RemoteAddr = packetConn.LocalAddr()
	}
	testPacketRoundTrip(t, router, dev, config, packetSizes...)
}

func testGateway(t *testing.T, enableH3Datagrams bool, configuredMTU ...int) (http.Handler, *gateway.Router, *fakeDevice) {
	t.Helper()
	mtu := 1300
	if len(configuredMTU) > 0 {
		mtu = configuredMTU[0]
	}
	return testMTUGateway(t, enableH3Datagrams, mtu, false)
}

func testMTUGateway(t *testing.T, enableH3Datagrams bool, mtu int, autoMTU bool) (http.Handler, *gateway.Router, *fakeDevice) {
	t.Helper()
	pool, err := gateway.NewPool("10.66.0.0/29")
	if err != nil {
		t.Fatal(err)
	}
	dev := newFakeDevice()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := gateway.NewRouter(dev, logger)
	handler, err := gateway.NewHandler(gateway.HandlerConfig{
		AuthorizeClient: func(token, deviceID string) (gateway.ClientIdentity, error) {
			if token != testToken {
				return gateway.ClientIdentity{}, errors.New("unauthorized")
			}
			return gateway.ClientIdentity{AccountID: "test", LeaseID: "test-" + deviceID}, nil
		},
		Pool:              pool,
		Router:            router,
		DNS:               "1.1.1.1",
		MTU:               mtu,
		AutoMTU:           autoMTU,
		EnableH3Datagrams: enableH3Datagrams,
		KeepaliveInterval: time.Hour,
		Logger:            logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, router, dev
}

// testPacketRoundTrip owns the real context and starts the router only after
// the transport-specific server is listening.
func testPacketRoundTrip(t *testing.T, router *gateway.Router, dev *fakeDevice, config tunnel.Config, packetSizes ...int) tunnel.Transport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if err := router.Run(ctx); err != nil {
			t.Logf("router stopped: %v", err)
		}
	}()

	connection, err := tunnel.Dial(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if connection.RemoteAddr == nil {
		t.Fatal("tunnel did not expose its remote address")
	}

	if len(packetSizes) == 0 {
		packetSizes = []int{20}
	}
	for _, size := range packetSizes {
		clientPacket := sizedIPv4Packet(connection.Lease.Address.Addr().As4(), [4]byte{1, 1, 1, 1}, size)
		if err := connection.Send(clientPacket); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-dev.writes:
			if !bytes.Equal(got, clientPacket) {
				t.Fatalf("gateway TUN got %x, want %x", got, clientPacket)
			}
		case <-time.After(packetRoundTripTimeout):
			t.Fatal("timed out waiting for client-to-gateway packet")
		}

		serverPacket := sizedIPv4Packet([4]byte{8, 8, 8, 8}, connection.Lease.Address.Addr().As4(), size)
		dev.reads <- serverPacket
		received := make(chan []byte, 1)
		errs := make(chan error, 1)
		go func() {
			packet, receiveErr := connection.Receive()
			if receiveErr != nil {
				errs <- receiveErr
				return
			}
			received <- packet
		}()
		select {
		case got := <-received:
			if !bytes.Equal(got, serverPacket) {
				t.Fatalf("client got %x, want %x", got, serverPacket)
			}
		case receiveErr := <-errs:
			t.Fatal(receiveErr)
		case <-time.After(packetRoundTripTimeout):
			t.Fatal("timed out waiting for gateway-to-client packet")
		}
	}
	return connection.Transport
}

func sizedIPv4Packet(source, destination [4]byte, size int) []byte {
	packet := append(ipv4Packet(source, destination), make([]byte, size-20)...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	return packet
}

type fakeDevice struct {
	reads  chan []byte
	writes chan []byte
	closed chan struct{}
}

type trackingPacketConn struct {
	net.PacketConn
	closeCalls int
}

func (c *trackingPacketConn) Close() error {
	c.closeCalls++
	return c.PacketConn.Close()
}

func newFakeDevice() *fakeDevice {
	return &fakeDevice{
		reads:  make(chan []byte, 8),
		writes: make(chan []byte, 8),
		closed: make(chan struct{}),
	}
}

func (f *fakeDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-f.reads:
		return append([]byte(nil), packet...), nil
	case <-f.closed:
		return nil, os.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeDevice) WritePacket(ctx context.Context, packet []byte) error {
	select {
	case f.writes <- append([]byte(nil), packet...):
		return nil
	case <-f.closed:
		return os.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeDevice) Name() string { return "fake0" }

func (f *fakeDevice) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func ipv4Packet(source, destination [4]byte) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = byte(len(packet))
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	return packet
}
