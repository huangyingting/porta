package tunnel_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/certutil"
	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func TestHTTP3AutomaticMTUEndToEnd(t *testing.T) {
	for _, test := range []struct {
		name      string
		auto      bool
		datagrams bool
		ceiling   int
		offer     bool
	}{
		{"automatic", true, true, 1500, true},
		{"automatic-default-ceiling", true, true, 1400, true},
		{"fixed", false, true, 1500, false},
		{"capsules", true, false, 1500, false},
		{"conservative-ceiling", true, true, 1100, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, router, dev := testMTUGateway(t, test.datagrams, test.ceiling, test.auto)
			offered := make(chan bool, 1)
			wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r)
				offered <- w.Header().Get(masque.MTUDiscoveryHeader) != ""
			})
			config := startMTUTestHTTP3(t, wrapped, test.datagrams)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			routerDone := make(chan error, 1)
			go func() { routerDone <- router.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				if err := <-routerDone; err != nil {
					t.Error(err)
				}
			})
			connection, err := tunnel.Dial(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close() })
			mtu := connection.Lease.MTU
			if test.offer {
				if mtu < masque.SafeMTU || mtu > masque.MaxDiscoveredMTU {
					t.Fatalf("automatic MTU outside safe range: %d", mtu)
				}
				if !connection.MTUAutomatic {
					t.Fatal("automatic MTU selection was not recorded")
				}
				if connection.MTUCeiling != min(test.ceiling, masque.MaxDiscoveredMTU) {
					t.Fatalf(
						"MTU ceiling = %d, want %d",
						connection.MTUCeiling,
						min(test.ceiling, masque.MaxDiscoveredMTU),
					)
				}
				t.Logf("real HTTP/3 selected MTU %d under ceiling %d", mtu, test.ceiling)
			} else {
				if connection.MTUAutomatic {
					t.Fatal("fixed transport incorrectly reported automatic MTU")
				}
				if connection.MTUCeiling != 0 {
					t.Fatalf("fixed transport reported unexpected MTU ceiling %d", connection.MTUCeiling)
				}
				if mtu != test.ceiling {
					t.Fatalf("fixed transport MTU changed: got %d, want %d", mtu, test.ceiling)
				}
			}
			wantMode := tunnel.DeliveryModeCapsule
			if test.datagrams {
				wantMode = tunnel.DeliveryModeDatagram
			}
			if connection.DeliveryMode != wantMode {
				t.Fatalf("delivery mode = %q, want %q", connection.DeliveryMode, wantMode)
			}
			clientPacket := sizedIPv4Packet(connection.Lease.Address.Addr().As4(), [4]byte{1, 1, 1, 1}, mtu)
			if err := connection.Send(clientPacket); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-dev.writes:
				if !bytes.Equal(got, clientPacket) {
					t.Fatal("selected-MTU upload changed")
				}
			case <-time.After(packetRoundTripTimeout):
				t.Fatal("selected-MTU upload did not reach TUN")
			}
			serverPacket := sizedIPv4Packet([4]byte{8, 8, 8, 8}, connection.Lease.Address.Addr().As4(), test.ceiling)
			serverPacket[8], serverPacket[9] = 64, 17
			setMTUIntegrationChecksum(serverPacket)
			fragments, err := protocol.FragmentIPv4(serverPacket, mtu)
			if err != nil {
				t.Fatal(err)
			}
			dev.reads <- serverPacket
			expected := make(map[uint16][]byte)
			for _, fragment := range fragments {
				expected[binary.BigEndian.Uint16(fragment[6:8])] = fragment
			}
			for range fragments {
				got := receiveMTUPacket(t, connection)
				key := binary.BigEndian.Uint16(got[6:8])
				if !bytes.Equal(got, expected[key]) {
					t.Fatalf("invalid downlink fragment: size=%d flags=%x", len(got), key)
				}
				delete(expected, key)
			}
			if test.offer && len(serverPacket) > mtu {
				dfPacket := bytes.Clone(serverPacket)
				dfPacket[6] = 0x40
				setMTUIntegrationChecksum(dfPacket)
				dev.reads <- dfPacket
				select {
				case reply := <-dev.writes:
					if len(reply) < 56 || reply[20] != 3 || reply[21] != 4 ||
						int(binary.BigEndian.Uint16(reply[26:28])) != mtu || !bytes.Equal(reply[28:], dfPacket[:28]) {
						t.Fatalf("missing/invalid DF feedback: %x", reply)
					}
				case <-time.After(packetRoundTripTimeout):
					t.Fatal("DF packet did not produce ICMP feedback")
				}
			}
			small := sizedIPv4Packet([4]byte{8, 8, 8, 8}, connection.Lease.Address.Addr().As4(), 20)
			dev.reads <- small
			if !bytes.Equal(receiveMTUPacket(t, connection), small) || connection.Lease.MTU != mtu {
				t.Fatal("MTU handling disrupted subsequent packets or resized a live lease")
			}
			_ = connection.Close()
			select {
			case got := <-offered:
				if got != test.offer {
					t.Fatalf("discovery offered=%v, want %v", got, test.offer)
				}
			case <-time.After(packetRoundTripTimeout):
				t.Fatal("server did not finish session")
			}
		})
	}
}

func TestHTTP2AutomaticMTURetainsConfiguredMTU(t *testing.T) {
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		t.Skip("set GODEBUG=http2xconnect=1 to exercise HTTP/2 Extended CONNECT")
	}
	handler, router, dev := testMTUGateway(t, false, 1300, true)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	if err := http2.ConfigureServer(server.Config, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	routerDone := make(chan error, 1)
	go func() { routerDone <- router.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-routerDone; err != nil {
			t.Error(err)
		}
	})
	connection, err := tunnel.Dial(ctx, withTestDeviceProof(tunnel.Config{
		URL: server.URL, Token: testToken, Transport: tunnel.TransportHTTP2,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, Timeout: 3 * time.Second, // test-only certificate
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if connection.Lease.MTU != 1300 {
		t.Fatalf("HTTP/2 MTU = %d, want 1300", connection.Lease.MTU)
	}
	if connection.MTUAutomatic {
		t.Fatal("HTTP/2 incorrectly reported automatic MTU discovery")
	}
	if connection.MTUCeiling != 0 {
		t.Fatalf("HTTP/2 reported unexpected MTU ceiling %d", connection.MTUCeiling)
	}
	if connection.DeliveryMode != tunnel.DeliveryModeCapsule {
		t.Fatalf("HTTP/2 delivery mode = %q, want capsule", connection.DeliveryMode)
	}
	clientPacket := sizedIPv4Packet(connection.Lease.Address.Addr().As4(), [4]byte{1, 1, 1, 1}, connection.Lease.MTU)
	if err := connection.Send(clientPacket); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dev.writes:
		if !bytes.Equal(got, clientPacket) {
			t.Fatal("HTTP/2 upload changed")
		}
	case <-time.After(packetRoundTripTimeout):
		t.Fatal("HTTP/2 upload did not reach TUN")
	}
	serverPacket := sizedIPv4Packet([4]byte{8, 8, 8, 8}, connection.Lease.Address.Addr().As4(), connection.Lease.MTU)
	dev.reads <- serverPacket
	if got := receiveMTUPacket(t, connection); !bytes.Equal(got, serverPacket) {
		t.Fatal("HTTP/2 downlink changed")
	}
}

func startMTUTestHTTP3(t *testing.T, handler http.Handler, datagrams bool) tunnel.Config {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := certutil.Generate(certPath, keyPath, certutil.Options{Hosts: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{Handler: handler, EnableDatagrams: datagrams, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	done := make(chan error, 1)
	go func() { done <- server.Serve(conn) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = conn.Close()
		if err := <-done; err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	})
	return withTestDeviceProof(tunnel.Config{
		URL: "https://" + conn.LocalAddr().String(), Token: testToken, Transport: tunnel.TransportHTTP3,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, Timeout: 3 * time.Second, // test-only certificate
	})
}

func receiveMTUPacket(t *testing.T, connection *tunnel.Conn) []byte {
	t.Helper()
	type result struct {
		packet []byte
		err    error
	}
	received := make(chan result, 1)
	go func() {
		packet, err := connection.Receive()
		received <- result{packet, err}
	}()
	select {
	case got := <-received:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.packet
	case <-time.After(packetRoundTripTimeout):
		t.Fatal("timed out receiving tunnel packet")
		return nil
	}
}

func setMTUIntegrationChecksum(packet []byte) {
	packet[10], packet[11] = 0, 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
}
