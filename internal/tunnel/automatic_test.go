package tunnel_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const testToken = "0123456789abcdef0123456789abcdef"

func TestAutomaticTransportFallsBackWithPinnedTLSIdentity(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protocol.ContentType)
		w.Header().Set(protocol.HeaderVersion, protocol.Version)
		w.Header().Set("X-Porta-Address", "10.66.0.2/29")
		w.Header().Set("X-Porta-Gateway", "10.66.0.1")
		w.Header().Set("X-Porta-DNS", "1.1.1.1")
		w.Header().Set("X-Porta-MTU", "1300")
		w.Header().Set("X-Porta-Lane-Session", r.Header.Get("X-Porta-Lane-Session"))
		w.Header().Set("X-Porta-Lane", r.Header.Get("X-Porta-Lane"))
		w.Header().Set("X-Porta-Lanes", r.Header.Get("X-Porta-Lanes"))
		w.WriteHeader(http.StatusOK)
		encoder := protocol.NewEncoder(w)
		if err := encoder.WritePacket(nil); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		decoder := protocol.NewDecoder(r.Body)
		for {
			packet, err := decoder.ReadPacket()
			if err != nil {
				return
			}
			if len(packet) == 0 {
				continue
			}
			reply := append([]byte(nil), packet...)
			copy(reply[12:16], packet[16:20])
			copy(reply[16:20], packet[12:16])
			if err := encoder.WritePacket(reply); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	if err := http2.ConfigureServer(server.Config, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	config := withTestDeviceProof(tunnel.Config{
		URL:         "https://vpn.example.invalid:" + port,
		DialAddress: server.Listener.Addr().String(),
		Token:       testToken,
		Transport:   tunnel.TransportAuto,
		Timeout:     time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // test server certificate; identity assertion below
			VerifyConnection: func(state tls.ConnectionState) error {
				if state.ServerName != "vpn.example.invalid" {
					return fmt.Errorf("pinned TLS connection lost server name: %q", state.ServerName)
				}
				return nil
			},
		},
	})
	connection, err := tunnel.Dial(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if connection.Transport != tunnel.TransportHTTP2 {
		t.Fatalf("automatic transport = %s, want HTTP/2", connection.Transport)
	}
	packet := []byte{
		0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0,
		10, 66, 0, 2, 1, 1, 1, 1,
	}
	if err := connection.Send(packet); err != nil {
		t.Fatal(err)
	}
	received, err := connection.Receive()
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]byte(nil), packet...)
	copy(expected[12:16], packet[16:20])
	copy(expected[16:20], packet[12:16])
	if string(received) != string(expected) {
		t.Fatal("fallback transport changed packet")
	}
}

func TestInvalidPinnedEndpointIsPermanent(t *testing.T) {
	for _, address := range []string{"vpn.example.com:443", "127.0.0.1:0", "0.0.0.0:443", "[ff02::1]:443"} {
		_, err := tunnel.Dial(context.Background(), withTestDeviceProof(tunnel.Config{
			URL: "https://vpn.example.invalid", Token: testToken,
			Transport: tunnel.TransportAuto, DialAddress: address, Timeout: time.Second,
		}))
		if err == nil || tunnel.IsTransportUnavailable(err) || tunnel.IsRetryable(err) {
			t.Fatalf("invalid pinned address %q classified as recoverable: %v", address, err)
		}
	}
}

func TestRejectedHTTP3DoesNotDowngrade(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		header    http.Header
		verifyTLS bool
		waitLease bool
		retryable bool
	}{
		{name: "authentication", status: http.StatusUnauthorized},
		{name: "wire version", status: http.StatusUpgradeRequired, header: http.Header{protocol.HeaderMinVersion: {"99"}, protocol.HeaderMaxVersion: {"99"}}},
		{name: "missing capsule protocol", status: http.StatusOK},
		{name: "certificate", status: http.StatusOK, verifyTLS: true},
		{name: "lease deadline", status: http.StatusOK, header: http.Header{http3.CapsuleProtocolHeader: {"?1"}, protocol.HeaderVersion: {protocol.Version}}, waitLease: true, retryable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var tcpConnections atomic.Int32
			tcpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "unexpected fallback", http.StatusUnauthorized)
			}))
			tcpServer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					tcpConnections.Add(1)
				}
			}
			tcpServer.EnableHTTP2 = true
			if err := http2.ConfigureServer(tcpServer.Config, &http2.Server{}); err != nil {
				t.Fatal(err)
			}
			tcpServer.StartTLS()
			t.Cleanup(tcpServer.Close)
			udp, err := net.ListenPacket("udp", tcpServer.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			server := &http3.Server{
				TLSConfig: tcpServer.TLS.Clone(),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for name, values := range test.header {
						w.Header()[name] = values
					}
					w.WriteHeader(test.status)
					if test.waitLease {
						w.(http.Flusher).Flush()
						<-r.Context().Done()
					}
				}),
			}
			go func() { _ = server.Serve(udp) }()
			t.Cleanup(func() { _ = server.Close(); _ = udp.Close() })
			connection, err := tunnel.Dial(context.Background(), withTestDeviceProof(tunnel.Config{
				URL: tcpServer.URL, Token: testToken, Transport: tunnel.TransportAuto,
				TLSConfig: &tls.Config{InsecureSkipVerify: !test.verifyTLS}, Timeout: 500 * time.Millisecond,
			}))
			if connection != nil {
				_ = connection.Close()
				t.Fatal("rejected session returned a connection")
			}
			if err == nil || tunnel.IsTransportUnavailable(err) || tunnel.IsRetryable(err) != test.retryable {
				t.Fatalf("wrong rejection classification: %v", err)
			}
			if tcpConnections.Load() != 0 {
				t.Fatal("rejected HTTP/3 session downgraded to HTTP/2")
			}
		})
	}
}
