package tunnel_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3ReliableBackpressureTerminatesWithoutDowngrade(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificateServer.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	server := &http3.Server{
		TLSConfig: certificateServer.TLS,
		QUICConfig: &quic.Config{
			InitialStreamReceiveWindow: 4096, MaxStreamReceiveWindow: 4096,
			InitialConnectionReceiveWindow: 8192, MaxConnectionReceiveWindow: 8192,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(http3.CapsuleProtocolHeader, "?1")
			w.Header().Set(protocol.HeaderVersion, protocol.Version)
			w.Header().Set("X-Porta-MTU", "9000")
			w.WriteHeader(http.StatusOK)
			stream := w.(http3.HTTPStreamer).HTTPStream()
			if capsule, err := masque.NewDecoder(stream).Read(); err != nil || capsule.Type != masque.CapsuleAddressRequest {
				t.Errorf("address request: %+v %v", capsule, err)
				return
			}
			assignment, err := masque.EncodeAddressAssign([]masque.Address{{RequestID: 1, Prefix: netip.MustParsePrefix("10.66.0.2/32")}})
			if err != nil {
				t.Error(err)
				return
			}
			if err := masque.NewEncoder(stream).Write(masque.CapsuleAddressAssign, assignment); err != nil {
				t.Error(err)
				return
			}
			// Withhold receive credit after assigning the lease.
			<-r.Context().Done()
		}),
	}
	go func() { _ = server.Serve(udp) }()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := tunnel.Dial(ctx, withTestDeviceProof(tunnel.Config{
		URL: "https://" + udp.LocalAddr().String(), Token: testToken, Transport: tunnel.TransportHTTP3,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, Timeout: 300 * time.Millisecond,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	packet := sizedIPv4Packet(conn.Lease.Address.Addr().As4(), [4]byte{8, 8, 8, 8}, 9000)
	started := time.Now()
	for i := 0; i < 32; i++ {
		err = conn.Send(packet)
		if err != nil {
			break
		}
	}
	if err == nil || tunnel.IsTransportUnavailable(err) || !tunnel.IsRetryable(err) ||
		errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
		t.Fatalf("reliable flow-control stall was not bounded/retryable: %v after %s", err, time.Since(started))
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}
