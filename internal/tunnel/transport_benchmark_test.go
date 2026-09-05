package tunnel_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/certutil"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func BenchmarkTransportPacketRoundTrip(b *testing.B) {
	for _, transport := range []tunnel.Transport{tunnel.TransportHTTP2, tunnel.TransportHTTP3} {
		b.Run(string(transport), func(b *testing.B) {
			connection, device := testTransportTunnel(b, transport)
			clientPacket := sizedIPv4Packet(connection.Lease.Address.Addr().As4(), [4]byte{1, 1, 1, 1}, 1200)
			serverPacket := sizedIPv4Packet([4]byte{8, 8, 8, 8}, connection.Lease.Address.Addr().As4(), 1200)
			b.SetBytes(int64(len(clientPacket) + len(serverPacket)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := connection.Send(clientPacket); err != nil {
					b.Fatal(err)
				}
				<-device.writes
				device.reads <- serverPacket
				if _, err := connection.Receive(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestTransportImpairment(t *testing.T) {
	if os.Getenv("PORTA_TRANSPORT_IMPAIRMENT") != "1" {
		t.Skip("set PORTA_TRANSPORT_IMPAIRMENT=1 to run the impairment probe")
	}
	packetCount := impairmentInteger(t, "PORTA_IMPAIRMENT_PACKETS", 200)
	timeout := time.Duration(impairmentInteger(t, "PORTA_IMPAIRMENT_TIMEOUT_SECONDS", 5)) * time.Second
	pacing := time.Duration(impairmentInteger(t, "PORTA_IMPAIRMENT_PACING_MICROS", 500)) * time.Microsecond

	for _, transport := range []tunnel.Transport{tunnel.TransportHTTP2, tunnel.TransportHTTP3} {
		t.Run(string(transport), func(t *testing.T) {
			connection, device := testTransportTunnel(t, transport)
			source := connection.Lease.Address.Addr().As4()
			dataUp := sizedIPv4Packet(source, [4]byte{1, 1, 1, 1}, 1200)
			controlUp := sizedIPv4Packet(source, [4]byte{1, 1, 1, 1}, 64)
			controlUp[9] = 1
			dataDown := sizedIPv4Packet([4]byte{8, 8, 8, 8}, source, 1200)
			controlDown := sizedIPv4Packet([4]byte{8, 8, 8, 8}, source, 64)
			controlDown[9] = 1
			total := packetCount + 1

			uploadCount := make(chan int, 1)
			uploadControl := make(chan time.Duration, 1)
			uploadControlStart := make(chan time.Time, 1)
			downloadCount := make(chan int, 1)
			downloadControl := make(chan time.Duration, 1)
			downloadControlStart := make(chan time.Time, 1)
			stop := make(chan struct{})
			var stopOnce sync.Once
			stopProbe := func() {
				stopOnce.Do(func() {
					close(stop)
					_ = connection.Close()
				})
			}
			defer stopProbe()
			start := time.Now()
			go collectImpairmentUploads(device, total, stop, uploadControlStart, uploadCount, uploadControl)
			go collectImpairmentDownloads(connection, total, downloadControlStart, downloadCount, downloadControl)
			go func() {
				for range packetCount {
					select {
					case device.reads <- dataDown:
					case <-stop:
						return
					}
					if pacing > 0 {
						time.Sleep(pacing)
					}
				}
				downloadControlStart <- time.Now()
				select {
				case device.reads <- controlDown:
				case <-stop:
				}
			}()
			for range packetCount {
				if err := connection.Send(dataUp); err != nil {
					t.Fatal(err)
				}
				if pacing > 0 {
					time.Sleep(pacing)
				}
			}
			uploadControlStart <- time.Now()
			if err := connection.Send(controlUp); err != nil {
				t.Fatal(err)
			}

			deadline := time.NewTimer(timeout)
			defer deadline.Stop()
			up, down := -1, -1
			for up < 0 || down < 0 {
				select {
				case up = <-uploadCount:
				case down = <-downloadCount:
				case <-deadline.C:
					stopProbe()
					if up < 0 {
						up = <-uploadCount
					}
					if down < 0 {
						down = <-downloadCount
					}
				}
			}
			stopProbe()
			t.Logf(
				"transport=%s upload=%d/%d download=%d/%d upload_control=%s download_control=%s elapsed=%s",
				transport,
				up,
				total,
				down,
				total,
				impairmentLatency(uploadControl),
				impairmentLatency(downloadControl),
				time.Since(start).Round(time.Millisecond),
			)
			if up == 0 || down == 0 {
				t.Fatalf("transport %s delivered no packets under impairment", transport)
			}
		})
	}
}

func testTransportTunnel(t testing.TB, transport tunnel.Transport) (*tunnel.Conn, *fakeDevice) {
	t.Helper()
	handler, router, device := testGateway(t, true)
	config := tunnel.Config{
		Token:     testToken,
		Transport: transport,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // test-only certificate
		Timeout:   5 * time.Second,
	}

	switch transport {
	case tunnel.TransportHTTP2:
		server := httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = true
		if err := http2.ConfigureServer(server.Config, &http2.Server{}); err != nil {
			t.Fatal(err)
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		config.URL = server.URL
	case tunnel.TransportHTTP3:
		certPath := filepath.Join(t.TempDir(), "server.crt")
		keyPath := filepath.Join(filepath.Dir(certPath), "server.key")
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
			EnableDatagrams: true,
		}
		go func() { _ = server.Serve(packetConn) }()
		t.Cleanup(func() {
			_ = server.Close()
			_ = packetConn.Close()
		})
		config.URL = "https://" + packetConn.LocalAddr().String()
	default:
		t.Fatalf("unsupported benchmark transport %q", transport)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = router.Run(ctx) }()
	config = withTestDeviceProof(config)
	connection, err := tunnel.Dial(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection, device
}

func collectImpairmentUploads(
	device *fakeDevice,
	total int,
	stop <-chan struct{},
	controlStart <-chan time.Time,
	count chan<- int,
	control chan<- time.Duration,
) {
	delivered := 0
	for delivered < total {
		select {
		case packet := <-device.writes:
			delivered++
			if len(packet) > 9 && packet[9] == 1 {
				control <- time.Since(<-controlStart)
			}
		case <-device.closed:
			count <- delivered
			return
		case <-stop:
			count <- delivered
			return
		}
	}
	count <- delivered
}

func collectImpairmentDownloads(
	connection *tunnel.Conn,
	total int,
	controlStart <-chan time.Time,
	count chan<- int,
	control chan<- time.Duration,
) {
	delivered := 0
	for delivered < total {
		packet, err := connection.Receive()
		if err != nil {
			count <- delivered
			return
		}
		delivered++
		if len(packet) > 9 && packet[9] == 1 {
			control <- time.Since(<-controlStart)
		}
	}
	count <- delivered
}

func impairmentLatency(value <-chan time.Duration) string {
	select {
	case latency := <-value:
		return latency.Round(time.Millisecond).String()
	default:
		return "lost"
	}
}

func impairmentInteger(t *testing.T, name string, fallback int) int {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		t.Fatalf("%s must be a positive integer", name)
	}
	return parsed
}
