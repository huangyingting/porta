package forwardproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/usage"
	"github.com/quic-go/quic-go/http3"
)

func TestSessionCancellationInterruptsLiveConnect(t *testing.T) {
	for _, proto := range []string{"h1", "h2", "h3"} {
		t.Run(proto, func(t *testing.T) {
			store, _ := usage.Open("", nil)
			released := make(chan struct{})
			registered := make(chan context.CancelFunc, 1)
			handler, err := New(Config{
				Next: http.NotFoundHandler(), Usage: store,
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
				AuthorizeSession: func(parent context.Context, _, deviceID string) (Identity, context.Context, func(), error) {
					if deviceID != DeviceID {
						t.Errorf("forward proxy device ID = %q", deviceID)
					}
					ctx, stop := context.WithCancel(parent)
					registered <- stop
					return Identity{AccountID: "account", DeviceID: deviceID}, ctx, func() { stop(); close(released) }, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			upstream, peer := net.Pipe()
			defer peer.Close()
			handler.dial = func(context.Context, string, string) (net.Conn, error) { return upstream, nil }
			go func() { _, _ = io.Copy(peer, peer) }()
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			serverURL := server.URL
			client := server.Client()
			if proto == "h3" {
				packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer packetConn.Close()
				quicServer := &http3.Server{Handler: handler, TLSConfig: server.TLS}
				go func() { _ = quicServer.Serve(packetConn) }()
				defer quicServer.Close()
				transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				defer transport.Close()
				client = &http.Client{Transport: transport}
				serverURL = "https://" + packetConn.LocalAddr().String()
			}
			var reader io.Reader
			var writer io.Writer
			if proto == "h1" {
				connection, err := tls.Dial("tcp", strings.TrimPrefix(serverURL, "https://"), &tls.Config{InsecureSkipVerify: true})
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = io.WriteString(connection, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"+
					"Proxy-Authorization: "+basicProxyAuth("phone", testToken)+"\r\n\r\n")
				if err != nil {
					t.Fatal(err)
				}
				buffered := bufio.NewReader(connection)
				response, err := http.ReadResponse(buffered, &http.Request{Method: http.MethodConnect})
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusOK {
					t.Fatalf("CONNECT status = %d", response.StatusCode)
				}
				reader, writer = buffered, connection
			} else {
				body, requestWriter := io.Pipe()
				defer requestWriter.Close()
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				request, err := http.NewRequestWithContext(ctx, http.MethodConnect, serverURL, body)
				if err != nil {
					t.Fatal(err)
				}
				request.Host = "example.com:443"
				request.Header.Set("Proxy-Authorization", basicProxyAuth("phone", testToken))
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("CONNECT status = %d", response.StatusCode)
				}
				reader, writer = response.Body, requestWriter
			}
			if _, err := io.WriteString(writer, "payload"); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(reader, make([]byte, len("payload"))); err != nil {
				t.Fatal(err)
			}
			(<-registered)()
			select {
			case <-released:
			case <-time.After(time.Second):
				t.Fatal("CONNECT cancellation did not drain handler/copy workers")
			}
			if _, err := reader.Read(make([]byte, 1)); err == nil {
				t.Fatal("client stream survived revocation")
			}
			device := usage.Device(store.Snapshot(), "account", DeviceID)
			if device.ActiveSessions != 0 || device.BytesUploaded != 7 || device.BytesDownloaded != 7 {
				t.Fatalf("usage was not fully drained: %+v", device)
			}
		})
	}
}

func TestSessionCancellationInterruptsPendingDial(t *testing.T) {
	registered := make(chan context.CancelFunc, 1)
	released := make(chan struct{})
	handler, err := New(Config{
		Next: http.NotFoundHandler(),
		AuthorizeSession: func(parent context.Context, _, _ string) (Identity, context.Context, func(), error) {
			ctx, cancel := context.WithCancel(parent)
			registered <- cancel
			return Identity{AccountID: "account"}, ctx, func() { cancel(); close(released) }, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dialing := make(chan struct{})
	handler.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(dialing)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	request := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	request.URL.Host, request.Host = "example.com:443", "example.com:443"
	request.Header.Set("Proxy-Authorization", basicProxyAuth("phone", testToken))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}()
	var cancel context.CancelFunc
	select {
	case cancel = <-registered:
	case <-time.After(time.Second):
		t.Fatal("CONNECT session was not registered")
	}
	select {
	case <-dialing:
	case <-time.After(time.Second):
		t.Fatal("CONNECT did not start dialing")
	}
	cancel()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("pending dial escaped cancellation")
	}
	<-done
}

func TestSessionCancellationInterruptsInitialConnectResponse(t *testing.T) {
	handler := newTestHandler(t)
	upstream, peer := net.Pipe()
	defer peer.Close()
	handler.dial = func(context.Context, string, string) (net.Conn, error) { return upstream, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body, requestWriter := io.Pipe()
	defer requestWriter.Close()
	request := httptest.NewRequest(http.MethodConnect, "http://example.com:443", body).WithContext(ctx)
	request.URL.Host, request.Host = "example.com:443", "example.com:443"
	request.ProtoMajor = 2
	request.Header.Set("Proxy-Authorization", basicProxyAuth("phone", testToken))
	response := &blockedConnectHeaderWriter{&blockedResponseWriter{
		started: make(chan struct{}), unblocked: make(chan struct{}),
	}}
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	<-response.started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("session cancellation did not interrupt initial CONNECT response headers")
		_ = response.SetWriteDeadline(time.Now())
		<-done
	}
}

type blockedConnectHeaderWriter struct{ *blockedResponseWriter }

func (w *blockedConnectHeaderWriter) WriteHeader(int) { _, _ = w.Write(nil) }
