package forwardproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/huangyingting/porta/internal/abuse"
)

const testToken = "proxy-token-0123456789"

func TestPlainHTTPForwardingIsRejected(t *testing.T) {
	handler := newTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	request.Header.Set("Proxy-Authorization", basicProxyAuth("phone", testToken))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("response = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestConnectForwardsBidirectionalTraffic(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		connection, acceptErr := target.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()

	handler := newTestHandler(t)
	dialer := net.Dialer{Timeout: time.Second}
	handler.dial = dialer.DialContext
	server := httptest.NewServer(handler)
	defer server.Close()

	proxyAddress := strings.TrimPrefix(server.URL, "http://")
	connection, err := net.DialTimeout("tcp", proxyAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(connection, "CONNECT "+target.Addr().String()+" HTTP/1.1\r\n"+
		"Host: "+target.Addr().String()+"\r\n"+
		"Proxy-Authorization: "+basicProxyAuth("laptop", testToken)+"\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	if _, err := io.WriteString(connection, "porta"); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("porta"))
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "porta" {
		t.Fatalf("echo = %q", echo)
	}
}

func TestHTTP2ConnectForwardsBidirectionalTraffic(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		connection, acceptErr := target.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()

	handler := newTestHandler(t)
	dialer := net.Dialer{Timeout: time.Second}
	handler.dial = dialer.DialContext
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	requestReader, requestWriter := io.Pipe()
	request, err := http.NewRequest(http.MethodConnect, server.URL, requestReader)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = target.Addr().String()
	request.Header.Set("Proxy-Authorization", basicProxyAuth("tablet", testToken))
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %s %d", response.Proto, response.StatusCode)
	}
	if _, err := io.WriteString(requestWriter, "porta-h2"); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("porta-h2"))
	if _, err := io.ReadFull(response.Body, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "porta-h2" {
		t.Fatalf("echo = %q", echo)
	}
	if err := requestWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("read clean CONNECT response EOF: %v", err)
	}
}

func TestStreamTunnelPreservesReverseHalfClose(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamListener.Close()
	upstreamAccepted := make(chan *net.TCPConn, 1)
	go func() {
		connection, acceptErr := upstreamListener.Accept()
		if acceptErr == nil {
			upstreamAccepted <- connection.(*net.TCPConn)
		}
	}()
	upstream, err := net.DialTimeout("tcp", upstreamListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamPeer := <-upstreamAccepted
	defer upstreamPeer.Close()

	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientListener.Close()
	clientAccepted := make(chan *net.TCPConn, 1)
	go func() {
		connection, acceptErr := clientListener.Accept()
		if acceptErr == nil {
			clientAccepted <- connection.(*net.TCPConn)
		}
	}()
	clientPeer, err := net.DialTimeout("tcp", clientListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientPeer.Close()
	client := <-clientAccepted
	defer client.Close()
	_ = clientPeer.SetDeadline(time.Now().Add(3 * time.Second))
	_ = upstreamPeer.SetDeadline(time.Now().Add(3 * time.Second))
	handler := newTestHandler(t)
	usageSession := handler.usage.Begin("", "account", "device", "test", "", "")
	defer usageSession.Close()
	upstream = &meteredConn{Conn: &idleConn{Conn: upstream, timeout: time.Minute}, session: usageSession}

	finished := make(chan struct{})
	go func() {
		copyStreamTunnel(context.Background(), upstream, client, &writeTimeoutConn{Conn: client})
		close(finished)
	}()

	if _, err := io.WriteString(upstreamPeer, "response"); err != nil {
		t.Fatal(err)
	}
	if err := upstreamPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("response"))
	if _, err := io.ReadFull(clientPeer, response); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(clientPeer, "request-after-half-close"); err != nil {
		t.Fatal(err)
	}
	if err := clientPeer.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(upstreamPeer)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request-after-half-close" {
		t.Fatalf("upstream request = %q", request)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("stream tunnel did not finish after both halves closed")
	}
}

func TestStreamTunnelTerminatesWhenWriterCannotHalfClose(t *testing.T) {
	upstream, upstreamPeer := net.Pipe()
	defer upstream.Close()
	body, bodyWriter := io.Pipe()
	defer bodyWriter.Close()
	writer := newFlushWriter(httptest.NewRecorder(), 128, time.Millisecond)
	finished := make(chan struct{})
	go func() {
		copyStreamTunnel(context.Background(), upstream, body, writer)
		close(finished)
	}()
	if err := upstreamPeer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("writer without CloseWrite left the upload direction blocked")
	}
	if !writer.isClosed() {
		t.Fatal("terminal response writer was not closed")
	}
}

func TestStreamTunnelUpstreamEOFInterruptsBlockedUpload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		upstream := &halfClosedBlockingConn{writing: make(chan struct{}), closed: make(chan struct{})}
		defer upstream.Close()
		handler := newTestHandler(t)
		session := handler.usage.Begin("", "account", "device", "test", "", "")
		defer session.Close()
		wrapped := &meteredConn{Conn: &idleConn{Conn: upstream, timeout: time.Minute}, session: session}
		writer := newFlushWriter(httptest.NewRecorder(), 128, time.Hour)
		defer writer.Close()
		done := make(chan struct{})
		go func() {
			copyStreamTunnel(context.Background(), wrapped, io.NopCloser(strings.NewReader("upload")), writer)
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("upstream EOF left an in-flight upload blocked after closing the HTTP/2 body")
		}
	})
}

type halfClosedBlockingConn struct {
	net.Conn
	writing chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *halfClosedBlockingConn) Read([]byte) (int, error) {
	<-c.writing
	return 0, io.EOF
}

func (c *halfClosedBlockingConn) Write([]byte) (int, error) {
	close(c.writing)
	<-c.closed
	return 0, net.ErrClosed
}

func (c *halfClosedBlockingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (*halfClosedBlockingConn) SetDeadline(time.Time) error { return nil }

func TestCamouflagePassesInvalidProxyRequestsToWebsite(t *testing.T) {
	handler, err := New(Config{
		Next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
		AuthorizeSession: func(ctx context.Context, _, _ string) (Identity, context.Context, func(), error) {
			return Identity{}, ctx, func() {}, context.Canceled
		},
		Camouflage: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTeapot {
		t.Fatalf("camouflage status = %d, want %d", response.Code, http.StatusTeapot)
	}
}

func TestCamouflageChallengesUnauthenticatedConnect(t *testing.T) {
	handler, err := New(Config{
		Next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
		AuthorizeSession: func(ctx context.Context, _, _ string) (Identity, context.Context, func(), error) {
			return Identity{}, ctx, func() {}, context.Canceled
		},
		Camouflage: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	request.Host = "example.com:443"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT status = %d, want %d", response.Code, http.StatusProxyAuthRequired)
	}
	if challenge := response.Header().Get("Proxy-Authenticate"); challenge != `Basic realm="Porta"` {
		t.Fatalf("Proxy-Authenticate = %q", challenge)
	}
}

func TestPublicDestinationPolicy(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1",
		"10.0.0.1",
		"100.64.0.1",
		"169.254.169.254",
		"192.31.196.1",
		"192.52.193.1",
		"192.88.99.1",
		"192.175.48.1",
		"192.0.2.1",
		"::1",
		"64:ff9b::1",
		"64:ff9b:1::1",
		"100::1",
		"2001::1",
		"2001:2::1",
		"2001:10::1",
		"fc00::1",
		"fe80::1",
		"fec0::1",
		"2001:db8::1",
		"2002::1",
		"3fff::1",
		"5f00::1",
	} {
		value := netip.MustParseAddr(address)
		if publicAddress(value) {
			t.Fatalf("%s was accepted as public", address)
		}
	}
	if !publicAddress(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("1.1.1.1 was not accepted as public")
	}
}

func TestIdleConnectionPreservesTCPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer := <-accepted
	defer peer.Close()

	wrapped := &idleConn{Conn: connection, timeout: time.Second}
	if _, err := wrapped.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(peer)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "request" {
		t.Fatalf("half-closed body = %q", body)
	}
}

func TestIdleConnectionThrottlesDeadlineRefreshes(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	counting := &deadlineCountingConn{Conn: client}
	wrapped := &idleConn{Conn: counting, timeout: time.Minute}
	const writes = 100
	received := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, peer, writes)
		received <- err
	}()
	for range writes {
		if _, err := wrapped.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	if calls := counting.deadlineCalls.Load(); calls != 1 {
		t.Fatalf("SetDeadline called %d times for %d writes, want 1", calls, writes)
	}
}

func TestTunnelShutdownCannotBeUndoneByDeadlineRefresh(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	delayed := &delayedDeadlineConn{Conn: client, entered: make(chan struct{}), release: make(chan struct{})}
	wrapped := &idleConn{Conn: delayed, timeout: time.Minute}
	refreshed := make(chan struct{})
	go func() {
		wrapped.refreshDeadline()
		close(refreshed)
	}()
	<-delayed.entered
	closeTunnelEndpoints(wrapped, strings.NewReader(""), io.Discard)
	close(delayed.release)
	<-refreshed
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := peer.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("upstream reopened after shutdown: %v", err)
	}
}

type delayedDeadlineConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (c *delayedDeadlineConn) SetDeadline(deadline time.Time) error {
	if deadline.After(time.Now()) {
		close(c.entered)
		<-c.release
	}
	return c.Conn.SetDeadline(deadline)
}

func TestStreamCancellationUnblocksResponseWrite(t *testing.T) {
	upstream, peer := net.Pipe()
	defer upstream.Close()
	defer peer.Close()
	body, bodyWriter := io.Pipe()
	defer body.Close()
	defer bodyWriter.Close()
	response := &blockedResponseWriter{started: make(chan struct{}), unblocked: make(chan struct{})}
	writer := newFlushWriter(response, 128, time.Millisecond)
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		copyStreamTunnel(ctx, upstream, body, writer)
		close(done)
	}()
	if _, err := peer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	<-response.started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = writer.Abort()
		t.Fatal("stream cancellation left the response writer blocked")
	}
	if _, err := writer.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after cancellation = %v", err)
	}
}

type blockedResponseWriter struct {
	started   chan struct{}
	unblocked chan struct{}
	once      sync.Once
}

func (w *blockedResponseWriter) Header() http.Header { return make(http.Header) }
func (w *blockedResponseWriter) WriteHeader(int)     {}
func (w *blockedResponseWriter) Write([]byte) (int, error) {
	close(w.started)
	<-w.unblocked
	return 0, net.ErrClosed
}
func (w *blockedResponseWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		w.once.Do(func() { close(w.unblocked) })
	}
	return nil
}

func TestUploadFailureClosesBothTunnelDirections(t *testing.T) {
	upstream, peer := net.Pipe()
	defer upstream.Close()
	defer peer.Close()
	done := make(chan struct{})
	go func() {
		copyStreamTunnel(context.Background(), upstream, failingReader{}, io.Discard)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = peer.Close()
		t.Fatal("failed upload left downstream copying blocked")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func BenchmarkIdleDeadlineRefresh(b *testing.B) {
	connection := &idleConn{Conn: &deadlineCountingConn{}, timeout: time.Minute}
	// Avoid an actual network call: the benchmark measures the throttled hot path.
	connection.nextDeadlineRefresh.Store((time.Since(idleDeadlineClockStart) + time.Hour).Nanoseconds())
	b.ReportAllocs()
	for b.Loop() {
		connection.refreshDeadline()
	}
}

type deadlineCountingConn struct {
	net.Conn
	deadlineCalls atomic.Int32
}

func (c *deadlineCountingConn) SetDeadline(deadline time.Time) error {
	c.deadlineCalls.Add(1)
	return c.Conn.SetDeadline(deadline)
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	handler, err := New(Config{
		Next: http.NotFoundHandler(),
		AuthorizeSession: func(ctx context.Context, token, deviceID string) (Identity, context.Context, func(), error) {
			if token != testToken || deviceID != DeviceID {
				return Identity{}, ctx, func() {}, context.Canceled
			}
			return Identity{AccountID: "account", DeviceID: deviceID}, ctx, func() {}, nil
		},
		Camouflage: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestBasicUsernameIsIgnored(t *testing.T) {
	handler := newTestHandler(t)
	for _, username := range []string{"", "phone", "anything is accepted", "invalid/device/name"} {
		identity, _, release, ok := handler.authenticateSession(
			context.Background(),
			basicProxyAuth(username, testToken),
		)
		if !ok || identity.DeviceID != DeviceID {
			t.Fatalf("username %q affected authentication: %+v, %t", username, identity, ok)
		}
		release()
	}
	if _, _, _, ok := handler.authenticateSession(
		context.Background(),
		basicProxyAuth("anything", ""),
	); ok {
		t.Fatal("empty token authenticated")
	}
}

func TestProxyAuthenticationFailuresAreRateLimited(t *testing.T) {
	policies := map[abuse.Surface]abuse.Policy{
		abuse.NativeAuthentication: {Burst: 1, RefillInterval: time.Hour},
		abuse.ProxyAuthentication:  {Burst: 1, RefillInterval: time.Hour},
		abuse.PortalAuthentication: {Burst: 1, RefillInterval: time.Hour},
		abuse.InvitationRedemption: {Burst: 1, RefillInterval: time.Hour},
	}
	guard, err := abuse.New(policies, 16, time.Hour, time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorizerCalls := 0
	handler, err := New(Config{
		Next: http.NotFoundHandler(),
		AuthorizeSession: func(ctx context.Context, _, _ string) (Identity, context.Context, func(), error) {
			authorizerCalls++
			return Identity{}, ctx, func() {}, errors.New("unauthorized")
		},
		Abuse: guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
		r.RemoteAddr = "192.0.2.31:1234"
		r.Header.Set("Proxy-Authorization", basicProxyAuth("ignored", "invalid-token-0123456789"))
		return r
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request())
	if first.Code != http.StatusProxyAuthRequired {
		t.Fatalf("first failure status = %d", first.Code)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request())
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") == "" {
		t.Fatalf("limited failure = %d %v", second.Code, second.Header())
	}
	if authorizerCalls != 1 {
		t.Fatalf("authorizer calls = %d, want 1", authorizerCalls)
	}
}

func basicProxyAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}
