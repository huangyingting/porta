package forwardproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/abuse"
	"github.com/huangyingting/porta/internal/clientip"
	"github.com/huangyingting/porta/internal/usage"
)

const (
	defaultMaxConnections = 128
	tunnelIdleTimeout     = 5 * time.Minute
	copyBufferSize        = 64 << 10
	responseBufferSize    = 128 << 10
	responseFlushInterval = 2 * time.Millisecond
	destinationTimeout    = 10 * time.Second
	dnsCacheTTL           = 30 * time.Second
	dnsCacheEntries       = 256
	happyEyeballsDelay    = 250 * time.Millisecond
	DeviceID              = "forward-proxy"
)

var errDestinationDenied = errors.New("proxy destination denied")
var idleDeadlineClockStart = time.Now()
var copyBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, copyBufferSize)
		return &buffer
	},
}

type Identity struct {
	AccountID string
	DeviceID  string
}

type AuthorizeSessionFunc func(context.Context, string, string) (Identity, context.Context, func(), error)

type Config struct {
	Next              http.Handler
	AuthorizeSession  AuthorizeSessionFunc
	Logger            *slog.Logger
	Camouflage        bool
	MaxConnections    int
	Usage             *usage.Store
	Abuse             *abuse.Guard
	TrustProxyHeaders bool
}

type Handler struct {
	next              http.Handler
	authorizeSession  AuthorizeSessionFunc
	logger            *slog.Logger
	camouflage        bool
	slots             chan struct{}
	usage             *usage.Store
	dial              func(context.Context, string, string) (net.Conn, error)
	resolve           func(context.Context, string) ([]netip.Addr, error)
	dialAddress       func(context.Context, string, string) (net.Conn, error)
	dnsCache          *addressCache
	now               func() time.Time
	abuse             *abuse.Guard
	trustProxyHeaders bool
}

func New(config Config) (*Handler, error) {
	if config.Next == nil {
		return nil, errors.New("forward proxy fallback handler is required")
	}
	if config.AuthorizeSession == nil {
		return nil, errors.New("forward proxy authorizer is required")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = defaultMaxConnections
	}
	if config.Usage == nil {
		config.Usage, _ = usage.Open("", config.Logger)
	}
	handler := &Handler{
		next:              config.Next,
		authorizeSession:  config.AuthorizeSession,
		logger:            config.Logger,
		camouflage:        config.Camouflage,
		slots:             make(chan struct{}, config.MaxConnections),
		usage:             config.Usage,
		resolve:           resolveHost,
		dnsCache:          newAddressCache(dnsCacheEntries, dnsCacheTTL),
		now:               time.Now,
		abuse:             config.Abuse,
		trustProxyHeaders: config.TrustProxyHeaders,
	}
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	handler.dialAddress = dialer.DialContext
	handler.dial = handler.dialPublic
	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect && !r.URL.IsAbs() {
		h.next.ServeHTTP(w, r)
		return
	}
	if requestTargetsProxy(r) {
		h.next.ServeHTTP(w, r)
		return
	}
	refund := func() {}
	if h.abuse != nil {
		var allowed bool
		refund, allowed = h.abuse.Reserve(
			abuse.ProxyAuthentication,
			clientip.Address(r, h.trustProxyHeaders),
		)
		if !allowed {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "too many proxy authentication attempts", http.StatusTooManyRequests)
			return
		}
	}
	identity, sessionCtx, release, ok := h.authenticateSession(r.Context(), r.Header.Get("Proxy-Authorization"))
	if !ok {
		if h.camouflage && r.Method != http.MethodConnect {
			h.next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Proxy-Authenticate", `Basic realm="Porta"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	refund()
	defer release()
	r = r.WithContext(sessionCtx)
	if r.Method != http.MethodConnect {
		http.Error(w, "HTTPS CONNECT is required", http.StatusForbidden)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "proxy capacity reached", http.StatusServiceUnavailable)
		return
	}

	started := time.Now()
	target := proxyTarget(r)
	h.logger.Info("forward proxy request",
		"account_id", identity.AccountID,
		"device_id", identity.DeviceID,
		"method", r.Method,
		"target", target,
		"remote", clientip.String(r, h.trustProxyHeaders),
	)
	h.serveConnect(w, r, target, identity)
	h.logger.Debug("forward proxy request complete",
		"account_id", identity.AccountID,
		"device_id", identity.DeviceID,
		"method", r.Method,
		"target", target,
		"duration", time.Since(started),
	)
}

func (h *Handler) authenticateSession(parent context.Context, header string) (Identity, context.Context, func(), bool) {
	token, ok := proxyToken(header)
	if !ok {
		return Identity{}, nil, nil, false
	}
	identity, ctx, release, err := h.authorizeSession(parent, token, DeviceID)
	return identity, ctx, release, err == nil
}

func proxyToken(header string) (string, bool) {
	const prefix = "Basic "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", false
	}
	_, token, ok := strings.Cut(string(decoded), ":")
	if !ok || len(token) < 16 || len(token) > 512 {
		return "", false
	}
	return token, true
}

func (h *Handler) serveConnect(w http.ResponseWriter, r *http.Request, target string, identity Identity) {
	if _, _, err := splitTarget(target, ""); err != nil {
		http.Error(w, "invalid proxy target", http.StatusBadRequest)
		return
	}
	upstream, err := h.dial(r.Context(), "tcp", target)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	defer upstream.Close()
	usageSession := h.usage.Begin("", identity.AccountID, identity.DeviceID, "https-connect", "", target)
	defer usageSession.Close()
	upstream = &idleConn{Conn: upstream, timeout: tunnelIdleTimeout}
	upstream = &meteredConn{Conn: upstream, session: usageSession}

	if r.ProtoMajor == 1 {
		h.serveHijackedConnect(r.Context(), w, upstream)
		return
	}
	w.WriteHeader(http.StatusOK)
	clientWriter := newFlushWriter(w, responseBufferSize, responseFlushInterval)
	clientWriter.onFailure = func(error) {
		closeTunnelEndpoints(upstream, r.Body, clientWriter)
	}
	defer clientWriter.Close()
	stop := onSessionCancel(r.Context(), func() {
		closeTunnelEndpoints(upstream, r.Body, clientWriter)
	})
	defer stop()
	if _, err := clientWriter.Write(nil); err != nil {
		return
	}
	copyStreamTunnel(r.Context(), upstream, r.Body, clientWriter)
}

func (h *Handler) serveHijackedConnect(ctx context.Context, w http.ResponseWriter, upstream net.Conn) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT is not supported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	stop := onSessionCancel(ctx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer stop()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	copyStreamTunnel(
		ctx,
		upstream,
		struct {
			io.Reader
			io.Closer
		}{Reader: buffered.Reader, Closer: client},
		&writeTimeoutConn{Conn: client},
	)
}

func onSessionCancel(ctx context.Context, interrupt func()) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		interrupt()
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

func (h *Handler) dialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := splitTarget(address, "")
	if err != nil {
		return nil, err
	}
	if port != "443" {
		return nil, fmt.Errorf("%w: port %s", errDestinationDenied, port)
	}
	dialCtx, cancel := context.WithTimeout(ctx, destinationTimeout)
	defer cancel()
	addresses, ok := h.dnsCache.Get(host, h.now())
	if !ok {
		addresses, err = h.resolve(dialCtx, host)
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			if !publicAddress(address) {
				return nil, fmt.Errorf("%w: %s", errDestinationDenied, address)
			}
		}
		h.dnsCache.Put(host, addresses, h.now())
	}
	if len(addresses) == 0 {
		return nil, errors.New("destination has no addresses")
	}
	return dialHappyEyeballs(dialCtx, h.dialAddress, network, port, addresses, happyEyeballsDelay)
}

func resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address.Unmap()}, nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.Unmap())
	}
	return result, nil
}

func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

func splitTarget(target, defaultPort string) (string, string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil && defaultPort != "" && strings.Contains(err.Error(), "missing port in address") {
		host = target
		port = defaultPort
		err = nil
	}
	if err != nil || strings.TrimSpace(host) == "" {
		return "", "", errors.New("invalid destination authority")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", errors.New("invalid destination port")
	}
	return strings.Trim(host, "[]"), port, nil
}

func proxyTarget(r *http.Request) string {
	if r.Method == http.MethodConnect {
		if r.URL.Host != "" {
			return r.URL.Host
		}
		return r.Host
	}
	return r.URL.Host
}

func requestTargetsProxy(r *http.Request) bool {
	if r.TLS == nil || r.TLS.ServerName == "" {
		return false
	}
	target := proxyTarget(r)
	host, _, err := splitTarget(target, "443")
	if err != nil {
		host = target
	}
	return strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(r.TLS.ServerName, "."))
}

func copyStreamTunnel(ctx context.Context, upstream net.Conn, clientReader io.Reader, clientWriter io.Writer) {
	type result struct {
		direction int
		err       error
	}
	done := make(chan result, 2)
	go func() {
		err := copyTunnelStream(upstream, clientReader)
		if err == nil {
			if closer, ok := upstream.(interface{ CloseWrite() error }); ok {
				err = closer.CloseWrite()
			}
		}
		done <- result{direction: 0, err: err}
	}()
	go func() {
		err := copyTunnelStream(clientWriter, upstream)
		done <- result{direction: 1, err: err}
	}()
	select {
	case <-ctx.Done():
		closeTunnelEndpoints(upstream, clientReader, clientWriter)
		<-done
		<-done
	case completed := <-done:
		if completed.direction == 1 && completed.err == nil {
			closeTunnelInput(upstream, clientReader)
			<-done
			return
		}
		if completed.err != nil {
			closeTunnelEndpoints(upstream, clientReader, clientWriter)
			<-done
			return
		}
		select {
		case <-ctx.Done():
			closeTunnelEndpoints(upstream, clientReader, clientWriter)
		case completed = <-done:
			if completed.err != nil {
				closeTunnelEndpoints(upstream, clientReader, clientWriter)
			}
			return
		}
		<-done
	}
}

func closeTunnelInput(upstream net.Conn, clientReader io.Reader) {
	_ = upstream.Close()
	if closer, ok := clientReader.(io.Closer); ok {
		_ = closer.Close()
	}
}

func copyTunnelStream(destination io.Writer, source io.Reader) error {
	buffer := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(buffer)
	_, err := io.CopyBuffer(destination, source, *buffer)
	if err == nil {
		if flusher, ok := destination.(interface{ Flush() error }); ok {
			err = flusher.Flush()
		}
	}
	return err
}

func closeTunnelEndpoints(upstream net.Conn, clientReader io.Reader, clientWriter io.Writer) {
	// Closing is terminal: an in-flight idle deadline refresh cannot undo it.
	_ = upstream.Close()
	if aborter, ok := clientWriter.(interface{ Abort() error }); ok {
		_ = aborter.Abort()
	} else if closer, ok := clientWriter.(io.Closer); ok {
		_ = closer.Close()
	}
	if closer, ok := clientReader.(io.Closer); ok {
		_ = closer.Close()
	}
}

type flushWriter struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
	buffer     *bufio.Writer
	writeMu    sync.Mutex
	stateMu    sync.Mutex
	closed     bool
	pending    int
	threshold  int
	interval   time.Duration
	timer      *time.Timer
	timerID    uint64
	failOnce   sync.Once
	onFailure  func(error)
}

type idleConn struct {
	net.Conn
	timeout             time.Duration
	nextDeadlineRefresh atomic.Int64
}

type writeTimeoutConn struct {
	net.Conn
}

func (c *writeTimeoutConn) Write(data []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(tunnelIdleTimeout))
	return c.Conn.Write(data)
}

type meteredConn struct {
	net.Conn
	session *usage.Session
}

func (c *meteredConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.session.AddDownloaded(uint64(n), 0)
	}
	return n, err
}

func (c *meteredConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n > 0 {
		c.session.AddUploaded(uint64(n), 0)
	}
	return n, err
}

func (c *meteredConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func (c *idleConn) Read(data []byte) (int, error) {
	c.refreshDeadline()
	return c.Conn.Read(data)
}

func (c *idleConn) Write(data []byte) (int, error) {
	c.refreshDeadline()
	return c.Conn.Write(data)
}

func (c *idleConn) refreshDeadline() {
	refreshInterval := c.timeout / 4
	if refreshInterval <= 0 || refreshInterval > 30*time.Second {
		refreshInterval = 30 * time.Second
	}
	nowTick := time.Since(idleDeadlineClockStart).Nanoseconds()
	nextRefresh := c.nextDeadlineRefresh.Load()
	if nowTick < nextRefresh ||
		!c.nextDeadlineRefresh.CompareAndSwap(nextRefresh, nowTick+refreshInterval.Nanoseconds()) {
		return
	}
	if err := c.Conn.SetDeadline(time.Now().Add(c.timeout + refreshInterval)); err != nil {
		c.nextDeadlineRefresh.Store(0)
	}
}

func (c *idleConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func (w *flushWriter) Write(data []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if w.isClosed() {
		return 0, net.ErrClosed
	}
	if len(data) == 0 {
		return 0, w.flushLocked()
	}
	if w.buffer == nil {
		w.buffer = bufio.NewWriterSize(w.writer, w.threshold)
	}
	n, err := w.buffer.Write(data)
	w.pending += n
	if err == nil && w.pending >= w.threshold {
		w.stopTimerLocked()
		err = w.flushLocked()
	} else if err == nil && w.pending == n {
		w.startTimerLocked()
	}
	return n, err
}

func (w *flushWriter) Close() error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	w.stopTimerLocked()
	if w.isClosed() {
		return nil
	}
	err := w.flushLocked()
	w.stateMu.Lock()
	w.closed = true
	w.stateMu.Unlock()
	return err
}

func (w *flushWriter) Abort() error {
	w.stateMu.Lock()
	if w.closed {
		w.stateMu.Unlock()
		return nil
	}
	w.closed = true
	w.stateMu.Unlock()
	err := w.controller.SetWriteDeadline(time.Now())
	w.writeMu.Lock()
	w.stopTimerLocked()
	w.writeMu.Unlock()
	return err
}

func (w *flushWriter) Flush() error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	w.stopTimerLocked()
	if w.isClosed() {
		return net.ErrClosed
	}
	return w.flushLocked()
}

func (w *flushWriter) flushLocked() error {
	_ = w.controller.SetWriteDeadline(time.Now().Add(tunnelIdleTimeout))
	var err error
	if w.pending > 0 && w.buffer != nil {
		err = w.buffer.Flush()
	}
	if err == nil {
		if flushErr := w.controller.Flush(); !errors.Is(flushErr, http.ErrNotSupported) {
			err = flushErr
		}
	}
	w.pending = 0
	if !w.isClosed() {
		// Bound only an in-flight write, not a healthy upload-only tunnel.
		_ = w.controller.SetWriteDeadline(time.Time{})
	}
	return err
}

func (w *flushWriter) isClosed() bool {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	return w.closed
}

func (w *flushWriter) startTimerLocked() {
	if w.interval <= 0 || w.timer != nil {
		return
	}
	w.timerID++
	timerID := w.timerID
	w.timer = time.AfterFunc(w.interval, func() {
		w.flushPending(timerID)
	})
}

func (w *flushWriter) stopTimerLocked() {
	w.timerID++
	if w.timer == nil {
		return
	}
	w.timer.Stop()
	w.timer = nil
}

func (w *flushWriter) flushPending(timerID uint64) {
	w.writeMu.Lock()
	if w.timerID != timerID {
		w.writeMu.Unlock()
		return
	}
	w.timer = nil
	w.timerID++
	if w.pending == 0 || w.isClosed() {
		w.writeMu.Unlock()
		return
	}
	err := w.flushLocked()
	w.writeMu.Unlock()
	if err != nil {
		w.failOnce.Do(func() {
			_ = w.Abort()
			if w.onFailure != nil {
				w.onFailure(err)
			}
		})
	}
}

func newFlushWriter(writer http.ResponseWriter, threshold int, interval time.Duration) *flushWriter {
	if threshold <= 0 {
		threshold = responseBufferSize
	}
	return &flushWriter{
		writer:     writer,
		controller: http.NewResponseController(writer),
		threshold:  threshold,
		interval:   interval,
	}
}

func writeProxyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errDestinationDenied) {
		http.Error(w, "proxy destination denied", http.StatusForbidden)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		http.Error(w, "proxy destination timed out", http.StatusGatewayTimeout)
		return
	}
	http.Error(w, "proxy destination unavailable", http.StatusBadGateway)
}

var _ http.Handler = (*Handler)(nil)
