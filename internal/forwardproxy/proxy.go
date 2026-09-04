package forwardproxy

import (
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
	"time"

	"github.com/huangyingting/porta/internal/usage"
)

const (
	defaultMaxConnections = 128
	tunnelIdleTimeout     = 5 * time.Minute
)

var errDestinationDenied = errors.New("proxy destination denied")

type Identity struct {
	AccountID string
	DeviceID  string
}

type AuthorizeFunc func(token, deviceID string) (Identity, error)

type Config struct {
	Next           http.Handler
	Authorize      AuthorizeFunc
	Logger         *slog.Logger
	Camouflage     bool
	MaxConnections int
	Usage          *usage.Store
}

type Handler struct {
	next       http.Handler
	authorize  AuthorizeFunc
	logger     *slog.Logger
	camouflage bool
	slots      chan struct{}
	usage      *usage.Store
	dial       func(context.Context, string, string) (net.Conn, error)
}

func New(config Config) (*Handler, error) {
	if config.Next == nil {
		return nil, errors.New("forward proxy fallback handler is required")
	}
	if config.Authorize == nil {
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
		next:       config.Next,
		authorize:  config.Authorize,
		logger:     config.Logger,
		camouflage: config.Camouflage,
		slots:      make(chan struct{}, config.MaxConnections),
		usage:      config.Usage,
	}
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
	identity, ok := h.authenticate(r.Header.Get("Proxy-Authorization"))
	if !ok {
		if h.camouflage {
			h.next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Proxy-Authenticate", `Basic realm="Porta"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
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
		"remote", remoteHost(r.RemoteAddr),
	)
	h.serveConnect(w, r, target, identity)
	h.logger.Info("forward proxy request complete",
		"account_id", identity.AccountID,
		"device_id", identity.DeviceID,
		"method", r.Method,
		"target", target,
		"duration", time.Since(started),
	)
}

func (h *Handler) authenticate(header string) (Identity, bool) {
	const prefix = "Basic "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return Identity{}, false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return Identity{}, false
	}
	deviceID, token, ok := strings.Cut(string(decoded), ":")
	if !ok || deviceID == "" || token == "" {
		return Identity{}, false
	}
	identity, err := h.authorize(token, deviceID)
	return identity, err == nil
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
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	copyStreamTunnel(r.Context(), upstream, r.Body, flushWriter{writer: w})
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
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	copyStreamTunnel(ctx, upstream, buffered.Reader, client)
}

func (h *Handler) dialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := splitTarget(address, "")
	if err != nil {
		return nil, err
	}
	if port != "443" {
		return nil, fmt.Errorf("%w: port %s", errDestinationDenied, port)
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := resolveHost(resolveCtx, host)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if !publicAddress(address) {
			return nil, fmt.Errorf("%w: %s", errDestinationDenied, address)
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, address := range addresses {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("destination has no addresses")
	}
	return nil, lastErr
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
	done := make(chan int, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		if closer, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		done <- 0
	}()
	go func() {
		_, _ = io.Copy(clientWriter, upstream)
		done <- 1
	}()
	select {
	case <-ctx.Done():
		closeTunnelEndpoints(upstream, clientReader, clientWriter)
		<-done
		<-done
	case direction := <-done:
		if direction == 1 {
			closeTunnelEndpoints(upstream, clientReader, clientWriter)
			<-done
			return
		}
		select {
		case <-ctx.Done():
			closeTunnelEndpoints(upstream, clientReader, clientWriter)
		case <-done:
			return
		}
		<-done
	}
}

func closeTunnelEndpoints(upstream net.Conn, clientReader io.Reader, clientWriter io.Writer) {
	_ = upstream.SetDeadline(time.Now())
	if closer, ok := clientReader.(io.Closer); ok {
		_ = closer.Close()
	}
	if closer, ok := clientWriter.(io.Closer); ok {
		_ = closer.Close()
	}
}

type flushWriter struct {
	writer io.Writer
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

type meteredConn struct {
	net.Conn
	session *usage.Session
	once    sync.Once
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
	_ = c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(data)
}

func (c *idleConn) Write(data []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(data)
}

func (c *idleConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func (w flushWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	if flusher, ok := w.writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
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

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}

var _ http.Handler = (*Handler)(nil)
