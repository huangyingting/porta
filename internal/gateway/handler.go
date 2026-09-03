package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/htun-project/htun/internal/protocol"
)

const TunnelPath = "/v1/tunnel"

const MasquePath = "/.well-known/masque/ip/*/*/"

var validClientID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func ValidClientID(value string) bool {
	return validClientID.MatchString(value)
}

type HandlerConfig struct {
	Token             string
	ClientTokens      map[string]string
	MetricsToken      string
	Metrics           *Metrics
	Pool              *Pool
	Router            *Router
	DNS               string
	MTU               int
	EnableH3Datagrams bool
	TrustProxyHeaders bool
	KeepaliveInterval time.Duration
	Logger            *slog.Logger
}

func NewHandler(config HandlerConfig) (http.Handler, error) {
	if config.Token != "" && len(config.Token) < 16 {
		return nil, errors.New("gateway fallback token must contain at least 16 characters")
	}
	if config.Token == "" && len(config.ClientTokens) == 0 {
		return nil, errors.New("at least one gateway credential is required")
	}
	if config.MetricsToken != "" && len(config.MetricsToken) < 16 {
		return nil, errors.New("metrics token must contain at least 16 characters")
	}
	if config.Metrics == nil {
		config.Metrics = &Metrics{}
	}
	for clientID, token := range config.ClientTokens {
		if !validClientID.MatchString(clientID) {
			return nil, fmt.Errorf("invalid credential client ID %q", clientID)
		}
		if len(token) < 16 {
			return nil, fmt.Errorf("credential token for %q must contain at least 16 characters", clientID)
		}
	}
	if config.Pool == nil || config.Router == nil {
		return nil, errors.New("gateway pool and router are required")
	}
	if config.MTU < 576 || config.MTU > 9000 {
		return nil, fmt.Errorf("MTU %d is outside 576..9000", config.MTU)
	}
	if config.KeepaliveInterval <= 0 {
		config.KeepaliveInterval = 20 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`+"\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ready"}`+"\n")
	})
	if config.MetricsToken != "" {
		mux.Handle("GET /metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !authorized(r.Header.Get("Authorization"), config.MetricsToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="htun-metrics"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			config.Metrics.ServeHTTP(w, r)
		}))
	}
	mux.HandleFunc("POST "+TunnelPath, config.serveTunnel)
	mux.HandleFunc("CONNECT "+MasquePath, config.serveMasque)
	return securityHeaders(mux), nil
}

func (c HandlerConfig) serveTunnel(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor < 2 {
		http.Error(w, "hTun requires HTTP/2 or HTTP/3", http.StatusHTTPVersionNotSupported)
		return
	}
	clientID := r.Header.Get("X-HTun-Client-ID")
	if !validClientID.MatchString(clientID) {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return
	}
	if !c.authorizedClient(r.Header.Get("Authorization"), clientID) {
		c.Metrics.authenticationFailed()
		w.Header().Set("WWW-Authenticate", `Bearer realm="htun"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-HTun-Version") != protocol.Version {
		http.Error(w, "unsupported hTun version", http.StatusUpgradeRequired)
		return
	}
	mediaType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if mediaType != protocol.ContentType {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	lease, err := c.Pool.Acquire(clientID)
	if err != nil {
		http.Error(w, "no tunnel addresses available", http.StatusServiceUnavailable)
		return
	}

	defer c.Pool.Release(lease)

	session, sessionCtx := c.Router.Register(r.Context(), lease.Address)
	defer session.Close()
	c.Metrics.connected()
	defer c.Metrics.disconnected()
	remoteHost := clientAddress(r, c.TrustProxyHeaders)
	c.Logger.Info("tunnel connected", "client_id", clientID, "address", lease.Address, "transport", r.Proto, "remote", remoteHost)
	defer c.Logger.Info("tunnel disconnected", "client_id", clientID, "address", lease.Address)

	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-HTun-Version", protocol.Version)
	w.Header().Set("X-HTun-Address", lease.Prefix().String())
	w.Header().Set("X-HTun-Gateway", lease.Gateway.String())
	w.Header().Set("X-HTun-MTU", strconv.Itoa(c.MTU))
	if c.DNS != "" {
		w.Header().Set("X-HTun-DNS", c.DNS)
	}

	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	inboundDone := make(chan error, 1)
	go func() {
		decoder := protocol.NewDecoder(r.Body)
		for {
			packet, err := decoder.ReadPacket()
			if err != nil {
				inboundDone <- err
				return
			}
			if len(packet) == 0 {
				continue
			}
			if len(packet) > c.MTU {
				inboundDone <- fmt.Errorf("packet length %d exceeds tunnel MTU %d", len(packet), c.MTU)
				return
			}
			if err := c.Router.Inject(sessionCtx, lease.Address, packet); err != nil {
				inboundDone <- err
				return
			}
			c.Metrics.receivedFromClient()
		}
	}()

	encoder := protocol.NewEncoder(w)
	keepalive := time.NewTicker(c.KeepaliveInterval)
	defer keepalive.Stop()
	for {
		select {
		case packet := <-session.Outgoing:
			if err := encoder.WritePacket(packet); err != nil {
				return
			}
			c.Metrics.sentToClient()
			flush(w)
		case <-keepalive.C:
			if err := encoder.WritePacket(nil); err != nil {
				return
			}
			flush(w)
		case err := <-inboundDone:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
				c.Logger.Warn("tunnel receive stopped", "client_id", clientID, "error", err)
			}
			return
		case <-sessionCtx.Done():
			return
		}
	}
}

func (c HandlerConfig) authorizedClient(header, clientID string) bool {
	if token, ok := c.ClientTokens[clientID]; ok {
		return authorized(header, token)
	}
	return c.Token != "" && authorized(header, c.Token)
}

func clientAddress(r *http.Request, trustProxyHeaders bool) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	if !trustProxyHeaders || !net.ParseIP(remoteHost).IsLoopback() {
		return remoteHost
	}
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for index := len(forwarded) - 1; index >= 0; index-- {
		if address := net.ParseIP(strings.TrimSpace(forwarded[index])); address != nil {
			return address.String()
		}
	}
	if address := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); address != nil {
		return address.String()
	}
	return remoteHost
}

func authorized(header, expected string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func flush(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
