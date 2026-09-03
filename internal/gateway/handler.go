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

type HandlerConfig struct {
	Token             string
	Pool              *Pool
	Router            *Router
	DNS               string
	MTU               int
	EnableH3Datagrams bool
	KeepaliveInterval time.Duration
	Logger            *slog.Logger
}

func NewHandler(config HandlerConfig) (http.Handler, error) {
	if len(config.Token) < 16 {
		return nil, errors.New("gateway token must contain at least 16 characters")
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
	mux.HandleFunc("POST "+TunnelPath, config.serveTunnel)
	mux.HandleFunc("CONNECT "+MasquePath, config.serveMasque)
	return securityHeaders(mux), nil
}

func (c HandlerConfig) serveTunnel(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor < 2 {
		http.Error(w, "hTun requires HTTP/2 or HTTP/3", http.StatusHTTPVersionNotSupported)
		return
	}
	if !authorized(r.Header.Get("Authorization"), c.Token) {
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
	clientID := r.Header.Get("X-HTun-Client-ID")
	if !validClientID.MatchString(clientID) {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
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
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
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
