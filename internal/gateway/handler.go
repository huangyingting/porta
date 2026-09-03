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
var validLaneSessionID = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

const (
	laneSessionHeader = "X-HTun-Lane-Session"
	laneIndexHeader   = "X-HTun-Lane"
	laneCountHeader   = "X-HTun-Lanes"
	tunnelLaneCount   = 4
)

type laneConfig struct {
	sessionID string
	index     int
	count     int
}

type ClientIdentity struct {
	AccountID string
	LeaseID   string
}

type AuthorizeClientFunc func(token, deviceID string) (ClientIdentity, error)

func ValidClientID(value string) bool {
	return validClientID.MatchString(value)
}

type HandlerConfig struct {
	AuthorizeClient   AuthorizeClientFunc
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
	if config.AuthorizeClient == nil {
		return nil, errors.New("gateway client authorizer is required")
	}
	if config.MetricsToken != "" && len(config.MetricsToken) < 16 {
		return nil, errors.New("metrics token must contain at least 16 characters")
	}
	if config.Metrics == nil {
		config.Metrics = &Metrics{}
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
	identity, err := c.authorizeClient(r.Header.Get("Authorization"), clientID)
	if err != nil {
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
	lanes, err := parseLaneConfig(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	lease, err := c.Pool.AcquireGroup(identity.LeaseID, lanes.sessionID)
	if err != nil {
		http.Error(w, "no tunnel addresses available", http.StatusServiceUnavailable)
		return
	}

	defer c.Pool.Release(lease)

	session, sessionCtx, err := c.Router.RegisterGroup(
		r.Context(),
		lease.Address,
		lanes.sessionID,
		lanes.index,
		lanes.count,
	)
	if err != nil {
		http.Error(w, "invalid tunnel lane group", http.StatusConflict)
		return
	}
	defer session.Close()
	c.Metrics.connected()
	defer c.Metrics.disconnected()
	remoteHost := clientAddress(r, c.TrustProxyHeaders)
	logAttributes := []any{
		"client_id", clientID,
		"account_id", identity.AccountID,
		"address", lease.Address,
		"transport", r.Proto,
		"remote", remoteHost,
		"lane", lanes.index,
		"lanes", lanes.count,
	}
	c.Logger.Info("tunnel connected", logAttributes...)
	defer c.Logger.Info("tunnel disconnected", "client_id", clientID, "address", lease.Address)

	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-HTun-Version", protocol.Version)
	w.Header().Set("X-HTun-Address", lease.Prefix().String())
	w.Header().Set("X-HTun-Gateway", lease.Gateway.String())
	w.Header().Set("X-HTun-MTU", strconv.Itoa(c.MTU))
	w.Header().Set(laneSessionHeader, lanes.sessionID)
	w.Header().Set(laneIndexHeader, strconv.Itoa(lanes.index))
	w.Header().Set(laneCountHeader, strconv.Itoa(lanes.count))
	if c.DNS != "" {
		w.Header().Set("X-HTun-DNS", c.DNS)
	}

	w.WriteHeader(http.StatusOK)
	encoder := protocol.NewEncoder(w)
	if err := encoder.WritePacket(nil); err != nil {
		return
	}

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
				c.Metrics.droppedFromClient()
				continue
			}
			info, err := protocol.ParseIPv4(packet)
			if err != nil || info.Source != lease.Address {
				c.Metrics.droppedFromClient()
				continue
			}
			if err := c.Router.Inject(sessionCtx, lease.Address, packet); err != nil {
				inboundDone <- err
				return
			}
			c.Metrics.receivedFromClient()
		}
	}()

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

func parseLaneConfig(r *http.Request) (laneConfig, error) {
	sessionID := strings.TrimSpace(r.Header.Get(laneSessionHeader))
	indexValue := strings.TrimSpace(r.Header.Get(laneIndexHeader))
	countValue := strings.TrimSpace(r.Header.Get(laneCountHeader))
	if !validLaneSessionID.MatchString(sessionID) {
		return laneConfig{}, errors.New("invalid tunnel lane session")
	}
	index, err := strconv.Atoi(indexValue)
	if err != nil {
		return laneConfig{}, errors.New("invalid tunnel lane index")
	}
	count, err := strconv.Atoi(countValue)
	if err != nil || count != tunnelLaneCount || index < 0 || index >= count {
		return laneConfig{}, errors.New("invalid tunnel lane count")
	}
	return laneConfig{sessionID: sessionID, index: index, count: count}, nil
}

func (c HandlerConfig) authorizeClient(header, deviceID string) (ClientIdentity, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ClientIdentity{}, errors.New("missing bearer token")
	}
	token := strings.TrimPrefix(header, prefix)
	if len(token) < 16 {
		return ClientIdentity{}, errors.New("invalid bearer token")
	}
	return c.AuthorizeClient(token, deviceID)
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
