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
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/usage"
)

const TunnelPath = "/v1/tunnel"

const MasquePath = "/.well-known/masque/ip/*/*/"

var validClientID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var validLaneSessionID = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

const (
	laneSessionHeader = "X-Porta-Lane-Session"
	laneIndexHeader   = "X-Porta-Lane"
	laneCountHeader   = "X-Porta-Lanes"
	tunnelLaneCount   = 4
	streamPacketBatch = 32
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

type AuthorizeSessionFunc func(context.Context, string, string) (ClientIdentity, context.Context, func(), error)

func ValidClientID(value string) bool {
	return validClientID.MatchString(value)
}

type HandlerConfig struct {
	AuthorizeClient   AuthorizeClientFunc
	AuthorizeSession  AuthorizeSessionFunc
	MetricsToken      string
	Metrics           *Metrics
	Usage             *usage.Store
	Pool              *Pool
	Router            *Router
	DNS               string
	MTU               int
	AutoMTU           bool
	EnableH3Datagrams bool
	TrustProxyHeaders bool
	KeepaliveInterval time.Duration
	Logger            *slog.Logger
	Readiness         *Readiness
}

func NewHandler(config HandlerConfig) (http.Handler, error) {
	if config.AuthorizeClient == nil && config.AuthorizeSession == nil {
		return nil, errors.New("gateway client authorizer is required")
	}
	if config.MetricsToken != "" && len(config.MetricsToken) < 16 {
		return nil, errors.New("metrics token must contain at least 16 characters")
	}
	if config.Metrics == nil {
		config.Metrics = &Metrics{}
	}
	if config.Usage == nil {
		config.Usage, _ = usage.Open("", config.Logger)
	}
	if config.Pool == nil || config.Router == nil {
		return nil, errors.New("gateway pool and router are required")
	}
	config.Router.metrics.Store(config.Metrics)
	if config.MTU < 576 || config.MTU > 9000 {
		return nil, fmt.Errorf("MTU %d is outside 576..9000", config.MTU)
	}
	if config.DNS != "" {
		address, err := netip.ParseAddr(config.DNS)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
			return nil, errors.New("advertised DNS must be a unicast IPv4 address, not loopback or link-local")
		}
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
	mux.Handle("GET /readyz", config.Readiness)
	if config.MetricsToken != "" {
		mux.Handle("GET /metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !authorized(r.Header.Get("Authorization"), config.MetricsToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="porta-metrics"`)
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
		http.Error(w, "Porta requires HTTP/2 or HTTP/3", http.StatusHTTPVersionNotSupported)
		return
	}
	clientID := r.Header.Get("X-Porta-Client-ID")
	if !validClientID.MatchString(clientID) {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return
	}
	identity, sessionParent, release, err := c.authorizeSession(r.Context(), r.Header.Get("Authorization"), clientID)
	if err != nil {
		c.Metrics.authenticationFailed()
		w.Header().Set("WWW-Authenticate", `Bearer realm="porta"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	defer release()
	r = r.WithContext(sessionParent)
	if !requireProtocolVersion(w, r) {
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
	stopIO := stopStreamOnCancel(sessionCtx, w, r.Body)
	defer stopIO()
	usageSession := c.Usage.Begin(
		"vpn:"+identity.AccountID+":"+clientID+":"+lanes.sessionID,
		identity.AccountID,
		clientID,
		r.Proto,
		lease.Address.String(),
		"",
	)
	defer usageSession.Close()
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
	setProtocolVersionHeaders(w.Header())
	w.Header().Set("X-Porta-Address", lease.Prefix().String())
	w.Header().Set("X-Porta-Gateway", lease.Gateway.String())
	w.Header().Set("X-Porta-MTU", strconv.Itoa(c.MTU))
	w.Header().Set(laneSessionHeader, lanes.sessionID)
	w.Header().Set(laneIndexHeader, strconv.Itoa(lanes.index))
	w.Header().Set(laneCountHeader, strconv.Itoa(lanes.count))
	if c.DNS != "" {
		w.Header().Set("X-Porta-DNS", c.DNS)
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
	inboundFinished := make(chan struct{})
	defer func() {
		session.Close()
		_ = r.Body.Close()
		<-inboundFinished
	}()
	go func() {
		defer close(inboundFinished)
		decoder := protocol.NewDecoder(r.Body)
		packetBuffer := make([]byte, c.MTU)
		for {
			packet, err := decoder.ReadPacketInto(packetBuffer)
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
			if err := c.Router.injectValidated(sessionCtx, packet); err != nil {
				inboundDone <- err
				return
			}
			c.Metrics.receivedFromClient()
			usageSession.AddUploaded(uint64(len(packet)), 1)
		}
	}()

	keepalive := time.NewTicker(c.KeepaliveInterval)
	defer keepalive.Stop()
	for {
		select {
		case packet := <-session.Outgoing:
		drain:
			for count := 0; ; count++ {
				if err := encoder.WritePacket(packet); err != nil {
					return
				}
				c.Metrics.sentToClient()
				usageSession.AddDownloaded(uint64(len(packet)), 1)
				if count+1 >= streamPacketBatch {
					break
				}
				select {
				case packet = <-session.Outgoing:
				default:
					break drain
				}
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

func requireProtocolVersion(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get(protocol.HeaderVersion) == protocol.Version {
		return true
	}
	setProtocolVersionHeaders(w.Header())
	http.Error(w, "unsupported Porta protocol version", http.StatusUpgradeRequired)
	return false
}

func setProtocolVersionHeaders(header http.Header) {
	header.Set(protocol.HeaderVersion, protocol.Version)
	header.Set(protocol.HeaderMinVersion, protocol.MinVersion)
	header.Set(protocol.HeaderMaxVersion, protocol.MaxVersion)
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
	token, err := bearerToken(header)
	if err != nil {
		return ClientIdentity{}, err
	}
	return c.AuthorizeClient(token, deviceID)
}

func (c HandlerConfig) authorizeSession(parent context.Context, header, deviceID string) (ClientIdentity, context.Context, func(), error) {
	token, err := bearerToken(header)
	if err != nil {
		return ClientIdentity{}, nil, nil, err
	}
	if c.AuthorizeSession != nil {
		return c.AuthorizeSession(parent, token, deviceID)
	}
	identity, err := c.AuthorizeClient(token, deviceID)
	return identity, parent, func() {}, err
}

func bearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("missing bearer token")
	}
	token := strings.TrimPrefix(header, prefix)
	if len(token) < 16 {
		return "", errors.New("invalid bearer token")
	}
	return token, nil
}

func stopStreamOnCancel(ctx context.Context, w http.ResponseWriter, body io.Closer) func() {
	return onSessionCancel(ctx, func() {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now())
		_ = body.Close()
	})
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
