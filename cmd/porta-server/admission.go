package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/gateway"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const (
	maxPublicTCPConnections            = 4096
	maxPublicTCPConnectionsPerSource   = 256
	maxPublicQUICConnections           = 4096
	maxPublicQUICConnectionsPerSource  = 256
	maxPublicUnverifiedQUICConnections = 512
	quicUnverifiedRetryThreshold       = 384
	quicRetryRate                      = 500
	quicRetryBurst                     = 1000
	quicUnvalidatedBurstPerSource      = 8
	quicRetrySourceShards              = 4096
)

type tcpAdmissionListener struct {
	net.Listener
	metrics      *gateway.Metrics
	maxGlobal    int
	maxPerSource int
	mu           sync.Mutex
	active       int
	bySource     map[netip.Addr]int
}

func newTCPAdmissionListener(listener net.Listener, metrics *gateway.Metrics) *tcpAdmissionListener {
	return &tcpAdmissionListener{
		Listener:     listener,
		metrics:      metrics,
		maxGlobal:    maxPublicTCPConnections,
		maxPerSource: maxPublicTCPConnectionsPerSource,
		bySource:     make(map[netip.Addr]int),
	}
}

func (listener *tcpAdmissionListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		release, reason := listener.admit(connection.RemoteAddr())
		if reason == "" {
			if listener.metrics != nil {
				listener.metrics.PublicConnectionOpened("tcp")
			}
			return &admittedConn{
				Conn: connection,
				release: func() {
					release()
					if listener.metrics != nil {
						listener.metrics.PublicConnectionClosed("tcp")
					}
				},
			}, nil
		}
		if listener.metrics != nil {
			listener.metrics.PublicConnectionRejected("tcp", reason)
		}
		_ = connection.Close()
	}
}

func (listener *tcpAdmissionListener) admit(remote net.Addr) (func(), string) {
	address := networkAddress(remote)
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.active >= listener.maxGlobal {
		return nil, "global"
	}
	if address.IsValid() && listener.maxPerSource > 0 && listener.bySource[address] >= listener.maxPerSource {
		return nil, "source"
	}
	listener.active++
	if address.IsValid() {
		listener.bySource[address]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			listener.mu.Lock()
			listener.active--
			if address.IsValid() {
				if listener.bySource[address] <= 1 {
					delete(listener.bySource, address)
				} else {
					listener.bySource[address]--
				}
			}
			listener.mu.Unlock()
		})
	}, ""
}

type admittedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *admittedConn) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}

type retryController struct {
	mu                      sync.Mutex
	rate                    float64
	burst                   float64
	tokens                  float64
	updated                 time.Time
	sourceBurst             float64
	sources                 [quicRetrySourceShards]retryBucket
	underUnverifiedPressure func() bool
	now                     func() time.Time
	metrics                 *gateway.Metrics
}

type retryBucket struct {
	tokens  float64
	updated time.Time
}

func newRetryController(metrics *gateway.Metrics) *retryController {
	now := time.Now()
	return &retryController{
		rate:        quicRetryRate,
		burst:       quicRetryBurst,
		tokens:      quicRetryBurst,
		updated:     now,
		sourceBurst: quicUnvalidatedBurstPerSource,
		now:         time.Now,
		metrics:     metrics,
	}
}

func (controller *retryController) ShouldRetry(remote net.Addr) bool {
	if controller.underUnverifiedPressure != nil && controller.underUnverifiedPressure() {
		if controller.metrics != nil {
			controller.metrics.QUICRetry()
		}
		return true
	}
	now := controller.now()
	controller.mu.Lock()
	refillRetryTokens(&controller.tokens, &controller.updated, controller.rate, controller.burst, now)
	globalAllowed := controller.tokens >= 1
	if globalAllowed {
		controller.tokens--
	}
	sourceAllowed := true
	if address := networkAddress(remote); address.IsValid() && controller.sourceBurst > 0 {
		bucket := &controller.sources[networkAddressShard(address)]
		refillRetryTokens(&bucket.tokens, &bucket.updated, 0, controller.sourceBurst, now)
		sourceAllowed = bucket.tokens >= 1
		if sourceAllowed {
			bucket.tokens--
		}
	}
	retry := !globalAllowed || !sourceAllowed
	controller.mu.Unlock()
	if retry && controller.metrics != nil {
		controller.metrics.QUICRetry()
	}
	return retry
}

func refillRetryTokens(tokens *float64, updated *time.Time, rate, burst float64, now time.Time) {
	if updated.IsZero() {
		*tokens = burst
		*updated = now
		return
	}
	if now.After(*updated) {
		*tokens = min(burst, *tokens+now.Sub(*updated).Seconds()*rate)
		*updated = now
	}
}

type quicAdmission struct {
	maxGlobal      int64
	maxPerSource   int
	maxUnverified  int64
	retryThreshold int64
	active         atomic.Int64
	unverified     atomic.Int64
	metrics        *gateway.Metrics
	mu             sync.Mutex
	bySource       map[netip.Addr]int
}

func (admission *quicAdmission) ConnContext(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if admission.active.Add(1) > admission.maxGlobal {
		admission.active.Add(-1)
		if admission.metrics != nil {
			admission.metrics.PublicConnectionRejected("quic", "global")
		}
		return nil, errors.New("QUIC connection capacity reached")
	}
	var remote net.Addr
	if info != nil {
		remote = info.RemoteAddr
	}
	address := networkAddress(remote)
	verified := info != nil && info.AddrVerified
	if !verified && admission.unverified.Add(1) > admission.maxUnverified {
		admission.unverified.Add(-1)
		admission.active.Add(-1)
		if admission.metrics != nil {
			admission.metrics.PublicConnectionRejected("quic", "unverified")
		}
		return nil, errors.New("unverified QUIC connection capacity reached")
	}
	admission.mu.Lock()
	if verified && address.IsValid() && admission.maxPerSource > 0 &&
		admission.bySource[address] >= admission.maxPerSource {
		admission.mu.Unlock()
		admission.active.Add(-1)
		if admission.metrics != nil {
			admission.metrics.PublicConnectionRejected("quic", "source")
		}
		return nil, errors.New("QUIC source connection capacity reached")
	}
	if verified && address.IsValid() {
		admission.bySource[address]++
	}
	admission.mu.Unlock()
	if admission.metrics != nil {
		admission.metrics.PublicConnectionOpened("quic")
	}
	var once sync.Once
	context.AfterFunc(ctx, func() {
		once.Do(func() {
			admission.active.Add(-1)
			if !verified {
				admission.unverified.Add(-1)
			}
			if verified && address.IsValid() {
				admission.mu.Lock()
				if admission.bySource[address] <= 1 {
					delete(admission.bySource, address)
				} else {
					admission.bySource[address]--
				}
				admission.mu.Unlock()
			}
			if admission.metrics != nil {
				admission.metrics.PublicConnectionClosed("quic")
			}
		})
	})
	return ctx, nil
}

func (admission *quicAdmission) underUnverifiedPressure() bool {
	return admission.unverified.Load() >= admission.retryThreshold
}

type ownedHTTP3Server struct {
	server       *http3.Server
	listener     *quic.EarlyListener
	transport    *quic.Transport
	packet       net.PacketConn
	cleanupOnce  sync.Once
	cleanupError error
}

func newOwnedHTTP3Server(
	address string,
	handler http.Handler,
	tlsConfig *tls.Config,
	metrics *gateway.Metrics,
) (*ownedHTTP3Server, error) {
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	admission := &quicAdmission{
		maxGlobal:      maxPublicQUICConnections,
		maxPerSource:   maxPublicQUICConnectionsPerSource,
		maxUnverified:  maxPublicUnverifiedQUICConnections,
		retryThreshold: quicUnverifiedRetryThreshold,
		metrics:        metrics,
		bySource:       make(map[netip.Addr]int),
	}
	retry := newRetryController(metrics)
	retry.underUnverifiedPressure = admission.underUnverifiedPressure
	transport := &quic.Transport{
		Conn:                packet,
		VerifySourceAddress: retry.ShouldRetry,
		ConnContext:         admission.ConnContext,
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout:           5 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     512 << 10,
		MaxStreamReceiveWindow:         6 << 20,
		InitialConnectionReceiveWindow: 512 << 10,
		MaxConnectionReceiveWindow:     15 << 20,
		MaxIncomingStreams:             128,
		MaxIncomingUniStreams:          8,
		Allow0RTT:                      true,
		EnableDatagrams:                true,
	}
	listener, err := transport.ListenEarly(http3TLSConfig(tlsConfig), quicConfig)
	if err != nil {
		_ = transport.Close()
		_ = packet.Close()
		return nil, err
	}
	return &ownedHTTP3Server{
		server: &http3.Server{
			Addr:            address,
			Handler:         handler,
			EnableDatagrams: true,
			MaxHeaderBytes:  16 << 10,
			IdleTimeout:     90 * time.Second,
		},
		listener:  listener,
		transport: transport,
		packet:    packet,
	}, nil
}

func (server *ownedHTTP3Server) Serve() error {
	return server.server.ServeListener(server.listener)
}

func (server *ownedHTTP3Server) Shutdown(ctx context.Context) error {
	return errors.Join(server.server.Shutdown(ctx), server.cleanup())
}

func (server *ownedHTTP3Server) Close() error {
	return errors.Join(server.server.Close(), server.cleanup())
}

func (server *ownedHTTP3Server) cleanup() error {
	server.cleanupOnce.Do(func() {
		server.cleanupError = errors.Join(
			server.listener.Close(),
			server.transport.Close(),
			server.packet.Close(),
		)
	})
	return server.cleanupError
}

func boundedHTTP2Server() *http2.Server {
	return &http2.Server{
		MaxConcurrentStreams:         128,
		MaxReadFrameSize:             64 << 10,
		MaxUploadBufferPerConnection: 1 << 20,
		MaxUploadBufferPerStream:     1 << 20,
		IdleTimeout:                  90 * time.Second,
		ReadIdleTimeout:              30 * time.Second,
		PingTimeout:                  10 * time.Second,
		WriteByteTimeout:             30 * time.Second,
	}
}

func networkAddress(address net.Addr) netip.Addr {
	if address == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		host = address.String()
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return parsed.Unmap()
}

func networkAddressShard(address netip.Addr) int {
	bytes := address.As16()
	hash := uint32(2166136261)
	for _, value := range bytes {
		hash ^= uint32(value)
		hash *= 16777619
	}
	return int(hash % quicRetrySourceShards)
}
