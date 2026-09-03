package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/htun-project/htun/internal/gateway"
	"github.com/htun-project/htun/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type Transport string

type Protocol string

const (
	TransportHTTP2 Transport = "h2"
	TransportHTTP3 Transport = "h3"

	ProtocolMasque Protocol = "masque"
	ProtocolLegacy Protocol = "legacy"
)

type Config struct {
	URL       string
	Token     string
	ClientID  string
	Transport Transport
	Protocol  Protocol
	TLSConfig *tls.Config
	Timeout   time.Duration

	// PacketConn and RemoteAddr allow callers such as Android VPN clients to
	// create and protect the UDP socket before QUIC starts. They must be set
	// together and are only used by HTTP/3 MASQUE. PacketConn remains owned by
	// the caller and is never closed by Conn.
	PacketConn net.PacketConn
	RemoteAddr net.Addr
}

type Lease struct {
	Address netip.Prefix
	Gateway netip.Addr
	DNS     netip.Addr
	MTU     int
}

type Conn struct {
	Lease Lease

	response *http.Response
	request  *io.PipeWriter
	encoder  *protocol.Encoder
	decoder  *protocol.Decoder
	closer   io.Closer
	sendMu   sync.Mutex
	close    sync.Once

	sendPacket    func([]byte) error
	receivePacket func() ([]byte, error)
	closePacket   func() error
}

func Dial(ctx context.Context, config Config) (*Conn, error) {
	if config.Protocol == "" {
		config.Protocol = ProtocolMasque
	}
	switch config.Protocol {
	case ProtocolMasque:
		return dialMasque(ctx, config)
	case ProtocolLegacy:
		return dialLegacy(ctx, config)
	default:
		return nil, fmt.Errorf("unsupported tunnel protocol %q", config.Protocol)
	}
}

func dialLegacy(ctx context.Context, config Config) (*Conn, error) {
	if config.URL == "" || config.Token == "" || config.ClientID == "" {
		return nil, errors.New("URL, token, and client ID are required")
	}
	endpoint, err := tunnelEndpoint(config.URL)
	if err != nil {
		return nil, err
	}
	if config.Transport == "" {
		config.Transport = TransportHTTP3
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}

	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}

	var roundTripper http.RoundTripper
	var closer io.Closer
	switch config.Transport {
	case TransportHTTP2:
		transport := &http2.Transport{
			TLSClientConfig: tlsConfig,
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     10 * time.Second,
		}
		roundTripper, closer = transport, closeIdle{transport}
	case TransportHTTP3:
		transport := &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout: config.Timeout,
				MaxIdleTimeout:       60 * time.Second,
				KeepAlivePeriod:      20 * time.Second,
			},
		}
		roundTripper, closer = transport, transport
	default:
		return nil, fmt.Errorf("unsupported transport %q", config.Transport)
	}

	reader, writer := io.Pipe()
	requestCtx, cancel := context.WithCancel(ctx)
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, reader)
	if err != nil {
		cancel()
		_ = closer.Close()
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+config.Token)
	request.Header.Set("Content-Type", protocol.ContentType)
	request.Header.Set("X-HTun-Version", protocol.Version)
	request.Header.Set("X-HTun-Client-ID", config.ClientID)
	request.ContentLength = -1

	type result struct {
		response *http.Response
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		response, err := roundTripper.RoundTrip(request)
		completed <- result{response: response, err: err}
	}()

	timer := time.NewTimer(config.Timeout)
	defer timer.Stop()
	var response *http.Response
	select {
	case got := <-completed:
		if got.err != nil {
			cancel()
			_ = writer.CloseWithError(got.err)
			_ = closer.Close()
			return nil, fmt.Errorf("open tunnel: %w", got.err)
		}
		response = got.response
	case <-timer.C:
		cancel()
		_ = writer.CloseWithError(context.DeadlineExceeded)
		_ = closer.Close()
		return nil, fmt.Errorf("open tunnel: %w", context.DeadlineExceeded)
	case <-ctx.Done():
		cancel()
		_ = writer.CloseWithError(ctx.Err())
		_ = closer.Close()
		return nil, ctx.Err()
	}

	if response.StatusCode != http.StatusOK {
		status := response.Status
		cancel()
		_ = writer.Close()
		_ = response.Body.Close()
		_ = closer.Close()
		return nil, fmt.Errorf("gateway returned %s", status)
	}
	lease, err := parseLease(response.Header)
	if err != nil {
		cancel()
		_ = writer.CloseWithError(err)
		_ = response.Body.Close()
		_ = closer.Close()
		return nil, err
	}

	return &Conn{
		Lease:    lease,
		response: response,
		request:  writer,
		encoder:  protocol.NewEncoder(writer),
		decoder:  protocol.NewDecoder(response.Body),
		closer: closeGroup{func() error {
			cancel()
			return closer.Close()
		}},
	}, nil
}

func (c *Conn) Send(packet []byte) error {
	if c.sendPacket != nil {
		return c.sendPacket(packet)
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.encoder.WritePacket(packet)
}

func (c *Conn) Receive() ([]byte, error) {
	if c.receivePacket != nil {
		return c.receivePacket()
	}
	for {
		packet, err := c.decoder.ReadPacket()
		if err != nil {
			return nil, err
		}
		if len(packet) != 0 {
			return packet, nil
		}
	}
}

func (c *Conn) Close() error {
	var result error
	c.close.Do(func() {
		if c.closePacket != nil {
			result = c.closePacket()
			return
		}
		_ = c.request.Close()
		_ = c.response.Body.Close()
		result = c.closer.Close()
	})
	return result
}

func parseLease(header http.Header) (Lease, error) {
	address, err := netip.ParsePrefix(header.Get("X-HTun-Address"))
	if err != nil {
		return Lease{}, fmt.Errorf("invalid gateway lease address: %w", err)
	}
	gatewayAddress, err := netip.ParseAddr(header.Get("X-HTun-Gateway"))
	if err != nil {
		return Lease{}, fmt.Errorf("invalid gateway address: %w", err)
	}
	mtu, err := strconv.Atoi(header.Get("X-HTun-MTU"))
	if err != nil || mtu < 576 || mtu > 9000 {
		return Lease{}, fmt.Errorf("invalid gateway MTU %q", header.Get("X-HTun-MTU"))
	}
	var dns netip.Addr
	if value := header.Get("X-HTun-DNS"); value != "" {
		dns, err = netip.ParseAddr(value)
		if err != nil {
			return Lease{}, fmt.Errorf("invalid gateway DNS address: %w", err)
		}
	}
	return Lease{Address: address, Gateway: gatewayAddress, DNS: dns, MTU: mtu}, nil
}

func tunnelEndpoint(origin string) (string, error) {
	parsed, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("parse gateway URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("gateway URL must be an https origin without user information")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("gateway URL must not contain a path, query, or fragment")
	}
	parsed.Path = gateway.TunnelPath
	return parsed.String(), nil
}

type closeIdle struct{ transport *http2.Transport }

func (c closeIdle) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

type closeGroup struct{ close func() error }

func (c closeGroup) Close() error { return c.close() }
