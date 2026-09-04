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

	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const masqueRequestID uint64 = 1

type masqueClient struct {
	ctx        context.Context
	cancel     context.CancelFunc
	encoder    *masque.Encoder
	decoder    *masque.Decoder
	lease      Lease
	remoteAddr net.Addr
	leaseReady chan netip.Prefix
	packets    chan []byte
	errors     chan error

	sendDatagram    func([]byte) error
	receiveDatagram func(context.Context) ([]byte, error)
	closeTransport  func() error
	closeOnce       sync.Once
}

func dialMasque(ctx context.Context, config Config) (*Conn, error) {
	if config.URL == "" || config.Token == "" || config.ClientID == "" {
		return nil, errors.New("URL, token, and client ID are required")
	}
	if config.Transport == "" {
		config.Transport = TransportHTTP3
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}
	endpoint, err := masqueEndpoint(config.URL)
	if err != nil {
		return nil, err
	}
	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}

	var client *masqueClient
	switch config.Transport {
	case TransportHTTP2:
		client, err = dialMasqueHTTP2(ctx, config, endpoint, tlsConfig)
	case TransportHTTP3:
		client, err = dialMasqueHTTP3(ctx, config, endpoint, tlsConfig)
	default:
		return nil, fmt.Errorf("unsupported transport %q", config.Transport)
	}
	if err != nil {
		return nil, err
	}
	client.start()
	request, err := masque.EncodeAddressRequest([]masque.Address{{
		RequestID: masqueRequestID,
		Prefix:    netip.PrefixFrom(netip.IPv4Unspecified(), 32),
	}})
	if err != nil {
		_ = client.close()
		return nil, err
	}
	if err := client.encoder.Write(masque.CapsuleAddressRequest, request); err != nil {
		_ = client.close()
		return nil, fmt.Errorf("send ADDRESS_REQUEST: %w", err)
	}

	timer := time.NewTimer(config.Timeout)
	defer timer.Stop()
	select {
	case prefix := <-client.leaseReady:
		client.lease.Address = prefix
	case err := <-client.errors:
		_ = client.close()
		return nil, err
	case <-timer.C:
		_ = client.close()
		return nil, fmt.Errorf("wait for ADDRESS_ASSIGN: %w", context.DeadlineExceeded)
	case <-ctx.Done():
		_ = client.close()
		return nil, ctx.Err()
	}

	return &Conn{
		Lease:         client.lease,
		RemoteAddr:    client.remoteAddr,
		sendPacket:    client.send,
		receivePacket: client.receive,
		closePacket:   client.close,
	}, nil
}

func dialMasqueHTTP2(
	parent context.Context,
	config Config,
	endpoint *url.URL,
	tlsConfig *tls.Config,
) (*masqueClient, error) {
	ctx, cancel := context.WithCancel(parent)
	reader, writer := io.Pipe()
	transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     10 * time.Second,
	}
	var remoteAddr net.Addr
	transport.DialTLSContext = func(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
		connection, err := (&tls.Dialer{Config: config}).DialContext(ctx, network, address)
		if err == nil {
			remoteAddr = connection.RemoteAddr()
		}
		return connection, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, endpoint.String(), reader)
	if err != nil {
		cancel()
		return nil, err
	}
	setMasqueHeaders(request, config)
	request.Header.Set(":protocol", "connect-ip")
	request.ContentLength = -1

	response, err := timedRoundTrip(ctx, transport, request, config.Timeout)
	if err != nil {
		cancel()
		_ = writer.CloseWithError(err)
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("open HTTP/2 CONNECT-IP tunnel: %w", err)
	}
	if err := validateMasqueResponse(response); err != nil {
		cancel()
		_ = writer.CloseWithError(err)
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, err
	}

	client := newMasqueClient(ctx, cancel, masque.NewEncoder(writer), masque.NewDecoder(response.Body), response.Header)
	client.remoteAddr = remoteAddr
	client.closeTransport = func() error {
		_ = writer.Close()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil
	}
	return client, nil
}

func dialMasqueHTTP3(
	parent context.Context,
	config Config,
	endpoint *url.URL,
	tlsConfig *tls.Config,
) (*masqueClient, error) {
	ctx, cancel := context.WithCancel(parent)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = endpoint.Hostname()
	}
	quicConfig := &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: config.Timeout,
		MaxIdleTimeout:       60 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
	}
	if (config.PacketConn == nil) != (config.RemoteAddr == nil) {
		cancel()
		return nil, errors.New("packet connection and remote address must be provided together")
	}
	handshakeCtx, stopHandshake := context.WithTimeout(ctx, config.Timeout)
	var (
		connection *quic.Conn
		err        error
	)
	if config.PacketConn != nil {
		connection, err = quic.Dial(handshakeCtx, config.PacketConn, config.RemoteAddr, tlsConfig, quicConfig)
	} else {
		connection, err = quic.DialAddr(handshakeCtx, endpoint.Host, tlsConfig, quicConfig)
	}
	stopHandshake()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("dial QUIC: %w", err)
	}
	transport := &http3.Transport{
		EnableDatagrams:        true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	clientConnection := transport.NewClientConn(connection)
	select {
	case <-clientConnection.ReceivedSettings():
	case <-time.After(config.Timeout):
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "settings timeout")
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "context canceled")
		return nil, ctx.Err()
	}
	settings := clientConnection.Settings()
	if !settings.EnableExtendedConnect {
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeSettingsError), "extended CONNECT unavailable")
		return nil, errors.New("gateway did not enable HTTP/3 Extended CONNECT")
	}
	stream, err := clientConnection.OpenRequestStream(ctx)
	if err != nil {
		cancel()
		_ = clientConnection.CloseWithError(0, "")
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    endpoint,
		Host:   endpoint.Host,
		Proto:  "connect-ip",
		Header: make(http.Header),
	}
	setMasqueHeaders(request, config)
	if err := stream.SendRequestHeader(request); err != nil {
		cancel()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = clientConnection.CloseWithError(0, "")
		return nil, err
	}
	type responseResult struct {
		response *http.Response
		err      error
	}
	responseReady := make(chan responseResult, 1)
	go func() {
		response, readErr := stream.ReadResponse()
		responseReady <- responseResult{response: response, err: readErr}
	}()
	var response *http.Response
	select {
	case got := <-responseReady:
		if got.err != nil {
			cancel()
			_ = clientConnection.CloseWithError(0, "")
			return nil, got.err
		}
		response = got.response
	case <-time.After(config.Timeout):
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "response timeout")
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "context canceled")
		return nil, ctx.Err()
	}
	if err := validateMasqueResponse(response); err != nil {
		cancel()
		_ = clientConnection.CloseWithError(0, "")
		return nil, err
	}

	client := newMasqueClient(ctx, cancel, masque.NewEncoder(stream), masque.NewDecoder(stream), response.Header)
	client.remoteAddr = connection.RemoteAddr()
	if settings.EnableDatagrams {
		client.sendDatagram = stream.SendDatagram
		client.receiveDatagram = stream.ReceiveDatagram
	}
	client.closeTransport = func() error {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		return clientConnection.CloseWithError(0, "")
	}
	return client, nil
}

func newMasqueClient(
	ctx context.Context,
	cancel context.CancelFunc,
	encoder *masque.Encoder,
	decoder *masque.Decoder,
	header http.Header,
) *masqueClient {
	lease := Lease{MTU: 1280}
	if mtu, err := strconv.Atoi(header.Get("X-Porta-MTU")); err == nil && mtu >= 576 && mtu <= 9000 {
		lease.MTU = mtu
	}
	if value := header.Get("X-Porta-DNS"); value != "" {
		lease.DNS, _ = netip.ParseAddr(value)
	}
	return &masqueClient{
		ctx:        ctx,
		cancel:     cancel,
		encoder:    encoder,
		decoder:    decoder,
		lease:      lease,
		leaseReady: make(chan netip.Prefix, 1),
		packets:    make(chan []byte, 256),
		errors:     make(chan error, 2),
	}
}

func (m *masqueClient) start() {
	go m.readCapsules()
	if m.receiveDatagram != nil {
		go m.readDatagrams()
	}
}

func (m *masqueClient) readCapsules() {
	for {
		capsule, err := m.decoder.Read()
		if err != nil {
			m.report(err)
			return
		}
		switch capsule.Type {
		case masque.CapsuleAddressAssign:
			addresses, err := masque.DecodeAddressAssign(capsule.Value)
			if err != nil {
				m.report(err)
				return
			}
			for _, address := range addresses {
				if address.RequestID == masqueRequestID && address.Prefix.Addr().Is4() && address.Prefix.Bits() == 32 && !address.Prefix.Addr().IsUnspecified() {
					select {
					case m.leaseReady <- address.Prefix:
					default:
					}
				}
			}
		case masque.CapsuleRouteAdvertisement:
			if _, err := masque.DecodeRouteAdvertisement(capsule.Value); err != nil {
				m.report(err)
				return
			}
		case masque.CapsuleDatagram:
			packet, err := masque.DecodeIPPacket(capsule.Value)
			if err != nil {
				if errors.Is(err, masque.ErrUnknownContext) {
					continue
				}
				m.report(err)
				return
			}
			m.deliver(packet)
		default:
			// Unknown capsules are ignored as required by RFC 9297.
		}
	}
}

func (m *masqueClient) readDatagrams() {
	for {
		value, err := m.receiveDatagram(m.ctx)
		if err != nil {
			m.report(err)
			return
		}
		packet, err := masque.DecodeIPPacket(value)
		if err != nil {
			if errors.Is(err, masque.ErrUnknownContext) {
				continue
			}
			m.report(err)
			return
		}
		m.deliver(packet)
	}
}

func (m *masqueClient) deliver(packet []byte) {
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case m.packets <- copyOfPacket:
	case <-m.ctx.Done():
	}
}

func (m *masqueClient) send(packet []byte) error {
	if len(packet) > m.lease.MTU {
		return fmt.Errorf("packet length %d exceeds tunnel MTU %d", len(packet), m.lease.MTU)
	}
	info, err := protocol.ParseIPv4(packet)
	if err != nil {
		return err
	}
	if info.Source != m.lease.Address.Addr() {
		return fmt.Errorf("packet source %s does not match lease %s", info.Source, m.lease.Address)
	}
	value := masque.EncodeIPPacket(packet)
	if m.sendDatagram != nil {
		return m.sendDatagram(value)
	}
	return m.encoder.Write(masque.CapsuleDatagram, value)
}

func (m *masqueClient) receive() ([]byte, error) {
	for {
		select {
		case packet := <-m.packets:
			if len(packet) > m.lease.MTU {
				continue
			}
			info, err := protocol.ParseIPv4(packet)
			if err != nil || info.Destination != m.lease.Address.Addr() {
				continue
			}
			return packet, nil
		case err := <-m.errors:
			return nil, err
		case <-m.ctx.Done():
			return nil, m.ctx.Err()
		}
	}
}

func (m *masqueClient) report(err error) {
	select {
	case m.errors <- err:
	default:
	}
}

func (m *masqueClient) close() error {
	var result error
	m.closeOnce.Do(func() {
		m.cancel()
		if m.closeTransport != nil {
			result = m.closeTransport()
		}
	})
	return result
}

func setMasqueHeaders(request *http.Request, config Config) {
	request.Header.Set("Authorization", "Bearer "+config.Token)
	request.Header.Set(http3.CapsuleProtocolHeader, "?1")
	request.Header.Set("X-Porta-Client-ID", config.ClientID)
	request.Header.Set(protocol.HeaderVersion, protocol.Version)
}

func validateMasqueResponse(response *http.Response) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		return &GatewayResponseError{
			StatusCode:       response.StatusCode,
			Status:           response.Status,
			ServerVersion:    response.Header.Get(protocol.HeaderVersion),
			ServerMinVersion: response.Header.Get(protocol.HeaderMinVersion),
			ServerMaxVersion: response.Header.Get(protocol.HeaderMaxVersion),
			ClientVersion:    protocol.Version,
		}
	}
	if response.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		return errors.New("gateway response did not enable the Capsule Protocol")
	}
	if response.Header.Get(protocol.HeaderVersion) != protocol.Version {
		return fmt.Errorf(
			"gateway selected Porta protocol %q, client requires %q",
			response.Header.Get(protocol.HeaderVersion),
			protocol.Version,
		)
	}
	return nil
}

// GatewayResponseError reports a non-success response from a tunnel endpoint.
type GatewayResponseError struct {
	StatusCode       int
	Status           string
	ServerVersion    string
	ServerMinVersion string
	ServerMaxVersion string
	ClientVersion    string
}

func (e *GatewayResponseError) Error() string {
	if e.StatusCode == http.StatusUpgradeRequired && (e.ServerMinVersion != "" || e.ServerMaxVersion != "") {
		supported := e.ServerMinVersion
		if e.ServerMaxVersion != "" && e.ServerMaxVersion != e.ServerMinVersion {
			supported += "-" + e.ServerMaxVersion
		}
		return fmt.Sprintf("gateway requires Porta protocol %s; client uses %s", supported, e.ClientVersion)
	}
	return fmt.Sprintf("gateway returned %s", e.Status)
}

func timedRoundTrip(ctx context.Context, transport http.RoundTripper, request *http.Request, timeout time.Duration) (*http.Response, error) {
	type result struct {
		response *http.Response
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		response, err := transport.RoundTrip(request)
		completed <- result{response: response, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case got := <-completed:
		return got.response, got.err
	case <-timer.C:
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func masqueEndpoint(origin string) (*url.URL, error) {
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("parse gateway URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("gateway URL must be an https origin without user information")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("gateway URL must not contain a path, query, or fragment")
	}
	parsed.Path = gateway.MasquePath
	return parsed, nil
}
