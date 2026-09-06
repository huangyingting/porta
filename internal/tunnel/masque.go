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

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const masqueRequestID uint64 = 1

type masqueClient struct {
	ctx          context.Context
	cancel       context.CancelFunc
	encoder      *masque.Encoder
	decoder      *masque.Decoder
	lease        Lease
	remoteAddr   net.Addr
	leaseReady   chan netip.Prefix
	packets      chan []byte
	errors       chan error
	mtuDiscovery *clientMTUDiscovery
	deliveryMode DeliveryMode
	mtuAutomatic bool
	mtuCeiling   int

	sendDatagram    func([]byte) error
	receiveDatagram func(context.Context) ([]byte, error)
	closeTransport  func() error
	closeOnce       sync.Once
}

func dialMasque(ctx context.Context, config Config) (*Conn, error) {
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}
	return establishWithTimeout(ctx, config.Timeout, func(ctx context.Context) (*Conn, error) {
		return establishMasque(ctx, config)
	})
}

// Bound the complete handshake without imposing a lifetime on the tunnel.
func establishWithTimeout(ctx context.Context, timeout time.Duration, establish func(context.Context) (*Conn, error)) (*Conn, error) {
	sessionCtx, cancelSession := context.WithCancel(ctx)
	startupCtx, cancelStartup := context.WithTimeout(ctx, timeout)
	defer cancelStartup()
	stop := context.AfterFunc(startupCtx, cancelSession)
	connection, err := establish(sessionCtx)
	stopped := stop()
	if !stopped || startupCtx.Err() != nil {
		cancelSession()
		if connection != nil {
			_ = connection.Close()
		}
		deadlineErr := fmt.Errorf("initialize CONNECT-IP: %w", startupCtx.Err())
		if err != nil {
			deadlineErr = fmt.Errorf("initialize CONNECT-IP (%v): %w", err, startupCtx.Err())
		}
		if IsTransportUnavailable(err) {
			return nil, TransportUnavailableError{Err: deadlineErr}
		}
		if isPermanent(err) {
			return nil, PermanentError{Err: deadlineErr}
		}
		return nil, deadlineErr
	}
	if err != nil {
		cancelSession()
		return nil, err
	}
	closeTransport := connection.closePacket
	connection.closePacket = func() error {
		cancelSession()
		return closeTransport()
	}
	return connection, nil
}

func establishMasque(ctx context.Context, config Config) (*Conn, error) {
	if config.URL == "" || config.Token == "" || config.DeviceProof == nil {
		return nil, PermanentError{Err: errors.New("URL, token, and device proof signer are required")}
	}
	if config.Transport == "" {
		config.Transport = TransportHTTP3
	}
	endpoint, err := masqueEndpoint(config.URL)
	if err != nil {
		return nil, PermanentError{Err: err}
	}
	if config.DialAddress != "" {
		address, err := netip.ParseAddrPort(config.DialAddress)
		if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
			return nil, PermanentError{Err: errors.New("dial address must be a numeric unicast IP and port")}
		}
		if config.PacketConn != nil {
			return nil, PermanentError{Err: errors.New("dial address cannot be combined with a caller-owned packet connection")}
		}
	}
	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}

	if config.Transport == TransportHTTP2 {
		return dialFramedHTTP2(ctx, config, endpoint, tlsConfig)
	}

	var client *masqueClient
	switch config.Transport {
	case TransportHTTP3:
		client, err = dialMasqueHTTP3(ctx, config, endpoint, tlsConfig)
	default:
		return nil, fmt.Errorf("unsupported transport %q", config.Transport)
	}
	if err != nil {
		return nil, err
	}
	client.start()
	if err := client.selectMTU(ctx); err != nil {
		_ = client.close()
		return nil, sessionFailure(fmt.Errorf("negotiate tunnel MTU: %w", err))
	}
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
		return nil, sessionFailure(err)
	case <-timer.C:
		_ = client.close()
		return nil, fmt.Errorf("wait for ADDRESS_ASSIGN: %w", context.DeadlineExceeded)
	case <-ctx.Done():
		_ = client.close()
		return nil, fmt.Errorf("wait for ADDRESS_ASSIGN: %w", ctx.Err())
	}

	return &Conn{
		Lease:         client.lease,
		RemoteAddr:    client.remoteAddr,
		DeliveryMode:  client.deliveryMode,
		MTUAutomatic:  client.mtuAutomatic,
		MTUCeiling:    client.mtuCeiling,
		sendPacket:    client.send,
		receivePacket: client.receive,
		closePacket:   client.close,
	}, nil
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
		return nil, PermanentError{Err: errors.New("packet connection and remote address must be provided together")}
	}
	handshakeCtx, stopHandshake := context.WithTimeout(ctx, config.Timeout)
	var (
		connection *quic.Conn
		err        error
	)
	if config.PacketConn != nil {
		connection, err = quic.Dial(handshakeCtx, config.PacketConn, config.RemoteAddr, tlsConfig, quicConfig)
	} else {
		var addresses []string
		target := endpoint.Host
		if config.DialAddress != "" {
			target = config.DialAddress
		}
		addresses, err = resolveQUICAddresses(handshakeCtx, target)
		if err == nil {
			connection, err = dialQUICAddresses(handshakeCtx, addresses, tlsConfig, quicConfig)
		}
	}
	stopHandshake()
	if err != nil {
		cancel()
		return nil, preSessionFailure(fmt.Errorf("dial QUIC: %w", err))
	}
	context.AfterFunc(ctx, func() {
		_ = connection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "context canceled")
	})
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
		return nil, TransportUnavailableError{Err: context.DeadlineExceeded}
	case <-ctx.Done():
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "context canceled")
		return nil, TransportUnavailableError{Err: ctx.Err()}
	}
	settings := clientConnection.Settings()
	if !settings.EnableExtendedConnect {
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeSettingsError), "extended CONNECT unavailable")
		return nil, TransportUnavailableError{Err: errors.New("gateway did not enable HTTP/3 Extended CONNECT")}
	}
	stream, err := clientConnection.OpenRequestStream(ctx)
	if err != nil {
		cancel()
		_ = clientConnection.CloseWithError(0, "")
		return nil, preSessionFailure(err)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    endpoint,
		Host:   endpoint.Host,
		Proto:  "connect-ip",
		Header: make(http.Header),
	}
	if err := setMasqueHeaders(request, config); err != nil {
		cancel()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = clientConnection.CloseWithError(0, "")
		return nil, err
	}
	request.Header.Set(masque.MTUDiscoveryHeader, "1")
	if err := stream.SendRequestHeader(request); err != nil {
		cancel()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		_ = clientConnection.CloseWithError(0, "")
		return nil, preSessionFailure(err)
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
			return nil, preSessionFailure(got.err)
		}
		response = got.response
	case <-time.After(config.Timeout):
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "response timeout")
		return nil, TransportUnavailableError{Err: context.DeadlineExceeded}
	case <-ctx.Done():
		cancel()
		_ = clientConnection.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestCanceled), "context canceled")
		return nil, TransportUnavailableError{Err: ctx.Err()}
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
		client.deliveryMode = DeliveryModeDatagram
	} else {
		client.deliveryMode = DeliveryModeCapsule
	}
	client.closeTransport = func() error {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		return clientConnection.CloseWithError(0, "")
	}
	if err := client.configureMTU(response.Header); err != nil {
		_ = client.close()
		return nil, err
	}
	return client, nil
}

func resolveQUICAddresses(ctx context.Context, address string) ([]string, error) {
	return resolveQUICAddressesWithLookup(ctx, address, net.DefaultResolver.LookupNetIP)
}

func resolveQUICAddressesWithLookup(
	ctx context.Context,
	address string,
	lookup func(context.Context, string, string) ([]netip.Addr, error),
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return []string{address}, nil
	}
	// quic.DialAddr's own DNS lookup has no context, so pass it a numeric address.
	addresses, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	resolved := make([]string, 0, len(addresses))
	for _, resolvedAddress := range addresses {
		resolved = append(resolved, net.JoinHostPort(resolvedAddress.String(), port))
	}
	return resolved, nil
}

func dialQUICAddresses(
	ctx context.Context,
	addresses []string,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) (*quic.Conn, error) {
	if len(addresses) == 1 {
		return quic.DialAddr(ctx, addresses[0], tlsConfig, quicConfig)
	}
	type result struct {
		connection *quic.Conn
		err        error
	}
	results := make(chan result)
	finished := make(chan struct{})
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for index, address := range addresses {
		go func() {
			if delay := time.Duration(index) * 250 * time.Millisecond; delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-finished:
					return
				case <-attemptCtx.Done():
					return
				}
			}
			connection, err := quic.DialAddr(attemptCtx, address, tlsConfig, quicConfig)
			select {
			case results <- result{connection: connection, err: err}:
			case <-finished:
				if connection != nil {
					_ = connection.CloseWithError(0, "")
				}
			}
		}()
	}
	var failures []error
	for range addresses {
		select {
		case <-ctx.Done():
			close(finished)
			return nil, ctx.Err()
		case result := <-results:
			if result.err == nil {
				close(finished)
				cancel()
				return result.connection, nil
			}
			failures = append(failures, result.err)
		}
	}
	close(finished)
	return nil, errors.Join(failures...)
}

func preSessionFailure(err error) error {
	if IsRetryable(err) || errors.Is(err, context.Canceled) {
		return TransportUnavailableError{Err: err}
	}
	return PermanentError{Err: err}
}

func sessionFailure(err error) error {
	if IsRetryable(err) || errors.Is(err, context.Canceled) {
		return err
	}
	return PermanentError{Err: err}
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
		case masque.CapsuleMTUSelected:
			if m.mtuDiscovery == nil {
				m.report(PermanentError{Err: masque.ErrMTUMessage})
				return
			}
			mtu, err := masque.DecodeMTUSelection(capsule.Value, m.mtuDiscovery.token)
			if err != nil || mtu < masque.SafeMTU || mtu > m.mtuDiscovery.maximum {
				m.report(PermanentError{Err: masque.ErrMTUMessage})
				return
			}
			select {
			case m.mtuDiscovery.selected <- mtu:
			default:
			}
		case masque.CapsuleAddressAssign:
			addresses, err := masque.DecodeAddressAssign(capsule.Value)
			if err != nil {
				m.report(PermanentError{Err: err})
				return
			}
			for _, address := range addresses {
				if address.RequestID != masqueRequestID {
					continue
				}
				if !address.Prefix.Addr().Is4() || address.Prefix.Bits() != 32 || !address.Prefix.Addr().IsGlobalUnicast() {
					m.report(PermanentError{Err: fmt.Errorf("gateway returned an invalid IPv4 /32 lease: %s", address.Prefix)})
					return
				}
				select {
				case m.leaseReady <- address.Prefix:
				default:
				}
			}
		case masque.CapsuleRouteAdvertisement:
			if _, err := masque.DecodeRouteAdvertisement(capsule.Value); err != nil {
				m.report(PermanentError{Err: err})
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
		if m.mtuDiscovery != nil && masque.IsMTUProbe(value) {
			if probe, err := masque.DecodeMTUProbe(value); err == nil && probe.Token == m.mtuDiscovery.token {
				select {
				case m.mtuDiscovery.echoes <- probe:
				default:
				}
			}
			continue
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
	// Both capsule decoding and QUIC datagram reception transfer owned storage.
	select {
	case m.packets <- packet:
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
	if m.sendDatagram != nil {
		return masque.SendIPPacket(packet, m.sendDatagram, m.encoder)
	}
	return m.encoder.WriteIPPacket(packet)
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

func setMasqueHeaders(request *http.Request, config Config) error {
	if config.DeviceProof == nil {
		return PermanentError{Err: errors.New("device proof signer is required")}
	}
	proof, err := config.DeviceProof(request.Method, request.URL.Path)
	if err != nil {
		return PermanentError{Err: fmt.Errorf("create device proof: %w", err)}
	}
	request.Header.Set("Authorization", "Bearer "+config.Token)
	request.Header.Set(http3.CapsuleProtocolHeader, "?1")
	deviceauth.Apply(request, proof)
	request.Header.Set(protocol.HeaderVersion, protocol.Version)
	return nil
}

func validateMasqueResponse(response *http.Response) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		failure := &GatewayResponseError{
			StatusCode:       response.StatusCode,
			Status:           response.Status,
			ServerVersion:    response.Header.Get(protocol.HeaderVersion),
			ServerMinVersion: response.Header.Get(protocol.HeaderMinVersion),
			ServerMaxVersion: response.Header.Get(protocol.HeaderMaxVersion),
			ClientVersion:    protocol.Version,
		}
		switch response.StatusCode {
		case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusMisdirectedRequest, http.StatusNotImplemented, http.StatusHTTPVersionNotSupported:
			return TransportUnavailableError{Err: failure}
		case http.StatusUpgradeRequired:
			if failure.ServerMinVersion == "" && failure.ServerMaxVersion == "" {
				return TransportUnavailableError{Err: failure}
			}
			return PermanentError{Err: failure}
		default:
			return failure
		}
	}
	if response.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		return PermanentError{Err: errors.New("gateway response did not enable the Capsule Protocol")}
	}
	if response.Header.Get(protocol.HeaderVersion) != protocol.Version {
		return PermanentError{Err: fmt.Errorf(
			"gateway selected Porta protocol %q, client requires %q",
			response.Header.Get(protocol.HeaderVersion),
			protocol.Version,
		)}
	}
	if value := response.Header.Get("X-Porta-MTU"); value != "" {
		if mtu, err := strconv.Atoi(value); err != nil || mtu < 576 || mtu > 9000 {
			return PermanentError{Err: errors.New("gateway returned an invalid tunnel MTU")}
		}
	}
	if value := response.Header.Get("X-Porta-DNS"); value != "" {
		if address, err := netip.ParseAddr(value); err != nil || !address.Is4() || !address.IsGlobalUnicast() {
			return PermanentError{Err: errors.New("gateway returned an invalid IPv4 DNS address")}
		}
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
	requestCtx, cancel := context.WithCancel(ctx)
	request = request.WithContext(requestCtx)
	completed := make(chan result)
	abandoned := make(chan struct{})
	defer close(abandoned)
	go func() {
		response, err := transport.RoundTrip(request)
		select {
		case completed <- result{response: response, err: err}:
		case <-abandoned:
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
		}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case got := <-completed:
		if got.err != nil {
			cancel()
			if got.response != nil && got.response.Body != nil {
				_ = got.response.Body.Close()
			}
		} else {
			got.response.Body = &cancelOnCloseBody{ReadCloser: got.response.Body, cancel: cancel}
		}
		return got.response, got.err
	case <-timer.C:
		cancel()
		return nil, context.DeadlineExceeded
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}

func masqueEndpoint(origin string) (*url.URL, error) {
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("parse gateway URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return nil, errors.New("gateway URL must be an https origin without user information")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("gateway URL must not contain a path, query, or fragment")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	} else if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return nil, errors.New("gateway URL has an invalid port")
	}
	parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
	parsed.Path = gateway.MasquePath
	return parsed, nil
}
