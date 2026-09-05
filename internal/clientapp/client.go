package clientapp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/clientid"
	"github.com/huangyingting/porta/internal/device"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/tunnel"
)

type State string

const (
	StateConnecting    State = "connecting"
	StateConfiguring   State = "configuring"
	StateConnected     State = "connected"
	StateReconnecting  State = "reconnecting"
	StateDisconnecting State = "disconnecting"
	StateDisconnected  State = "disconnected"
	StateError         State = "error"
)

type Config struct {
	ServerURL         string
	Token             string
	Transport         tunnel.Transport
	InterfaceName     string
	CAPath            string
	Thumbprint        string
	Insecure          bool
	Reconnect         bool
	ReconnectMaxDelay time.Duration
	Network           NetworkConfigurator
	Logger            *slog.Logger
}

type NetworkConfigurator interface {
	Up(context.Context, string, net.Addr, tunnel.Lease) error
	Down(context.Context) error
}

// NetworkPreparer installs a fail-closed guard and a narrowly scoped physical
// escape route before dialing a literal endpoint. Repeated calls retain the guard.
type NetworkPreparer interface {
	Prepare(context.Context, net.Addr) error
}

// NetworkInterfacePreparer is the preparation variant for platforms that must
// journal the requested interface identity before the device exists.
type NetworkInterfacePreparer interface {
	Prepare(context.Context, string, net.Addr) error
}

// NetworkReconfigurer replaces a live configuration without dropping its guard.
type NetworkReconfigurer interface {
	Reconfigure(context.Context, string, net.Addr, tunnel.Lease) error
}

// NetworkRecoveryEndpoints exposes journaled literal endpoints so a process can
// resume protection after a crash without using the physical DNS resolver.
type NetworkRecoveryEndpoints interface {
	RecoveryEndpoints() []net.Addr
}

type Event struct {
	State             State
	Message           string
	Lease             tunnel.Lease
	Transport         tunnel.Transport
	ConnectedAt       time.Time
	BytesUploaded     uint64
	BytesDownloaded   uint64
	PacketsUploaded   uint64
	PacketsDownloaded uint64
}

type Observer func(Event)

type counters struct {
	bytesUploaded     atomic.Uint64
	bytesDownloaded   atomic.Uint64
	packetsUploaded   atomic.Uint64
	packetsDownloaded atomic.Uint64
}

func Run(ctx context.Context, config Config, observer Observer) error {
	return run(ctx, clientid.Current, config, observer, func(ctx context.Context, config tunnel.Config) (*clientConnection, error) {
		connection, err := tunnel.Dial(ctx, config)
		if err != nil {
			return nil, err
		}
		return &clientConnection{packetConnection: connection, lease: connection.Lease, remoteAddr: connection.RemoteAddr, transport: connection.Transport}, nil
	}, func(name string, mtu int) (device.PacketDevice, error) {
		return device.OpenNative(name, mtu)
	})
}

type clientConnection struct {
	packetConnection
	lease      tunnel.Lease
	remoteAddr net.Addr
	transport  tunnel.Transport
}

func run(ctx context.Context, resolveIdentity func() (string, error), config Config, observer Observer, dial func(context.Context, tunnel.Config) (*clientConnection, error), openDevice func(string, int) (device.PacketDevice, error)) (runErr error) {
	if strings.TrimSpace(config.ServerURL) == "" || config.Token == "" {
		return errors.New("server URL and token are required")
	}
	if config.Transport == "" {
		config.Transport = tunnel.TransportAuto
	}
	if config.Transport != tunnel.TransportAuto && config.Transport != tunnel.TransportHTTP3 && config.Transport != tunnel.TransportHTTP2 {
		return fmt.Errorf("unsupported transport %q", config.Transport)
	}
	if config.InterfaceName == "" {
		config.InterfaceName = "Porta"
	}
	if config.ReconnectMaxDelay <= 0 {
		config.ReconnectMaxDelay = 30 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	parsedURL, err := url.ParseRequestURI(config.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if parsedURL.Scheme != "https" || parsedURL.Host == "" {
		return errors.New("server URL must be an https origin")
	}
	tlsConfig, err := TLSConfig(config.CAPath, config.Thumbprint, config.Insecure)
	if err != nil {
		return err
	}
	deviceID, err := resolveIdentity()
	if err != nil {
		return fmt.Errorf("resolve OS device identity: %w", err)
	}
	tunnelConfig := tunnel.Config{
		URL:       config.ServerURL,
		Token:     config.Token,
		ClientID:  deviceID,
		Transport: config.Transport,
		TLSConfig: tlsConfig,
		Timeout:   15 * time.Second,
	}
	var (
		tunDevice      device.PacketDevice
		connection     *clientConnection
		reader         *deviceReader
		networkStarted bool
		networkUp      bool
		lease          tunnel.Lease
		remote         string
		transport      = config.Transport
		connectedAt    time.Time
		totals         counters
	)
	outbound := make(chan []byte, 256)
	deviceErrors := make(chan error, 1)
	var prepareNetwork func(context.Context, net.Addr) error
	if preparer, ok := config.Network.(NetworkPreparer); ok {
		prepareNetwork = preparer.Prepare
	} else if preparer, ok := config.Network.(NetworkInterfacePreparer); ok {
		prepareNetwork = func(ctx context.Context, endpoint net.Addr) error {
			return preparer.Prepare(ctx, config.InterfaceName, endpoint)
		}
	}
	stopReader := func() {
		reader.stop()
		reader = nil
	}
	defer func() {
		if connection != nil {
			_ = connection.Close()
		}
		stopReader()
		if networkStarted && prepareNetwork != nil && ctx.Err() == nil && runErr != nil {
			runErr = fmt.Errorf("%w; automatic cleanup was not attempted: use --cleanup-network for network recovery", runErr)
		} else if networkStarted {
			downCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := config.Network.Down(downCtx); err != nil {
				config.Logger.Error("restore network", "error", err)
				cleanupErr := fmt.Errorf("restore network: %w", err)
				if errors.Is(runErr, context.Canceled) {
					runErr = cleanupErr
				} else {
					runErr = errors.Join(runErr, cleanupErr)
				}
			}
		}
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
	}()

	finish := func(err error) error {
		state := StateError
		message := err.Error()
		if ctx.Err() != nil {
			err, state, message = ctx.Err(), StateDisconnected, "Disconnected"
		}
		emitSnapshot(observer, state, message, lease, transport, connectedAt, &totals)
		return err
	}
	emit(observer, Event{State: StateConnecting, Message: "Device ID: " + deviceID + " (OS derived)", Transport: transport})
	emit(observer, Event{State: StateConnecting, Message: "Connecting", Transport: transport})
	var endpoints []net.Addr
	if recovery, ok := config.Network.(NetworkRecoveryEndpoints); ok && prepareNetwork != nil {
		if saved := recovery.RecoveryEndpoints(); len(saved) > 0 {
			networkStarted = true
			endpoints, err = restoredEndpoints(parsedURL, saved)
			if err != nil {
				return finish(err)
			}
		}
	}
	failures := 0
	var retryErr error
	for {
		if ctx.Err() != nil {
			return finish(ctx.Err())
		}
		if retryErr != nil {
			var deviceErr clientDeviceError
			if errors.As(retryErr, &deviceErr) || !config.Reconnect || !tunnel.IsRetryable(retryErr) {
				return finish(retryErr)
			}
			delay := ReconnectDelay(failures, config.ReconnectMaxDelay)
			failures++
			emitSnapshot(observer, StateReconnecting, fmt.Sprintf("Reconnecting in %s", delay), lease, transport, connectedAt, &totals)
			if err := wait(ctx, delay, deviceErrors); err != nil {
				return finish(err)
			}
		}
		var endpoint net.Addr
		if prepareNetwork != nil {
			if len(endpoints) == 0 {
				resolveCtx, cancel := context.WithTimeout(ctx, tunnelConfig.Timeout)
				endpoints, err = resolveEndpoints(resolveCtx, parsedURL)
				cancel()
				if err != nil {
					retryErr = err
					continue
				}
			}
			// Never use the system resolver while the guard is active. Rotate
			// only the addresses obtained before installing it.
			endpoint = endpoints[failures%len(endpoints)]
			tunnelConfig.DialAddress = endpoint.String()
		}
		sessionDial := dial
		if prepareNetwork != nil && networkStarted {
			sessionDial = func(ctx context.Context, candidate tunnel.Config) (*clientConnection, error) {
				if err := prepareNetwork(ctx, transportEndpoint(endpoint, candidate.Transport)); err != nil {
					return nil, tunnel.PermanentError{Err: fmt.Errorf("prepare network: %w", err)}
				}
				return dial(ctx, candidate)
			}
		}
		connection, err = dialAutomatic(ctx, tunnelConfig, sessionDial)
		if err != nil {
			retryErr = err
			continue
		}
		if ctx.Err() != nil {
			return finish(ctx.Err())
		}
		if prepareNetwork != nil && !networkStarted {
			// Initial DNS and handshake are ordinary bootstrap traffic. Begin
			// protection only after authentication, before configuring routes.
			networkStarted = true
			if err := prepareNetwork(ctx, transportEndpoint(endpoint, connection.transport)); err != nil {
				return finish(fmt.Errorf("prepare network: %w", err))
			}
		}
		transport = connection.transport
		changedLease := tunDevice != nil && connection.lease != lease
		nextRemote := ""
		if connection.remoteAddr != nil {
			nextRemote = connection.remoteAddr.String()
		}
		changedRemote := networkUp && remote != nextRemote
		// Address/MTU changes invalidate source queues or native buffers.
		// Resolver and route-only changes can retain the adapter identity.
		if tunDevice == nil || connection.lease.Address != lease.Address || connection.lease.MTU != lease.MTU {
			stopReader()
			if tunDevice != nil {
				if err := tunDevice.Close(); err != nil {
					return finish(fmt.Errorf("close previous TUN: %w", err))
				}
				tunDevice = nil
			}
			drainPackets(outbound)
			select {
			case err := <-deviceErrors:
				return finish(clientDeviceError{err})
			default:
			}
			tunDevice, err = openDevice(config.InterfaceName, connection.lease.MTU)
			if err != nil {
				return finish(err)
			}
		}
		if config.Network != nil && (!networkUp || changedLease || changedRemote || prepareNetwork != nil) {
			networkStarted = true
			emitSnapshot(observer, StateConfiguring, "Configuring network", connection.lease, transport, connectedAt, &totals)
			if !networkUp {
				err = config.Network.Up(ctx, tunDevice.Name(), connection.remoteAddr, connection.lease)
			} else if reconfigurer, ok := config.Network.(NetworkReconfigurer); ok {
				err = reconfigurer.Reconfigure(ctx, tunDevice.Name(), connection.remoteAddr, connection.lease)
			} else {
				err = errors.New("network configurator cannot safely reconfigure a changed session")
			}
			if err != nil {
				return finish(fmt.Errorf("configure network: %w", err))
			}
			networkUp = true
		}
		lease = connection.lease
		remote = nextRemote
		if reader == nil {
			reader = startDeviceReader(ctx, tunDevice, outbound, deviceErrors)
		}
		if connectedAt.IsZero() {
			connectedAt = time.Now()
		}
		progress := func() { emitSnapshot(observer, StateConnected, "Connected", lease, transport, connectedAt, &totals) }
		progress()
		connectionStarted := time.Now()
		retryErr = runConnection(ctx, tunDevice, connection, outbound, deviceErrors, &totals, progress)
		connection = nil
		if time.Since(connectionStarted) >= 30*time.Second {
			failures = 0
		}
	}
}

func dialAutomatic(ctx context.Context, config tunnel.Config, dial func(context.Context, tunnel.Config) (*clientConnection, error)) (*clientConnection, error) {
	automatic := config.Transport == "" || config.Transport == tunnel.TransportAuto
	if automatic {
		config.Transport = tunnel.TransportHTTP3
	}
	connection, err := dial(ctx, config)
	if automatic && err != nil && ctx.Err() == nil && tunnel.IsTransportUnavailable(err) {
		config.Transport = tunnel.TransportHTTP2
		connection, err = dial(ctx, config)
	}
	if err == nil && connection.transport == "" {
		connection.transport = config.Transport
	}
	return connection, err
}

func resolveEndpoints(ctx context.Context, endpoint *url.URL) ([]net.Addr, error) {
	port, err := gatewayPort(endpoint)
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	if address, parseErr := netip.ParseAddr(endpoint.Hostname()); parseErr == nil {
		if !usableProtectedEndpoint(address) {
			return nil, errors.New("automatic networking requires an unscoped unicast gateway endpoint, not a link-local or loopback address")
		}
		addresses = []netip.Addr{address}
	} else {
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", endpoint.Hostname())
		if err != nil {
			return nil, fmt.Errorf("resolve gateway before network protection: %w", err)
		}
	}
	var endpoints []net.Addr
	for _, ipv4 := range []bool{true, false} {
		for _, address := range addresses {
			address = address.Unmap()
			if address.Is4() == ipv4 && usableProtectedEndpoint(address) {
				endpoints = append(endpoints, &net.TCPAddr{IP: net.IP(address.AsSlice()), Port: port, Zone: address.Zone()})
			}
		}
	}
	if len(endpoints) == 0 {
		return nil, errors.New("gateway has no supported unscoped unicast IP endpoint")
	}
	return endpoints, nil
}

func gatewayPort(endpoint *url.URL) (int, error) {
	if endpoint.Port() == "" {
		return 443, nil
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("gateway port must be in 1..65535")
	}
	return port, nil
}

func usableProtectedEndpoint(address netip.Addr) bool {
	return address.IsGlobalUnicast() && address.Zone() == ""
}

func restoredEndpoints(endpoint *url.URL, saved []net.Addr) ([]net.Addr, error) {
	port, err := gatewayPort(endpoint)
	if err != nil {
		return nil, err
	}
	if address, err := netip.ParseAddr(endpoint.Hostname()); err == nil {
		if !usableProtectedEndpoint(address) {
			return nil, errors.New("automatic networking requires an unscoped unicast gateway endpoint, not a link-local or loopback address")
		}
		return []net.Addr{&net.TCPAddr{IP: net.IP(address.AsSlice()), Zone: address.Zone(), Port: port}}, nil
	}
	var endpoints []net.Addr
	seen := make(map[netip.AddrPort]bool)
	for _, endpoint := range saved {
		if endpoint == nil {
			return nil, errors.New("network recovery journal has an invalid endpoint")
		}
		address, err := netip.ParseAddrPort(endpoint.String())
		if err != nil || !usableProtectedEndpoint(address.Addr()) {
			return nil, errors.New("network recovery journal has an invalid numeric endpoint")
		}
		if int(address.Port()) == port && !seen[address] {
			seen[address] = true
			endpoints = append(endpoints, net.TCPAddrFromAddrPort(address))
		}
	}
	if len(endpoints) == 0 {
		return nil, errors.New("network protection is active but no cached endpoint matches this gateway port")
	}
	return endpoints, nil
}

func drainPackets(packets <-chan []byte) {
	for {
		select {
		case <-packets:
		default:
			return
		}
	}
}

func transportEndpoint(endpoint net.Addr, transport tunnel.Transport) net.Addr {
	if address, ok := endpoint.(*net.TCPAddr); ok && transport == tunnel.TransportHTTP3 {
		return &net.UDPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
	}
	if address, ok := endpoint.(*net.UDPAddr); ok && transport == tunnel.TransportHTTP2 {
		return &net.TCPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
	}
	return endpoint
}

type deviceReader struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func startDeviceReader(ctx context.Context, tunDevice device.PacketDevice, outbound chan<- []byte, deviceErrors chan<- error) *deviceReader {
	readCtx, cancel := context.WithCancel(ctx)
	reader := &deviceReader{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(reader.done)
		readDevice(readCtx, tunDevice, outbound, deviceErrors)
	}()
	return reader
}

func (r *deviceReader) stop() {
	if r == nil {
		return
	}
	r.cancel()
	<-r.done
}

func readDevice(ctx context.Context, tunDevice device.PacketDevice, outbound chan<- []byte, deviceErrors chan<- error) {
	for {
		packet, err := tunDevice.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			select {
			case deviceErrors <- err:
			case <-ctx.Done():
			}
			return
		}
		if _, err := protocol.ParseIPv4(packet); err != nil {
			continue
		}
		select {
		case outbound <- packet:
		case <-ctx.Done():
			return
		}
	}
}

type clientDeviceError struct{ err error }

func (e clientDeviceError) Error() string { return e.err.Error() }
func (e clientDeviceError) Unwrap() error { return e.err }

type packetConnection interface {
	Send([]byte) error
	Receive() ([]byte, error)
	Close() error
}

func runConnection(
	ctx context.Context,
	tunDevice device.PacketDevice,
	connection packetConnection,
	outbound <-chan []byte,
	deviceErrors <-chan error,
	totals *counters,
	progress func(),
) error {
	connectionCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		_ = connection.Close()
		workers.Wait()
	}()
	errCh := make(chan error, 2)
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			select {
			case packet := <-outbound:
				if connectionCtx.Err() != nil {
					return
				}
				if err := connection.Send(packet); err != nil {
					errCh <- err
					return
				}
				totals.bytesUploaded.Add(uint64(len(packet)))
				totals.packetsUploaded.Add(1)
			case <-connectionCtx.Done():
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			packet, err := connection.Receive()
			if err != nil {
				errCh <- err
				return
			}
			if err := tunDevice.WritePacket(connectionCtx, packet); err != nil {
				errCh <- clientDeviceError{err}
				return
			}
			totals.bytesDownloaded.Add(uint64(len(packet)))
			totals.packetsDownloaded.Add(1)
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-deviceErrors:
			return clientDeviceError{err}
		case err := <-errCh:
			return err
		case <-ticker.C:
			if progress != nil {
				progress()
			}
		}
	}
}

func emitSnapshot(observer Observer, state State, message string, lease tunnel.Lease, transport tunnel.Transport, connectedAt time.Time, totals *counters) {
	emit(observer, Event{
		State:             state,
		Message:           message,
		Lease:             lease,
		Transport:         transport,
		ConnectedAt:       connectedAt,
		BytesUploaded:     totals.bytesUploaded.Load(),
		BytesDownloaded:   totals.bytesDownloaded.Load(),
		PacketsUploaded:   totals.packetsUploaded.Load(),
		PacketsDownloaded: totals.packetsDownloaded.Load(),
	})
}

func emit(observer Observer, event Event) {
	if observer != nil {
		observer(event)
	}
}

func wait(ctx context.Context, duration time.Duration, deviceErrors <-chan error) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-deviceErrors:
		return clientDeviceError{err}
	case <-timer.C:
		return nil
	}
}

func remoteHost(address net.Addr) string {
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		return host
	}
	return address.String()
}

func ReconnectDelay(failures int, maximum time.Duration) time.Duration {
	if maximum < time.Second {
		maximum = time.Second
	}
	if failures > 5 {
		failures = 5
	}
	if failures < 0 {
		failures = 0
	}
	delay := time.Second << failures
	if delay > maximum {
		return maximum
	}
	return delay
}

func TLSConfig(caPath, thumbprint string, insecure bool) (*tls.Config, error) {
	if insecure && thumbprint != "" {
		return nil, errors.New("--insecure and --thumbprint cannot be used together")
	}
	pinnedThumbprint, err := ParseThumbprint(thumbprint)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} // #nosec G402 -- explicit development flag
	if pinnedThumbprint != nil {
		if caPath == "" {
			config.InsecureSkipVerify = true // #nosec G402 -- the pinned certificate is verified below
		}
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return tunnel.PermanentError{Err: errors.New("gateway did not provide a certificate")}
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], pinnedThumbprint) != 1 {
				return tunnel.PermanentError{Err: fmt.Errorf("gateway certificate SHA-256 thumbprint mismatch: got %s", hex.EncodeToString(actual[:]))}
			}
			return nil
		}
	}
	if caPath == "" {
		return config, nil
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("CA file contains no certificates")
	}
	config.RootCAs = roots
	return config, nil
}

func ParseThumbprint(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	normalized := strings.TrimSpace(value)
	if len(normalized) >= len("sha256:") && strings.EqualFold(normalized[:len("sha256:")], "sha256:") {
		normalized = normalized[len("sha256:"):]
	}
	normalized = strings.NewReplacer(":", "", "-", "").Replace(normalized)
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("thumbprint must be a 64-digit SHA-256 value (separators and a sha256: prefix are optional)")
	}
	return decoded, nil
}
