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
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

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
	ClientID          string
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
	if strings.TrimSpace(config.ServerURL) == "" || config.Token == "" {
		return errors.New("server URL and token are required")
	}
	if config.Transport == "" {
		config.Transport = tunnel.TransportHTTP3
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
	tunnelConfig := tunnel.Config{
		URL:       config.ServerURL,
		Token:     config.Token,
		ClientID:  config.ClientID,
		Transport: config.Transport,
		TLSConfig: tlsConfig,
		Timeout:   15 * time.Second,
	}
	emit(observer, Event{State: StateConnecting, Message: "Connecting", Transport: config.Transport})
	connection, err := tunnel.Dial(ctx, tunnelConfig)
	if err != nil {
		emit(observer, Event{State: StateError, Message: err.Error(), Transport: config.Transport})
		return err
	}
	tunDevice, err := device.OpenNative(config.InterfaceName, connection.Lease.MTU)
	if err != nil {
		_ = connection.Close()
		emit(observer, Event{State: StateError, Message: err.Error(), Transport: config.Transport})
		return err
	}
	defer tunDevice.Close()

	if config.Network != nil {
		emit(observer, Event{State: StateConfiguring, Message: "Configuring Windows network", Lease: connection.Lease, Transport: config.Transport})
		if err := config.Network.Up(ctx, config.InterfaceName, connection.RemoteAddr, connection.Lease); err != nil {
			_ = connection.Close()
			emit(observer, Event{State: StateError, Message: err.Error(), Lease: connection.Lease, Transport: config.Transport})
			return fmt.Errorf("configure network: %w", err)
		}
		defer func() {
			downCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := config.Network.Down(downCtx); err != nil {
				config.Logger.Error("restore Windows network", "error", err)
			}
		}()
	}

	var totals counters
	var connected atomic.Bool
	connectedAt := time.Now()
	connected.Store(true)
	emitSnapshot(observer, StateConnected, "Connected", connection.Lease, config.Transport, connectedAt, &totals)
	trafficCtx, stopTraffic := context.WithCancel(ctx)
	defer stopTraffic()
	go reportTraffic(trafficCtx, observer, connection.Lease, config.Transport, connectedAt, &totals, &connected)

	outbound := make(chan []byte, 256)
	deviceErrors := make(chan error, 1)
	go readDevice(ctx, tunDevice, outbound, deviceErrors)

	initialLease := connection.Lease
	initialRemote := remoteHost(connection.RemoteAddr)
	failures := 0
	connectionStarted := time.Now()
	for {
		err := runConnection(ctx, tunDevice, connection, outbound, deviceErrors, &totals)
		connected.Store(false)
		_ = connection.Close()
		if ctx.Err() != nil {
			emitSnapshot(observer, StateDisconnected, "Disconnected", initialLease, config.Transport, connectedAt, &totals)
			return ctx.Err()
		}
		var deviceErr clientDeviceError
		if errors.As(err, &deviceErr) || !config.Reconnect {
			emitSnapshot(observer, StateError, err.Error(), initialLease, config.Transport, connectedAt, &totals)
			return err
		}
		if time.Since(connectionStarted) >= 30*time.Second {
			failures = 0
		}
		delay := ReconnectDelay(failures, config.ReconnectMaxDelay)
		failures++
		emitSnapshot(observer, StateReconnecting, fmt.Sprintf("Reconnecting in %s", delay), initialLease, config.Transport, connectedAt, &totals)
		if err := wait(ctx, delay); err != nil {
			emitSnapshot(observer, StateDisconnected, "Disconnected", initialLease, config.Transport, connectedAt, &totals)
			return err
		}
		for {
			connection, err = tunnel.Dial(ctx, tunnelConfig)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				emitSnapshot(observer, StateDisconnected, "Disconnected", initialLease, config.Transport, connectedAt, &totals)
				return ctx.Err()
			}
			delay = ReconnectDelay(failures, config.ReconnectMaxDelay)
			failures++
			emitSnapshot(observer, StateReconnecting, fmt.Sprintf("Reconnect failed; retrying in %s", delay), initialLease, config.Transport, connectedAt, &totals)
			if err := wait(ctx, delay); err != nil {
				return err
			}
		}
		if connection.Lease != initialLease {
			_ = connection.Close()
			err := fmt.Errorf("gateway lease changed from %+v to %+v", initialLease, connection.Lease)
			emitSnapshot(observer, StateError, err.Error(), initialLease, config.Transport, connectedAt, &totals)
			return err
		}
		if remoteHost(connection.RemoteAddr) != initialRemote {
			_ = connection.Close()
			err := fmt.Errorf("gateway address changed from %s to %s; reconnect to refresh the escape route", initialRemote, remoteHost(connection.RemoteAddr))
			emitSnapshot(observer, StateError, err.Error(), initialLease, config.Transport, connectedAt, &totals)
			return err
		}
		connectionStarted = time.Now()
		connected.Store(true)
		emitSnapshot(observer, StateConnected, "Connected", connection.Lease, config.Transport, connectedAt, &totals)
	}
}

func readDevice(ctx context.Context, tunDevice device.PacketDevice, outbound chan<- []byte, deviceErrors chan<- error) {
	for {
		packet, err := tunDevice.ReadPacket(ctx)
		if err != nil {
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

func runConnection(
	ctx context.Context,
	tunDevice device.PacketDevice,
	connection *tunnel.Conn,
	outbound <-chan []byte,
	deviceErrors <-chan error,
	totals *counters,
) error {
	connectionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	go func() {
		for {
			select {
			case packet := <-outbound:
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
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-deviceErrors:
		return clientDeviceError{err}
	case err := <-errCh:
		return err
	}
}

func reportTraffic(ctx context.Context, observer Observer, lease tunnel.Lease, transport tunnel.Transport, connectedAt time.Time, totals *counters, connected *atomic.Bool) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if connected.Load() {
				emitSnapshot(observer, StateConnected, "Connected", lease, transport, connectedAt, totals)
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

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
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
				return errors.New("gateway did not provide a certificate")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], pinnedThumbprint) != 1 {
				return fmt.Errorf("gateway certificate SHA-256 thumbprint mismatch: got %s", hex.EncodeToString(actual[:]))
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
