package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/htun-project/htun/internal/device"
	"github.com/htun-project/htun/internal/tunnel"
)

var invalidClientID = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "htun-client:", err)
		os.Exit(1)
	}
}

func run() error {
	serverURL := flag.String("server", "", "gateway origin, for example https://vpn.example.com:8443")
	transportName := flag.String("transport", "h3", "tunnel transport: h3 or h2")
	protocolName := flag.String("protocol", "masque", "tunnel protocol: masque or legacy")
	interfaceName := flag.String("interface", defaultInterfaceName(), "TUN interface name")
	clientID := flag.String("client-id", defaultClientID(), "stable client identifier")
	caPath := flag.String("ca", "", "optional PEM CA certificate")
	thumbprint := flag.String("thumbprint", "", "optional SHA-256 gateway certificate thumbprint")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (development only)")
	tokenFlag := flag.String("token", "", "bearer token (prefer HTUN_TOKEN environment variable)")
	flag.Parse()

	token := os.Getenv("HTUN_TOKEN")
	if token == "" {
		token = *tokenFlag
	}
	if *serverURL == "" || token == "" {
		return errors.New("--server and HTUN_TOKEN are required")
	}
	tlsConfig, err := clientTLSConfig(*caPath, *thumbprint, *insecure)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	connection, err := tunnel.Dial(ctx, tunnel.Config{
		URL:       *serverURL,
		Token:     token,
		ClientID:  *clientID,
		Transport: tunnel.Transport(*transportName),
		Protocol:  tunnel.Protocol(*protocolName),
		TLSConfig: tlsConfig,
		Timeout:   15 * time.Second,
	})
	if err != nil {
		return err
	}
	defer connection.Close()

	tunDevice, err := device.OpenNative(*interfaceName, connection.Lease.MTU)
	if err != nil {
		return err
	}
	defer tunDevice.Close()
	attributes := []any{
		"interface", tunDevice.Name(),
		"address", connection.Lease.Address,
		"dns", connection.Lease.DNS,
		"mtu", connection.Lease.MTU,
		"transport", *transportName,
		"protocol", *protocolName,
	}
	if connection.Lease.Gateway.IsValid() {
		attributes = append(attributes, "gateway", connection.Lease.Gateway)
	}
	slog.Info("tunnel ready", attributes...)
	if runtime.GOOS == "windows" {
		slog.Info("configure routes in another elevated terminal with scripts/windows-up.ps1")
	} else {
		slog.Info("configure the interface and routes explicitly; see README.md")
	}

	errCh := make(chan error, 2)
	go func() {
		for {
			packet, err := tunDevice.ReadPacket(ctx)
			if err != nil {
				errCh <- err
				return
			}
			if err := connection.Send(packet); err != nil {
				errCh <- err
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
			if err := tunDevice.WritePacket(ctx, packet); err != nil {
				errCh <- err
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func clientTLSConfig(caPath, thumbprint string, insecure bool) (*tls.Config, error) {
	if insecure && thumbprint != "" {
		return nil, errors.New("--insecure and --thumbprint cannot be used together")
	}
	pinnedThumbprint, err := parseThumbprint(thumbprint)
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

func parseThumbprint(value string) ([]byte, error) {
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

func defaultInterfaceName() string {
	if runtime.GOOS == "windows" {
		return "hTun"
	}
	return "htun0"
}

func defaultClientID() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "htun-client"
	}
	value := strings.Trim(invalidClientID.ReplaceAllString(hostname, "-"), "-._")
	if value == "" {
		return "htun-client"
	}
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
