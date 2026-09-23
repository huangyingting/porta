package clientapp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/clientid"
	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/tunnel"
)

// This opt-in probe never reads a real token, persistent identity, or VPN
// journal. An unrecognized token must be rejected before device enrollment.
func TestLivePlatformTLSAndAuthentication(t *testing.T) {
	origin := os.Getenv("PORTA_TLS_TEST_URL")
	if origin == "" {
		t.Skip("set PORTA_TLS_TEST_URL for credential-free platform TLS/authentication probes")
	}
	endpoint, err := url.Parse(origin)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		t.Fatal("PORTA_TLS_TEST_URL must be an HTTPS origin without credentials, path, query or fragment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tlsConfig, err := TLSConfig("", "", false)
	if err != nil {
		t.Fatal(err)
	}
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second},
		Config:    tlsConfig,
	}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(endpoint.Hostname(), port))
	if err != nil {
		t.Fatalf("platform trust store rejected live TLS: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := deviceauth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := clientid.New(key, "Porta-Platform-Probe")
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	token := "invalid-platform-probe-" + hex.EncodeToString(random)
	for _, transport := range []tunnel.Transport{tunnel.TransportHTTP3, tunnel.TransportHTTP2} {
		t.Run(string(transport), func(t *testing.T) {
			config := tunnel.Config{
				URL: origin, Token: token, Transport: transport, TLSConfig: tlsConfig.Clone(), Timeout: 15 * time.Second,
				DeviceProof: func(method, path string) (deviceauth.Proof, error) {
					return identity.Proof(token, method, path)
				},
			}
			connection, err := tunnel.Dial(ctx, config)
			if connection != nil {
				_ = connection.Close()
				t.Fatal("live endpoint unexpectedly accepted an invalid token")
			}
			var response *tunnel.GatewayResponseError
			if !errors.As(err, &response) || response.StatusCode != http.StatusUnauthorized ||
				tunnel.IsTransportUnavailable(err) || tunnel.IsRetryable(err) {
				t.Fatalf("native transport did not reach permanent authentication rejection: %v", err)
			}
			config.TLSConfig.ServerName = "porta-hostname-mismatch.invalid"
			connection, err = tunnel.Dial(ctx, config)
			if connection != nil {
				_ = connection.Close()
				t.Fatal("native transport accepted the wrong certificate hostname")
			}
			var certificate *tls.CertificateVerificationError
			if !errors.As(err, &certificate) || tunnel.IsRetryable(err) || tunnel.IsTransportUnavailable(err) {
				t.Fatalf("hostname verification did not fail permanently: %v", err)
			}
		})
	}
}
