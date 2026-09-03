package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/htun-project/htun/internal/certutil"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/http2"
)

func TestServerTLSConfigACME(t *testing.T) {
	config, manager, err := serverTLSConfig("VPN.Example.COM.", "admin@example.com", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if manager == nil || config.GetCertificate == nil {
		t.Fatal("ACME mode did not configure dynamic certificates")
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %d, want %d", config.MinVersion, tls.VersionTLS12)
	}
	if err := manager.HostPolicy(t.Context(), "vpn.example.com"); err != nil {
		t.Fatalf("configured domain rejected: %v", err)
	}
	if err := manager.HostPolicy(t.Context(), "other.example.com"); err == nil {
		t.Fatal("unconfigured domain accepted")
	}
	if !contains(config.NextProtos, acme.ALPNProto) {
		t.Fatal("ACME TLS-ALPN-01 protocol is not enabled")
	}

	http3Config := http3TLSConfig(config)
	if len(http3Config.NextProtos) != 1 || http3Config.NextProtos[0] != http3.NextProtoH3 {
		t.Fatalf("HTTP/3 protocols = %v", http3Config.NextProtos)
	}
	if http3Config.GetCertificate == nil {
		t.Fatal("HTTP/3 config did not retain dynamic certificates")
	}
}

func TestStaticTLSConfigReloadsCertificate(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	if err := certutil.Generate(certPath, keyPath, certutil.Options{Hosts: []string{"vpn.example.com"}}); err != nil {
		t.Fatal(err)
	}
	config, err := staticTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %d, want %d", config.MinVersion, tls.VersionTLS12)
	}

	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := certutil.Generate(certPath, keyPath, certutil.Options{Hosts: []string{"vpn.example.com"}}); err != nil {
		t.Fatal(err)
	}
	second, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("certificate replacement was not reloaded")
	}
}

func TestStaticTLSConfigKeepsCertificateDuringPartialReplacement(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	if err := certutil.Generate(certPath, keyPath, certutil.Options{Hosts: []string{"vpn.example.com"}}); err != nil {
		t.Fatal(err)
	}
	config, err := staticTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(keyPath, []byte("incomplete replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatalf("partial replacement interrupted TLS handshakes: %v", err)
	}
	if !bytes.Equal(first.Certificate[0], current.Certificate[0]) {
		t.Fatal("partial replacement discarded the previous certificate")
	}
}

func TestServerTLSConfigRejectsInvalidACMEOptions(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		cache  string
	}{
		{name: "empty domain", cache: "cache"},
		{name: "non-qualified domain", domain: "localhost", cache: "cache"},
		{name: "URL", domain: "https://vpn.example.com", cache: "cache"},
		{name: "empty cache", domain: "vpn.example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := serverTLSConfig(test.domain, "", test.cache); err == nil {
				t.Fatal("invalid ACME options accepted")
			}
		})
	}
}

func TestProxyBackendHandlerServesH2C(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: proxyBackendHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%d", r.ProtoMajor)
	}))}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			t.Errorf("serve h2c backend: %v", serveErr)
		}
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
	})

	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	response, err := transport.RoundTrip(mustRequest(t, "http://"+listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "2" {
		t.Fatalf("backend protocol = %q, want HTTP/2", body)
	}
}

func TestValidateProxyListenAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8443", "[::1]:8443", "localhost:8443"} {
		if err := validateProxyListenAddress(address); err != nil {
			t.Fatalf("%s rejected: %v", address, err)
		}
	}
	for _, address := range []string{":8443", "0.0.0.0:8443", "10.0.0.4:8443", "invalid"} {
		if err := validateProxyListenAddress(address); err == nil {
			t.Fatalf("%s accepted", address)
		}
	}
}

func mustRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
