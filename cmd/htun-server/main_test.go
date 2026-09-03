package main

import (
	"crypto/tls"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme"
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

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
