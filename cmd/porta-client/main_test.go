package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestClientTLSConfigThumbprint(t *testing.T) {
	rawCertificate := []byte("gateway certificate")
	sum := sha256.Sum256(rawCertificate)
	thumbprint := strings.ToUpper(hex.EncodeToString(sum[:]))
	config, err := clientTLSConfig("", "sha256:"+thumbprint, false)
	if err != nil {
		t.Fatal(err)
	}
	if !config.InsecureSkipVerify {
		t.Fatal("thumbprint-only verification must bypass CA verification")
	}
	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Raw: rawCertificate}},
	}
	if err := config.VerifyConnection(state); err != nil {
		t.Fatalf("matching thumbprint rejected: %v", err)
	}

	state.PeerCertificates[0].Raw = []byte("different certificate")
	if err := config.VerifyConnection(state); err == nil {
		t.Fatal("mismatched thumbprint accepted")
	}
}

func TestClientTLSConfigRejectsInvalidThumbprint(t *testing.T) {
	if _, err := clientTLSConfig("", "not-a-thumbprint", false); err == nil {
		t.Fatal("invalid thumbprint accepted")
	}
	if _, err := clientTLSConfig("", strings.Repeat("00", sha256.Size), true); err == nil {
		t.Fatal("--insecure with --thumbprint accepted")
	}
}

func TestParseThumbprintWithSeparators(t *testing.T) {
	value := strings.Repeat("ab:", sha256.Size-1) + "ab"
	got, err := parseThumbprint(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != sha256.Size {
		t.Fatalf("decoded thumbprint length = %d, want %d", len(got), sha256.Size)
	}
}

func TestReconnectDelay(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second}
	for index, expected := range want {
		if got := reconnectDelay(index, 5*time.Second); got != expected {
			t.Fatalf("delay %d = %s, want %s", index, got, expected)
		}
	}
}
