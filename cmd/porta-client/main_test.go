package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestClientCLIRequiresEnvironmentToken(t *testing.T) {
	if mode := os.Getenv("PORTA_CLI_TOKEN_TEST"); mode != "" {
		os.Args = []string{"porta-client", "--server", "https://example.invalid", "--manual-network=true"}
		if mode == "argument" {
			os.Args = append(os.Args, "--token", "private-test-token")
		}
		main()
		return
	}
	for _, test := range []struct{ mode, message string }{
		{"argument", "flag provided but not defined: -token"},
		{"missing", "PORTA_TOKEN is required"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestClientCLIRequiresEnvironmentToken$")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "PORTA_TOKEN=") && !strings.HasPrefix(entry, "PORTA_CLI_TOKEN_TEST=") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, "PORTA_CLI_TOKEN_TEST="+test.mode)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), test.message) || strings.Contains(string(output), "private-test-token") {
				t.Fatalf("CLI did not reject token input safely: %s (%v)", output, err)
			}
		})
	}
}

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
