package certutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGenerateCertificateAndPrivateKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := Generate(certPath, keyPath, Options{Hosts: []string{"localhost", "127.0.0.1"}, ValidFor: time.Hour}); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"localhost", "127.0.0.1"} {
		if err := cert.VerifyHostname(host); err != nil {
			t.Fatal(err)
		}
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("invalid key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.(crypto.Signer).Public()) {
		t.Fatal("certificate and key do not match")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key mode = %o", info.Mode().Perm())
		}
	}
}

func TestGenerateDoesNotClobberExistingFiles(t *testing.T) {
	for _, existing := range []string{"server.crt", "server.key"} {
		t.Run(existing, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, existing)
			if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
			if err := Generate(certPath, keyPath, Options{Hosts: []string{"localhost"}}); err == nil {
				t.Fatal("existing file overwritten")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "original" {
				t.Fatalf("original file changed: %q, %v", data, err)
			}
			if existing == "server.key" {
				if _, err := os.Stat(certPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("orphaned certificate left on key failure")
				}
			}
		})
	}
}
