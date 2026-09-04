package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/certutil"
	"golang.org/x/sys/unix"
)

func TestDecodeJSONRejectsTruncatedTrailingBody(t *testing.T) {
	valid := `{"name":"Operations","max_devices":4}`
	for _, test := range []struct {
		name string
		body string
		ok   bool
	}{
		{"valid", valid, true},
		{"exact-limit", valid + strings.Repeat(" ", (16<<10)-len(valid)), true},
		{"oversized", valid + strings.Repeat(" ", 16<<10), false},
		{"hidden-trailing-json", valid + strings.Repeat(" ", 16<<10) + `{}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/clients", strings.NewReader(test.body))
			var input clientInput
			if err := decodeJSON(request, &input); (err == nil) != test.ok {
				t.Fatalf("decodeJSON error = %v, want success=%v", err, test.ok)
			}
		})
	}
}

func TestStaticTLSKeepsCertificateWhileReplacementIsMissing(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	if err := certutil.Generate(certPath, keyPath, certutil.Options{Hosts: []string{"vpn.example.com"}}); err != nil {
		t.Fatal(err)
	}
	config, err := staticTLSConfig(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	current, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatalf("missing replacement interrupted handshakes: %v", err)
	}
	if !bytes.Equal(first.Certificate[0], current.Certificate[0]) {
		t.Fatal("missing replacement discarded the previous certificate")
	}
}

func TestStaticTLSReloadsReplacementWithPreservedMetadata(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	generate := func(cert, key string) {
		t.Helper()
		if err := certutil.Generate(cert, key, certutil.Options{Hosts: []string{"vpn.example.com"}}); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{cert, key} {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, bytes.Repeat([]byte("\n"), 4096-len(data))...)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			when := time.Unix(1_700_000_000, 0)
			if err := os.Chtimes(path, when, when); err != nil {
				t.Fatal(err)
			}
		}
	}
	generate(certPath, keyPath)
	config, err := staticTLSConfig(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey := filepath.Join(directory, "new.crt"), filepath.Join(directory, "new.key")
	generate(newCert, newKey)
	if err := os.Rename(newCert, certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(newKey, keyPath); err != nil {
		t.Fatal(err)
	}
	second, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("atomic replacement with identical size and mtime was not reloaded")
	}
}

func TestDownloadsRejectSpecialFilesWithoutBlocking(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"SHA256SUMS", "CLIENT_VERSION", "porta-client-linux-amd64"} {
		if err := unix.Mkfifo(filepath.Join(directory, name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler := clientDownloadHandler(http.NotFoundHandler(), directory)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/download/SHA256SUMS", nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("FIFO download status = %d", response.Code)
		}
		if version := readDownloadVersion(directory); version != "Unknown" {
			t.Errorf("FIFO version = %q", version)
		}
		if artifacts := availableDownloads(directory); len(artifacts) != 0 {
			t.Errorf("published FIFO artifacts = %#v", artifacts)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("opening a published FIFO blocked")
	}
}
