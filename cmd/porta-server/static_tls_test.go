package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/huangyingting/porta/internal/certutil"
)

func TestStaticTLSReportsReloadFailuresAndRecoveryWithoutFlooding(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	if err := certutil.Generate(certPath, keyPath, certutil.Options{Hosts: []string{"vpn.example.com"}}); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	config, err := staticTLSConfig(certPath, keyPath, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	handshakes := func() {
		t.Helper()
		var pending sync.WaitGroup
		for range 32 {
			pending.Go(func() {
				current, err := config.GetCertificate(nil)
				if err != nil {
					t.Errorf("reload failure interrupted handshake: %v", err)
					return
				}
				if !bytes.Equal(first.Certificate[0], current.Certificate[0]) {
					t.Error("last-good certificate was discarded")
				}
			})
		}
		pending.Wait()
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	handshakes()
	if err := os.WriteFile(keyPath, []byte("incomplete replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	handshakes()
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	handshakes()
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	handshakes()

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected two distinct failures, one recovery and one recurrence; logs:\n%s", logs.String())
	}
	for index, expected := range []struct {
		level string
		err   string
	}{
		{"WARN", "stat TLS key"},
		{"WARN", "load TLS certificate"},
		{"INFO", ""},
		{"WARN", "stat TLS key"},
	} {
		var record struct {
			Level   string `json:"level"`
			Message string `json:"msg"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal([]byte(lines[index]), &record); err != nil {
			t.Fatal(err)
		}
		if record.Level != expected.level || !strings.Contains(record.Error, expected.err) {
			t.Fatalf("log %d = %#v, expected %#v", index, record, expected)
		}
		if expected.level == "INFO" && record.Message != "TLS certificate reload recovered" {
			t.Fatalf("missing recovery signal: %#v", record)
		}
		if expected.level == "WARN" && !strings.Contains(record.Message, "keeping previous certificate") {
			t.Fatalf("missing fallback signal: %#v", record)
		}
	}
}
