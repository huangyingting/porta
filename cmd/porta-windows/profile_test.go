//go:build windows

package main

import (
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/clientprofile"
	"github.com/huangyingting/porta/internal/tunnel"
)

func TestProfileWithFieldsPreservesHiddenSettings(t *testing.T) {
	original := clientprofile.Profile{
		ID: "work", CAPath: "private-ca.pem", Thumbprint: "pinned-certificate",
		Reconnect: false, ReconnectMaxDelay: 10 * time.Second, CreatedAt: time.Now(),
	}
	fields := clientprofile.Profile{
		ID: "work", Name: "Updated", ServerURL: "https://gateway", Transport: tunnel.TransportHTTP2,
	}
	got := profileWithFields(original, fields)
	if got.CAPath != original.CAPath || got.Thumbprint != original.Thumbprint ||
		got.Reconnect != original.Reconnect || got.ReconnectMaxDelay != original.ReconnectMaxDelay ||
		got.CreatedAt != original.CreatedAt {
		t.Fatalf("hidden settings changed: %+v", got)
	}
	if got.Name != fields.Name || got.ServerURL != fields.ServerURL || got.Transport != fields.Transport {
		t.Fatalf("visible settings not updated: %+v", got)
	}
}

func TestNewProfileDefaults(t *testing.T) {
	got := profileWithFields(clientprofile.Profile{}, clientprofile.Profile{Name: "New"})
	if !got.Reconnect || got.ReconnectMaxDelay != 30*time.Second {
		t.Fatalf("new profile defaults: %+v", got)
	}
}

func TestTransportSelectionPreservesExplicitProfiles(t *testing.T) {
	for _, transport := range []tunnel.Transport{tunnel.TransportAuto, tunnel.TransportHTTP3, tunnel.TransportHTTP2} {
		if got := selectedTransport(transportIndex(transport)); got != transport {
			t.Errorf("transport %q became %q", transport, got)
		}
	}
	if got := selectedTransport(0); got != tunnel.TransportAuto {
		t.Fatalf("new profile transport = %q", got)
	}
}
