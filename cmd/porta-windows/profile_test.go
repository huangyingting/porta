//go:build windows

package main

import (
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/clientprofile"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/rodrigocfd/windigo/win"
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

func TestConnectionPresentationMatchesState(t *testing.T) {
	style := &visualStyle{muted: 1, accent: 2, warning: 3, danger: 4}
	app := &application{style: style}
	for _, test := range []struct {
		event  clientapp.Event
		title  string
		detail string
		color  win.COLORREF
	}{
		{
			event: clientapp.Event{
				State: clientapp.StateConnected, Transport: tunnel.TransportHTTP3,
				Lease: tunnel.Lease{MTU: 1280},
			},
			title: "Connected", detail: "HTTP/3 MASQUE · Fast and resilient · MTU 1280", color: style.accent,
		},
		{
			event:  clientapp.Event{State: clientapp.StateConfiguring},
			title:  "Configuring network",
			detail: "Applying private routes, DNS, and tunnel MTU…",
			color:  style.warning,
		},
		{
			event:  clientapp.Event{State: clientapp.StateError},
			title:  "Connection error",
			detail: "Review the activity log, then try again.",
			color:  style.danger,
		},
	} {
		title, detail, color := app.connectionPresentation(test.event)
		if title != test.title || detail != test.detail || color != test.color {
			t.Fatalf("state %q = %q, %q, %d", test.event.State, title, detail, color)
		}
	}
}
