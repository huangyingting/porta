//go:build windows

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/clientprofile"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/huangyingting/porta/internal/winnetwork"
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
	for _, test := range []struct {
		event  clientapp.Event
		title  string
		detail string
		tone   string
	}{
		{
			event: clientapp.Event{
				State: clientapp.StateConnected, Transport: tunnel.TransportHTTP3,
				Lease: tunnel.Lease{MTU: 1280},
			},
			title: "Connected", detail: "HTTP/3 MASQUE - fast and resilient - MTU 1280", tone: "connected",
		},
		{
			event:  clientapp.Event{State: clientapp.StateConfiguring},
			title:  "Configuring network",
			detail: "Applying private routes, DNS, and tunnel MTU...",
			tone:   "warning",
		},
		{
			event:  clientapp.Event{State: clientapp.StateError},
			title:  "Connection error",
			detail: "Review Activity for details, then try again.",
			tone:   "danger",
		},
	} {
		display := connectionPresentation(test.event)
		if display.title != test.title || display.detail != test.detail || display.tone != test.tone {
			t.Fatalf("state %q = %+v", test.event.State, display)
		}
	}
}

type testProtector struct{}

func (testProtector) Protect(value []byte) ([]byte, error) { return append([]byte(nil), value...), nil }
func (testProtector) Unprotect(value []byte) ([]byte, error) {
	return append([]byte(nil), value...), nil
}

func newTestDesktopController(t *testing.T) (*DesktopController, *clientprofile.Store, clientprofile.Profile) {
	t.Helper()
	dir := t.TempDir()
	store, err := clientprofile.Open(filepath.Join(dir, "profiles.json"), testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := store.Save(clientprofile.Profile{
		Name: "Home", ServerURL: "https://porta.example", Transport: tunnel.TransportAuto,
		Reconnect: true, ReconnectMaxDelay: 30 * time.Second,
	}, "secret-client-token")
	if err != nil {
		t.Fatal(err)
	}
	network, err := winnetwork.NewRunner(filepath.Join(dir, "network-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	controller := newDesktopController(store, network, filepath.Join(dir, "porta.log"))
	controller.selectedID = profile.ID
	return controller, store, profile
}

func TestDesktopSnapshotNeverExposesProtectedToken(t *testing.T) {
	controller, _, _ := newTestDesktopController(t)
	data, err := json.Marshal(controller.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-client-token") || strings.Contains(string(data), `"token"`) {
		t.Fatalf("desktop snapshot exposed credential material: %s", data)
	}
}

func TestDesktopProfileEditKeepsStoredTokenWhenTokenIsBlank(t *testing.T) {
	controller, store, profile := newTestDesktopController(t)
	snapshot, err := controller.SaveProfile(ProfileInput{
		ID: profile.ID, Name: "Updated home", ServerURL: profile.ServerURL, Transport: string(profile.Transport),
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SelectedProfileID != profile.ID || snapshot.Profiles[0].Name != "Updated home" {
		t.Fatalf("profile edit not reflected in snapshot: %+v", snapshot)
	}
	token, err := store.Token(profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if token != "secret-client-token" {
		t.Fatalf("stored token changed to %q", token)
	}
}

func TestDesktopRejectsProfileChangesWhileConnected(t *testing.T) {
	controller, _, profile := newTestDesktopController(t)
	controller.mu.Lock()
	controller.running = true
	controller.activeID = profile.ID
	controller.mu.Unlock()
	if _, err := controller.SaveProfile(ProfileInput{
		ID: profile.ID, Name: profile.Name, ServerURL: profile.ServerURL, Transport: string(profile.Transport),
	}); err == nil {
		t.Fatal("profile edit succeeded while connected")
	}
	if _, err := controller.DeleteProfile(profile.ID); err == nil {
		t.Fatal("profile deletion succeeded while connected")
	}
}

func TestWindowCloseRequiresCompletedSafeExit(t *testing.T) {
	controller, _, _ := newTestDesktopController(t)
	controller.mu.Lock()
	controller.quitting = true
	controller.mu.Unlock()
	if controller.CanClose() {
		t.Fatal("window close was allowed while cleanup was still pending")
	}
	controller.mu.Lock()
	controller.allowClose = true
	controller.mu.Unlock()
	if !controller.CanClose() {
		t.Fatal("window close was blocked after safe exit was authorized")
	}
}

func TestResetConnectionClearsLiveDashboardValues(t *testing.T) {
	controller, _, _ := newTestDesktopController(t)
	controller.address = "10.0.0.2/32"
	controller.transport = string(tunnel.TransportHTTP3)
	controller.mtu = 1280
	controller.connectedAt = time.Now()
	controller.bytesUploaded = 100
	controller.bytesDownloaded = 200
	controller.uploadRate = 10
	controller.downloadRate = 20
	controller.resetConnectionLocked()
	if controller.address != "" || controller.transport != "" || controller.mtu != 0 ||
		!controller.connectedAt.IsZero() || controller.bytesUploaded != 0 || controller.bytesDownloaded != 0 ||
		controller.uploadRate != 0 || controller.downloadRate != 0 {
		t.Fatalf("live dashboard values were retained: %+v", controller.Snapshot())
	}
}

func TestFrontendUsesWailsBindingAndInlineEditor(t *testing.T) {
	script, err := frontend.ReadFile("frontend/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "Call.ByName") {
		t.Fatal("frontend does not use the Wails named binding API")
	}
	html, err := frontend.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, err := frontend.ReadFile("frontend/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "editor-scrim") ||
		strings.Contains(string(stylesheet), ".editor-panel { position: fixed") {
		t.Fatal("profile editor regressed to a modal overlay")
	}
}
