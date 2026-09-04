package usage

import (
	"path/filepath"
	"testing"
)

func TestStoreCollapsesMultiLaneSessionAndPersistsTotals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	store, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := store.Begin("vpn:account:phone:session", "account", "phone", "HTTP/2.0", "10.66.0.2", "")
	second := store.Begin("vpn:account:phone:session", "account", "phone", "HTTP/2.0", "10.66.0.2", "")
	first.AddUploaded(120, 2)
	second.AddDownloaded(340, 3)

	live := Device(store.Snapshot(), "account", "phone")
	if live.ActiveSessions != 1 || live.ConnectionsTotal != 1 || live.BytesUploaded != 120 || live.BytesDownloaded != 340 {
		t.Fatalf("live usage = %#v", live)
	}
	first.Close()
	if got := Device(store.Snapshot(), "account", "phone").ActiveSessions; got != 1 {
		t.Fatalf("active sessions after first lane closed = %d, want 1", got)
	}
	second.Close()

	reopened, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	persisted := Device(reopened.Snapshot(), "account", "phone")
	if persisted.ActiveSessions != 0 || persisted.ConnectionsTotal != 1 ||
		persisted.BytesUploaded != 120 || persisted.BytesDownloaded != 340 ||
		persisted.PacketsUploaded != 2 || persisted.PacketsDownloaded != 3 {
		t.Fatalf("persisted usage = %#v", persisted)
	}
	if persisted.LastConnected == nil || persisted.LastDisconnected == nil {
		t.Fatalf("persisted timestamps = %#v", persisted)
	}
}

func TestStoreAggregatesClientAndDeletesDevice(t *testing.T) {
	store, err := Open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	phone := store.Begin("", "account", "phone", "masque-h3-datagram", "10.66.0.2", "")
	laptop := store.Begin("", "account", "laptop", "https-connect", "", "example.com:443")
	phone.AddUploaded(10, 1)
	laptop.AddDownloaded(20, 0)

	snapshot := store.Snapshot()
	client := snapshot.Clients["account"]
	if client.ActiveSessions != 2 || client.ConnectionsTotal != 2 ||
		client.BytesUploaded != 10 || client.BytesDownloaded != 20 {
		t.Fatalf("client usage = %#v", client)
	}
	phone.Close()
	laptop.Close()
	store.DeleteDevice("account", "phone")
	if got := Device(store.Snapshot(), "account", "phone"); got.DeviceID != "" {
		t.Fatalf("deleted device usage = %#v", got)
	}
}

func TestStoreCheckpointIncludesActiveTraffic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	store, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	session := store.Begin("", "account", "phone", "HTTP/2.0", "10.66.0.2", "")
	session.AddUploaded(4096, 8)
	err = store.persist()
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	device := Device(reopened.Snapshot(), "account", "phone")
	if device.ActiveSessions != 0 || device.ConnectionsTotal != 1 ||
		device.BytesUploaded != 4096 || device.PacketsUploaded != 8 {
		t.Fatalf("checkpointed usage = %#v", device)
	}
	session.Close()
}
