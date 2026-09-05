package usage

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}

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

func TestSnapshotKeepsByteAndPacketCountersConsistent(t *testing.T) {
	store, err := Open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	session := store.Begin("", "account", "phone", "masque-h3-datagram", "10.66.0.2", "")
	const updates = 10_000
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for range updates {
			session.AddUploaded(2, 1)
		}
	}()
	for range updates {
		device := Device(store.Snapshot(), "account", "phone")
		if device.BytesUploaded != device.PacketsUploaded*2 {
			t.Fatalf(
				"inconsistent snapshot: bytes=%d packets=%d",
				device.BytesUploaded,
				device.PacketsUploaded,
			)
		}
	}
	wait.Wait()
	session.Close()
}

func TestDeletedSessionCannotCloseReplacement(t *testing.T) {
	for _, deleteClient := range []bool{false, true} {
		store, _ := Open("", nil)
		old := store.Begin("shared-key", "account", "phone", "", "", "")
		if deleteClient {
			store.DeleteClient("account")
		} else {
			store.DeleteDevice("account", "phone")
		}
		replacement := store.Begin("shared-key", "account", "phone", "", "", "")
		old.Close()
		old.AddUploaded(100, 1)
		replacement.AddUploaded(7, 1)
		got := Device(store.Snapshot(), "account", "phone")
		if got.ActiveSessions != 1 || got.BytesUploaded != 7 {
			t.Fatalf("deleteClient=%v: replacement usage = %#v", deleteClient, got)
		}
		replacement.Close()
	}
}

func TestGeneratedSessionKeyDoesNotCollide(t *testing.T) {
	store, _ := Open("", nil)
	explicit := store.Begin("session-1", "account", "phone", "", "", "")
	generated := store.Begin("", "account", "laptop", "", "", "")
	defer explicit.Close()
	defer generated.Close()
	if got := Device(store.Snapshot(), "account", "laptop"); got.ActiveSessions != 1 {
		t.Fatalf("generated session merged with explicit key: %#v", got)
	}
}

func TestUsageKeepsLatestConnectionMetadata(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "usage.json"), nil)
	older := store.Begin("older", "account", "phone", "old", "", "old:443")
	newer := store.Begin("newer", "account", "phone", "new", "", "new:443")
	older.state.connectedAt = time.Unix(100, 0).UTC()
	newer.state.connectedAt = time.Unix(200, 0).UTC()
	assertLatest := func(snapshot Snapshot) {
		t.Helper()
		got := Device(snapshot, "account", "phone")
		if got.LastConnected == nil || !got.LastConnected.Equal(newer.state.connectedAt) ||
			got.Transport != "new" || got.Target != "new:443" {
			t.Fatalf("latest connection metadata = %#v", got)
		}
	}
	for range 100 {
		assertLatest(store.Snapshot())
	}
	newer.Close()
	assertLatest(store.Snapshot())
	older.Close()
	assertLatest(store.Snapshot())
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(store.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertLatest(reopened.Snapshot())
}

func TestSnapshotDoesNotShareStoredTimestamps(t *testing.T) {
	store, _ := Open("", nil)
	session := store.Begin("", "account", "phone", "", "", "")
	session.Close()
	original := Device(store.Snapshot(), "account", "phone")
	connected, disconnected := *original.LastConnected, *original.LastDisconnected
	*original.LastConnected = time.Time{}
	*original.LastDisconnected = time.Time{}
	got := Device(store.Snapshot(), "account", "phone")
	if !got.LastConnected.Equal(connected) || !got.LastDisconnected.Equal(disconnected) {
		t.Fatal("snapshot mutation changed stored timestamps")
	}
}

func TestConcurrentSessionsSnapshotAndCheckpointPreserveTotals(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "usage.json"), nil)
	const lanes, updates = 8, 1000
	var writers sync.WaitGroup
	start := make(chan struct{})
	for range lanes {
		session := store.Begin("multi-lane", "account", "phone", "", "", "")
		writers.Go(func() {
			defer session.Close()
			<-start
			for range updates {
				session.AddUploaded(2, 1)
				session.AddDownloaded(3, 1)
			}
		})
	}
	close(start)
	for range 20 {
		device := Device(store.Snapshot(), "account", "phone")
		if device.BytesUploaded != 2*device.PacketsUploaded || device.BytesDownloaded != 3*device.PacketsDownloaded {
			t.Fatalf("inconsistent live totals: %#v", device)
		}
		if err := store.persist(); err != nil {
			t.Fatal(err)
		}
	}
	writers.Wait()
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(store.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := Device(reopened.Snapshot(), "account", "phone")
	if got.ActiveSessions != 0 || got.ConnectionsTotal != 1 ||
		got.BytesUploaded != lanes*updates*2 || got.BytesDownloaded != lanes*updates*3 ||
		got.PacketsUploaded != lanes*updates || got.PacketsDownloaded != lanes*updates {
		t.Fatalf("lost concurrent updates: %#v", got)
	}
}

func TestConcurrentAccountingOnSingleConnectionIsExact(t *testing.T) {
	store, _ := Open("", nil)
	session := store.Begin("", "account", "phone", "", "", "")
	const writers, updates = 16, 2000
	var wait sync.WaitGroup
	var completed atomic.Int64
	start := make(chan struct{})
	for range writers {
		wait.Go(func() {
			defer completed.Add(1)
			<-start
			for range updates {
				session.AddUploaded(2, 1)
				session.AddDownloaded(3, 1)
			}
		})
	}
	close(start)
	for {
		device := Device(store.Snapshot(), "account", "phone")
		if device.BytesUploaded != 2*device.PacketsUploaded ||
			device.BytesDownloaded != 3*device.PacketsDownloaded {
			t.Fatalf("inconsistent live counters: %#v", device)
		}
		if completed.Load() == writers {
			break
		}
	}
	wait.Wait()
	session.Close()
	got := Device(store.Snapshot(), "account", "phone")
	if got.BytesUploaded != writers*updates*2 ||
		got.BytesDownloaded != writers*updates*3 ||
		got.PacketsUploaded != writers*updates ||
		got.PacketsDownloaded != writers*updates {
		t.Fatalf("concurrent totals = %#v", got)
	}
}

func TestRunCoalescesCompletedSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	store, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int64
	written := make(chan struct{}, 2)
	store.persistenceDelay = time.Millisecond
	store.writeState = func(path string, data []byte) error {
		if err := writeStateAtomically(path, data); err != nil {
			return err
		}
		writes.Add(1)
		written <- struct{}{}
		return nil
	}
	const connections = 100
	for i := range connections {
		session := store.Begin("", "account", "phone", "https-connect", "", "")
		session.AddUploaded(uint64(i+1), 1)
		session.Close()
	}
	if got := writes.Load(); got != 0 {
		t.Fatalf("session Close performed %d synchronous writes", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := store.Run(ctx, time.Hour); err != nil {
			t.Errorf("Run: %v", err)
		}
		close(done)
	}()
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("coalesced persistence did not run")
	}
	cancel()
	<-done
	if got := writes.Load(); got != 1 {
		t.Fatalf("writes = %d, want one coalesced write", got)
	}
	reopened, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := Device(reopened.Snapshot(), "account", "phone")
	if got.ConnectionsTotal != connections ||
		got.BytesUploaded != connections*(connections+1)/2 ||
		got.PacketsUploaded != connections {
		t.Fatalf("coalesced persisted usage = %#v", got)
	}
}

func TestRunFinalFlushPersistsPendingUsage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	store, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.persistenceDelay = time.Hour
	session := store.Begin("", "account", "phone", "", "", "")
	session.AddDownloaded(8192, 4)
	session.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Run(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := Device(reopened.Snapshot(), "account", "phone")
	if got.ConnectionsTotal != 1 || got.BytesDownloaded != 8192 || got.PacketsDownloaded != 4 {
		t.Fatalf("shutdown-flushed usage = %#v", got)
	}
}

func TestFlushErrorCanBeRetriedWithoutLosingUsage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	store, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	session := store.Begin("", "account", "phone", "", "", "")
	session.AddUploaded(1234, 2)
	session.Close()

	writeError := errors.New("injected write failure")
	writes := 0
	store.writeState = func(path string, data []byte) error {
		writes++
		if writes == 1 {
			return writeError
		}
		return writeStateAtomically(path, data)
	}
	if err := store.Flush(); !errors.Is(err, writeError) {
		t.Fatalf("first Flush error = %v, want %v", err, writeError)
	}
	if err := store.Flush(); err != nil {
		t.Fatalf("retry Flush: %v", err)
	}
	if writes != 2 {
		t.Fatalf("write attempts = %d, want 2", writes)
	}
	reopened, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := Device(reopened.Snapshot(), "account", "phone")
	if got.ConnectionsTotal != 1 || got.BytesUploaded != 1234 || got.PacketsUploaded != 2 {
		t.Fatalf("retried usage = %#v", got)
	}
}

func TestRunReturnsFinalFlushError(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "usage.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	session := store.Begin("", "account", "phone", "", "", "")
	session.AddUploaded(1, 1)
	session.Close()
	writeError := errors.New("injected shutdown failure")
	store.writeState = func(string, []byte) error { return writeError }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Run(ctx, time.Hour); !errors.Is(err, writeError) {
		t.Fatalf("Run error = %v, want %v", err, writeError)
	}
}

func BenchmarkSessionAddUploaded(b *testing.B) {
	for _, snapshots := range []bool{false, true} {
		name := "updates"
		if snapshots {
			name = "with-snapshots"
		}
		b.Run(name, func(b *testing.B) {
			store, _ := Open("", nil)
			session := store.Begin("", "account", "phone", "", "", "")
			b.Cleanup(session.Close)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					session.AddUploaded(1200, 1)
					i++
					if snapshots && i%128 == 0 {
						store.Snapshot()
					}
				}
			})
		})
	}
}
