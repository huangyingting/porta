package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPoolRejectsSupersededLeaseRegistration(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		pool, err := NewPool("10.66.0.0/30")
		if err != nil {
			t.Fatal(err)
		}
		router := NewRouter(testPacketDevice{}, nil)
		acquire := func(group string) Lease {
			t.Helper()
			var lease Lease
			if grouped {
				lease, err = pool.AcquireGroup("client-a", group)
			} else {
				lease, err = pool.Acquire("client-a")
			}
			if err != nil {
				t.Fatal(err)
			}
			return lease
		}
		first := acquire("first-session")
		second := acquire("second-session")
		var currentCtx context.Context
		register := func(lease Lease, group string) bool {
			return pool.registerLease(lease, func() {
				var session *Session
				var ctx context.Context
				if grouped {
					session, ctx, _, err = router.RegisterGroup(context.Background(), lease.Address, group, 0, 2, "")
				} else {
					session, ctx = router.Register(context.Background(), lease.Address)
				}
				if err != nil {
					t.Fatal(err)
				}
				if group == "second-session" {
					currentCtx = ctx
				}
				t.Cleanup(session.Close)
			})
		}
		if !register(second, "second-session") {
			t.Fatal("current lease registration rejected")
		}
		if register(first, "first-session") {
			t.Errorf("stale lease replaced current routed session (grouped=%t)", grouped)
		}
		pool.Release(first)
		if currentCtx.Err() != nil {
			pool.Release(second)
		}
		if _, err := pool.Acquire("client-b"); !errors.Is(err, ErrPoolExhausted) {
			t.Errorf("replacement cleanup freed a still-routed address (grouped=%t): %v", grouped, err)
		}
	}
}

func TestPoolRegistrationSerializesReconnect(t *testing.T) {
	pool, err := NewPool("10.66.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	registered := make(chan bool, 1)
	go func() {
		registered <- pool.registerLease(lease, func() {
			close(entered)
			<-release
		})
	}()
	<-entered
	started, acquired := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		_, err := pool.Acquire("client-a")
		acquired <- err
	}()
	<-started
	completedEarly := false
	select {
	case err := <-acquired:
		completedEarly = true
		t.Errorf("reconnect superseded lease during router registration: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if !<-registered {
		t.Fatal("current lease was rejected")
	}
	if !completedEarly {
		if err := <-acquired; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPoolReconnectKeepsAddressAndOldReleaseIsIgnored(t *testing.T) {
	pool, err := NewPool("10.66.0.0/29")
	if err != nil {
		t.Fatal(err)
	}

	first, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}

	second, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	if first.Address != second.Address {
		t.Fatalf("reconnect address changed from %s to %s", first.Address, second.Address)
	}
	pool.Release(first)
	third, err := pool.Acquire("client-b")
	if err != nil {
		t.Fatal(err)
	}
	if third.Address == second.Address {
		t.Fatal("stale release freed the active reconnect lease")
	}
}

func TestPoolGroupStaysActiveUntilLastLaneReleases(t *testing.T) {
	pool, err := NewPool("10.66.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.AcquireGroup("client-a", "session-12345678")
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.AcquireGroup("client-a", "session-12345678")
	if err != nil {
		t.Fatal(err)
	}
	if first.Address != second.Address || first.generation != second.generation {
		t.Fatal("lanes in one group did not share a lease generation")
	}

	pool.Release(first)
	if _, err := pool.Acquire("client-b"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("partially active group allowed address reuse: %v", err)
	}

	pool.Release(second)
	if _, err := pool.Acquire("client-b"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("disconnected identity reservation was transferred: %v", err)
	}
	reused, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	if reused.Address != first.Address {
		t.Fatalf("reused address = %s, want %s", reused.Address, first.Address)
	}
}

func TestPoolReconnectAfterDisconnectKeepsAddress(t *testing.T) {
	pool, err := NewPool("10.66.0.0/29")
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	pool.Release(first)
	if _, err := pool.Acquire("client-b"); err != nil {
		t.Fatal(err)
	}
	reconnected, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	if reconnected.Address != first.Address {
		t.Fatalf("reconnect address changed from %s to %s", first.Address, reconnected.Address)
	}
}

func TestPoolKeepsInactiveLeaseIdentitySpecificWhenFull(t *testing.T) {
	pool, err := NewPool("10.66.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	pool.Release(first)
	if _, err := pool.Acquire("client-b"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("full pool transferred an inactive reservation: %v", err)
	}
	second, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	if second.Address != first.Address {
		t.Fatalf("reclaimed address = %s, want %s", second.Address, first.Address)
	}
}

func TestPersistentPoolRestoresLeaseAcrossRestart(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leases.json")
	firstPool, err := NewPersistentPool("10.66.0.0/29", statePath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstPool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}

	secondPool, err := NewPersistentPool("10.66.0.0/29", statePath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondPool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	if second.Address != first.Address {
		t.Fatalf("restored address = %s, want %s", second.Address, first.Address)
	}
}

func TestPersistentPoolRejectsInvalidClientBeforeMutation(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leases.json")
	pool, err := NewPersistentPool("10.66.0.0/29", statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Acquire(""); err == nil {
		t.Fatal("empty client ID was accepted")
	}
	if _, err := pool.AcquireGroup("invalid client", "session-12345678"); err == nil {
		t.Fatal("invalid grouped client ID was accepted")
	}
	if _, err := pool.Acquire("client-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistentPool("10.66.0.0/29", statePath); err != nil {
		t.Fatalf("invalid acquisition corrupted persistent state: %v", err)
	}
}

func TestPersistentPoolPreservesIdentityReservations(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leases.json")
	firstPool, err := NewPersistentPool("10.66.0.0/29", statePath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstPool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	firstPool.Release(first)
	second, err := firstPool.Acquire("client-b")
	if err != nil {
		t.Fatal(err)
	}
	firstPool.Release(second)
	for _, clientID := range []string{"client-c", "client-d", "client-e"} {
		lease, acquireErr := firstPool.Acquire(clientID)
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
		firstPool.Release(lease)
	}
	refreshed, err := firstPool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	firstPool.Release(refreshed)

	restarted, err := NewPersistentPool("10.66.0.0/29", statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Acquire("client-f"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("restarted pool transferred an inactive reservation: %v", err)
	}
	reclaimed, err := restarted.Acquire("client-b")
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.Address != second.Address {
		t.Fatalf("restored address = %s, want %s", reclaimed.Address, second.Address)
	}
}

func TestPoolCommittedReservationSurvivesDirectorySyncFailure(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "replacement"}[replacement], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "leases.json")
			pool, err := NewPersistentPool("10.66.0.0/30", path)
			if err != nil {
				t.Fatal(err)
			}
			var old []Lease
			if replacement {
				for range 2 {
					lease, err := pool.AcquireGroup("a", "old")
					if err != nil {
						t.Fatal(err)
					}
					old = append(old, lease)
				}
			}
			_, err = pool.acquireWithSync("a", "new", func(string) error { return os.ErrPermission })
			if !errors.Is(err, ErrLeaseDurability) || !errors.Is(err, os.ErrPermission) {
				t.Fatalf("post-commit error = %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var disk poolState
			if err := json.Unmarshal(data, &disk); err != nil {
				t.Fatal(err)
			}
			record := pool.byClient["a"]
			if record.active || record.address.String() != disk.Leases["a"].Address || record.generation != disk.Leases["a"].Generation || len(pool.groups) != 0 {
				t.Fatal("committed disk state was rolled back or activated")
			}
			for _, lease := range old {
				if pool.registerLease(lease, func() { t.Error("stale lease registered") }) {
					t.Fatal("post-commit failure revived a stale group")
				}
				pool.Release(lease)
			}
			if _, err := pool.Acquire("b"); !errors.Is(err, ErrPoolExhausted) {
				t.Fatalf("committed reservation was reused: %v", err)
			}
			recovered, err := pool.AcquireGroup("a", "new")
			if err != nil || recovered.generation <= record.generation || recovered.Address != record.address {
				t.Fatalf("reservation could not recover: %+v %v", recovered, err)
			}
			for _, lease := range old {
				pool.Release(lease)
			}
			if !pool.registerLease(recovered, func() {}) {
				t.Fatal("stale release disabled recovered generation")
			}
			reopened, err := NewPersistentPool("10.66.0.0/30", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reopened.Acquire("b"); !errors.Is(err, ErrPoolExhausted) {
				t.Fatal("reservation lost on restart")
			}
		})
	}
}

func TestPoolPrecommitFailurePreservesGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	pool, err := NewPersistentPool("10.66.0.0/29", path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.AcquireGroup("a", "old")
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.AcquireGroup("a", "old")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	for _, client := range []string{"a", "b"} {
		if _, err := pool.AcquireGroup(client, "new"); err == nil || errors.Is(err, ErrLeaseDurability) {
			t.Fatalf("rename failure misclassified: %v", err)
		}
		if len(pool.byClient) != 1 || len(pool.byAddr) != 1 || pool.groups["a"].references != 2 {
			t.Fatal("precommit failure corrupted old group")
		}
	}
	pool.Release(first)
	if !pool.registerLease(second, func() {}) {
		t.Fatal("precommit failure did not preserve old generation")
	}
}
