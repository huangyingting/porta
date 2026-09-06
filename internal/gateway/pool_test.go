package gateway

import (
	"context"
	"errors"
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
	reused, err := pool.Acquire("client-b")
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

func TestPoolReclaimsOldestInactiveLeaseWhenFull(t *testing.T) {
	pool, err := NewPool("10.66.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.Acquire("client-a")
	if err != nil {
		t.Fatal(err)
	}
	pool.Release(first)
	second, err := pool.Acquire("client-b")
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

func TestPersistentPoolPreservesReclamationOrder(t *testing.T) {
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
	reclaimed, err := restarted.Acquire("client-f")
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.Address != second.Address {
		t.Fatalf("reclaimed address = %s, want oldest inactive address %s", reclaimed.Address, second.Address)
	}
}
