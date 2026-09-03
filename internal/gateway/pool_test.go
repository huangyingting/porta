package gateway

import (
	"errors"
	"path/filepath"
	"testing"
)

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
