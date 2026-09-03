package gateway

import "testing"

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
