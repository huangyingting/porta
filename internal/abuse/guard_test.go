package abuse

import (
	"net/netip"
	"testing"
	"time"
)

func testGuard(t *testing.T, now *time.Time, maxEntries int, rejected *int) *Guard {
	t.Helper()
	guard, err := New(
		map[Surface]Policy{
			NativeAuthentication: {Burst: 2, RefillInterval: time.Second},
			ProxyAuthentication:  {Burst: 2, RefillInterval: time.Second},
			PortalAuthentication: {Burst: 2, RefillInterval: time.Second},
			InvitationRedemption: {Burst: 2, RefillInterval: time.Second},
		},
		maxEntries,
		time.Minute,
		func() time.Time { return *now },
		func(Surface) { (*rejected)++ },
	)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func TestGuardRetainsFailuresAndRefills(t *testing.T) {
	now := time.Unix(100, 0)
	rejected := 0
	guard := testGuard(t, &now, 8, &rejected)
	address := netip.MustParseAddr("192.0.2.1")

	for range 2 {
		if _, ok := guard.Reserve(PortalAuthentication, address); !ok {
			t.Fatal("initial burst was rejected")
		}
	}
	if _, ok := guard.Reserve(PortalAuthentication, address); ok || rejected != 1 {
		t.Fatal("exhausted bucket was not rejected")
	}
	now = now.Add(time.Second)
	if _, ok := guard.Reserve(PortalAuthentication, address); !ok {
		t.Fatal("refilled bucket was rejected")
	}
}

func TestGuardRefundDoesNotPenalizeSuccess(t *testing.T) {
	now := time.Unix(100, 0)
	rejected := 0
	guard := testGuard(t, &now, 8, &rejected)
	address := netip.MustParseAddr("192.0.2.2")
	for range 20 {
		refund, ok := guard.Reserve(NativeAuthentication, address)
		if !ok {
			t.Fatal("successful authentication exhausted the limiter")
		}
		refund()
		refund()
	}
}

func TestGuardBoundsEntriesAndIsolatesSurfaces(t *testing.T) {
	now := time.Unix(100, 0)
	rejected := 0
	guard := testGuard(t, &now, 1, &rejected)
	first := netip.MustParseAddr("192.0.2.3")
	second := netip.MustParseAddr("192.0.2.4")
	if _, ok := guard.Reserve(PortalAuthentication, first); !ok {
		t.Fatal("first address rejected")
	}
	for range 2 {
		if _, ok := guard.Reserve(PortalAuthentication, second); !ok {
			t.Fatal("overflow burst rejected too early")
		}
	}
	if _, ok := guard.Reserve(PortalAuthentication, second); ok {
		t.Fatal("overflow bucket did not enforce its bound")
	}
	if _, ok := guard.Reserve(ProxyAuthentication, second); !ok {
		t.Fatal("one surface exhausted another surface")
	}
	if len(guard.entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(guard.entries))
	}
}

func TestGuardThrottlesFullMapPruning(t *testing.T) {
	now := time.Unix(100, 0)
	rejected := 0
	guard := testGuard(t, &now, 1, &rejected)
	first := netip.MustParseAddr("192.0.2.10")
	if _, ok := guard.Reserve(PortalAuthentication, first); !ok {
		t.Fatal("first address rejected")
	}
	if _, ok := guard.Reserve(PortalAuthentication, netip.MustParseAddr("192.0.2.11")); !ok {
		t.Fatal("overflow address rejected")
	}
	nextPrune := guard.nextPrune
	if !nextPrune.Equal(now.Add(time.Minute)) {
		t.Fatalf("next prune = %v", nextPrune)
	}
	for index := 12; index < 40; index++ {
		guard.Reserve(PortalAuthentication, netip.AddrFrom4([4]byte{192, 0, 2, byte(index)}))
		if !guard.nextPrune.Equal(nextPrune) {
			t.Fatal("source churn rescheduled a full-map prune")
		}
	}
	now = nextPrune
	replacement := netip.MustParseAddr("192.0.2.100")
	if _, ok := guard.Reserve(PortalAuthentication, replacement); !ok {
		t.Fatal("expired entry was not reclaimed")
	}
	if len(guard.entries) != 1 || guard.entries[entryKey{surface: PortalAuthentication, address: replacement}] == nil {
		t.Fatal("expired entry was not replaced after the bounded prune interval")
	}
}
