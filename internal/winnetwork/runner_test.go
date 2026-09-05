package winnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/huangyingting/porta/internal/tunnel"
)

type fakeGuard struct {
	replace func(context.Context, guardSpec) error
	remove  func(context.Context, string) error
	luid    uint64
}

func (g *fakeGuard) Replace(ctx context.Context, spec guardSpec) error {
	if g.replace != nil {
		return g.replace(ctx, spec)
	}
	return nil
}
func (g *fakeGuard) Remove(ctx context.Context, key string) error {
	if g.remove != nil {
		return g.remove(ctx, key)
	}
	return nil
}
func (g *fakeGuard) InterfaceLUID(string) (uint64, error) {
	if g.luid != 0 {
		return g.luid, nil
	}
	return 77, nil
}
func (g *fakeGuard) InterfaceGUID(uint64) (string, error) {
	return "{77777777-7777-7777-7777-777777777777}", nil
}

func testRunner(t *testing.T) *Runner {
	t.Helper()
	runner, err := NewRunner(filepath.Join(t.TempDir(), "network-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner.guard = &fakeGuard{}
	runner.runCommand = func(context.Context, ...string) (string, error) { return "", nil }
	t.Cleanup(func() {
		runner.mu.Lock()
		defer runner.mu.Unlock()
		if err := runner.releaseLocked(); err != nil {
			t.Error(err)
		}
	})
	return runner
}

func testLease() tunnel.Lease {
	return tunnel.Lease{Address: netip.MustParsePrefix("10.0.0.2/24"), DNS: netip.MustParseAddr("1.1.1.1"), MTU: 1280}
}

func testRemote() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
}

func TestNetworkHelperUsesCompleteScriptFile(t *testing.T) {
	path, err := writeNetworkScript(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "\xef\xbb\xbf"+networkScript {
		t.Fatalf("network script content or Windows UTF-8 BOM is missing: %v", err)
	}
}

func TestActivationBeforeNetworkMutationAndNoUpdateGap(t *testing.T) {
	runner := testRunner(t)
	var calls []string
	runner.guard = &fakeGuard{
		replace: func(_ context.Context, spec guardSpec) error {
			var saved networkState
			data, err := os.ReadFile(runner.statePath)
			if err != nil || json.Unmarshal(data, &saved) != nil || saved.GuardKey != spec.Key {
				t.Fatal("guard activation preceded durable ownership")
			}
			calls = append(calls, "guard")
			return nil
		},
		remove: func(context.Context, string) error {
			calls = append(calls, "unguard")
			return nil
		},
	}
	runner.runCommand = func(_ context.Context, args ...string) (string, error) {
		if !runner.protected {
			t.Fatal("network changed before protection activation")
		}
		calls = append(calls, args[0])
		return "", nil
	}
	if runner.Protected() {
		t.Fatal("claimed protection before activation")
	}
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	lease := testLease()
	lease.Address = netip.MustParsePrefix("10.0.0.3/24")
	if err := runner.Reconfigure(context.Background(), "Porta", testRemote(), lease); err != nil {
		t.Fatal(err)
	}
	if want := []string{"guard", "prepare", "up", "guard", "prepare", "up"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("update opened protection gap: %v", calls)
	}
	if err := runner.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"down", "unguard"}; !reflect.DeepEqual(calls[len(calls)-2:], want) {
		t.Fatalf("release preceded route/DNS restoration: %v", calls)
	}
	if runner.Protected() {
		t.Fatal("protection remains after explicit release")
	}
}

func TestCancellationRetainsJournalAndProtectionUntilExplicitDown(t *testing.T) {
	runner := testRunner(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var owned networkState
	runner.runCommand = func(_ context.Context, args ...string) (string, error) {
		if args[0] == "up" {
			owned = runner.state
			owned.Routes = []routeState{{Kind: "escape", Prefix: "192.0.2.1/32", Interface: 7, GUID: "{11111111-1111-1111-1111-111111111111}", NextHop: "192.0.2.254", Metric: 1}}
			data, err := json.Marshal(owned)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(runner.statePath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			cancel()
			return "", context.Canceled
		}
		if args[0] == "down" {
			t.Fatal("automatic failure cleanup released protection")
		}
		return "", nil
	}
	err := runner.Up(ctx, "Porta", testRemote(), testLease())
	if !errors.Is(err, context.Canceled) || !runner.Protected() {
		t.Fatalf("cancellation error/protection: %v, %t", err, runner.Protected())
	}
	reopened, err := NewRunner(runner.statePath)
	if err != nil || !reflect.DeepEqual(reopened.state, owned) {
		t.Fatalf("crash recovery lost ownership: %v", err)
	}
	if reopened.Protected() {
		t.Fatal("journal alone is not activation proof")
	}
	reopened.guard = &fakeGuard{}
	reopened.runCommand = func(context.Context, ...string) (string, error) { return "", nil }
	// Simulate process death: the OS releases the ownership handle, but neither
	// the WFP objects nor the journal are removed.
	if err := runner.releaseLocked(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runner.statePath+".pending", []byte("interrupted journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(runner.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains after intentional release: %v", err)
	}
	if _, err := os.Stat(runner.statePath + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending journal remains after intentional release: %v", err)
	}
}

func TestPrepareFailureDoesNotClaimActivationOrChangeRoutes(t *testing.T) {
	runner := testRunner(t)
	runner.guard = &fakeGuard{replace: func(context.Context, guardSpec) error { return errors.New("WFP denied") }}
	runner.runCommand = func(context.Context, ...string) (string, error) {
		t.Fatal("network changed without confirmed guard")
		return "", nil
	}
	if err := runner.Prepare(context.Background(), "Porta", testRemote()); err == nil {
		t.Fatal("guard failure hidden")
	}
	if runner.Protected() {
		t.Fatal("claimed failed activation")
	}
	if _, err := os.Stat(runner.statePath); err != nil {
		t.Fatal("lost journal needed for uncertain WFP activation recovery")
	}
}

func TestUpDoesNotChangeNetworkWhenJournalCannotBeWritten(t *testing.T) {
	runner := testRunner(t)
	blocker := filepath.Join(filepath.Dir(runner.statePath), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner.statePath = filepath.Join(blocker, "state.json")
	runner.guard = &fakeGuard{replace: func(context.Context, guardSpec) error {
		t.Fatal("activated guard without journal")
		return nil
	}}
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err == nil {
		t.Fatal("unwritable journal accepted")
	}
	if runner.state.Interface != "" {
		t.Fatal("failed initial journal retained state")
	}
}

func TestDownPreservesStateOnEachCleanupFailure(t *testing.T) {
	for _, failure := range []string{"network", "guard"} {
		t.Run(failure, func(t *testing.T) {
			runner := testRunner(t)
			if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
				t.Fatal(err)
			}
			runner.runCommand = func(context.Context, ...string) (string, error) {
				if failure == "network" {
					return "", errors.New("access denied")
				}
				return "", nil
			}
			runner.guard = &fakeGuard{remove: func(context.Context, string) error {
				if failure == "network" {
					t.Fatal("removed guard after failed network restoration")
				}
				return errors.New("access denied")
			}}
			if err := runner.Down(context.Background()); err == nil {
				t.Fatal("cleanup error hidden")
			}
			if !runner.Protected() || runner.state.GuardKey == "" {
				t.Fatal("cleanup retry state/protection lost")
			}
			if _, err := os.Stat(runner.statePath); err != nil {
				t.Fatal("persistent cleanup state lost")
			}
		})
	}
}

func TestFailedCleanupReloadsRetiredOwnership(t *testing.T) {
	runner := testRunner(t)
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	runner.state.MTU = &mtuState{Original: 1500, Applied: 1100}
	if err := runner.persistLocked(); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("later cleanup failed")
	runner.runCommand = func(_ context.Context, args ...string) (string, error) {
		if args[0] == "down" {
			saved := runner.state
			saved.MTU = nil
			data, err := json.Marshal(saved)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(runner.statePath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			return "", failure
		}
		return "", nil
	}
	if err := runner.Down(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("cleanup error = %v", err)
	}
	if runner.state.MTU != nil || !runner.Protected() {
		t.Fatal("failed cleanup resurrected retired ownership or removed protection")
	}
	if err := runner.Prepare(context.Background(), "Porta", testRemote()); err != nil {
		t.Fatal(err)
	}
	saved, err := NewRunner(runner.statePath)
	if err != nil || saved.state.MTU != nil {
		t.Fatalf("reconnect rewrote stale MTU ownership: %v", err)
	}
}

func TestPrepareIPv6BeforeInterfaceExists(t *testing.T) {
	runner := testRunner(t)
	runner.guard = &fakeGuard{replace: func(_ context.Context, spec guardSpec) error {
		if !spec.Endpoint.IP.Is6() || spec.InterfaceLUID != 0 {
			t.Fatalf("incorrect initial IPv6 guard: %+v", spec)
		}
		return nil
	}}
	if err := runner.Prepare(context.Background(), "Porta", &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsMissingOrBypassingDNS(t *testing.T) {
	for _, dns := range []netip.Addr{{}, netip.MustParseAddr("::1"), netip.MustParseAddr("192.0.2.1")} {
		runner := testRunner(t)
		runner.guard = &fakeGuard{replace: func(context.Context, guardSpec) error {
			t.Fatal("invalid DNS accepted")
			return nil
		}}
		lease := testLease()
		lease.DNS = dns
		if err := runner.Up(context.Background(), "Porta", testRemote(), lease); err == nil {
			t.Fatalf("accepted DNS %s", dns)
		}
	}
}

func TestChangedInterfaceFailsClosed(t *testing.T) {
	runner := testRunner(t)
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	runner.guard = &fakeGuard{luid: 99, replace: func(context.Context, guardSpec) error {
		t.Fatal("silently changed protected interface identity")
		return nil
	}}
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err == nil || !runner.Protected() {
		t.Fatal("identity change did not fail closed")
	}
}

func TestRecoveryEndpointsAreLiteralAndIndependentOfActivationClaim(t *testing.T) {
	runner := testRunner(t)
	if len(runner.RecoveryEndpoints()) != 0 {
		t.Fatal("fresh runner has a recovery endpoint")
	}
	if err := runner.Prepare(context.Background(), "Porta", testRemote()); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewRunner(runner.statePath)
	if err != nil {
		t.Fatal(err)
	}
	endpoints := recovered.RecoveryEndpoints()
	if len(endpoints) != 1 || endpoints[0].String() != testRemote().String() || recovered.Protected() {
		t.Fatal("journal recovery either lost the pinned IP or falsely claimed activation")
	}
	endpoints[0].(*net.TCPAddr).IP[0] = 1
	if recovered.RecoveryEndpoints()[0].String() != testRemote().String() {
		t.Fatal("caller modified journal endpoint through returned slice")
	}
	recovered.state.Endpoint = endpoint{}
	if result := recovered.RecoveryEndpoints(); len(result) != 1 || result[0] != nil {
		t.Fatal("damaged guarded endpoint must stop bootstrap, not return an empty recovery list")
	}
}

func TestRecreatedTunnelIsReboundWithoutGuardRemoval(t *testing.T) {
	runner := testRunner(t)
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	var calls []string
	runner.guard = &fakeGuard{
		luid: 99,
		replace: func(_ context.Context, spec guardSpec) error {
			if spec.InterfaceLUID != 99 || !runner.protected {
				t.Fatal("replacement was not protected")
			}
			calls = append(calls, "guard")
			return nil
		},
		remove: func(context.Context, string) error {
			t.Fatal("retired guard during interface replacement")
			return nil
		},
	}
	runner.runCommand = func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args[0])
		if args[0] == "retire-interface" {
			runner.state.InterfaceLUID = 0
			return "", runner.persistLocked()
		}
		return "", nil
	}
	if err := runner.Reconfigure(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"retire-interface", "guard", "prepare", "up"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("unsafe rebind sequence: %v", calls)
	}
}

func TestCompetingRunnerCannotRemoveLiveGuard(t *testing.T) {
	owner := testRunner(t)
	other, err := NewRunner(owner.statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.releaseLocked() })
	other.guard = &fakeGuard{
		replace: func(context.Context, guardSpec) error {
			t.Fatal("competing runner replaced a live guard")
			return nil
		},
		remove: func(context.Context, string) error {
			t.Fatal("competing runner removed a live guard")
			return nil
		},
	}
	other.runCommand = func(context.Context, ...string) (string, error) {
		t.Fatal("competing runner changed live network state")
		return "", nil
	}
	if err := owner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	if err := other.Down(context.Background()); !errors.Is(err, ErrStateInUse) {
		t.Fatal("competing cleanup ignored ownership lock")
	}
	if err := other.Prepare(context.Background(), "Porta", testRemote()); err == nil {
		t.Fatal("competing preparation ignored ownership lock")
	}
	if err := owner.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := other.Down(context.Background()); err != nil {
		t.Fatalf("fresh state after owner's explicit cleanup: %v", err)
	}
}

func TestCrashLockRecoveryReloadsJournalBeforeMutation(t *testing.T) {
	owner := testRunner(t)
	other, err := NewRunner(owner.statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.releaseLocked() })
	other.guard = &fakeGuard{}
	other.runCommand = func(context.Context, ...string) (string, error) { return "", nil }
	if err := owner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	owned := routeState{Kind: "escape", Prefix: "192.0.2.1/32", Interface: 7, GUID: "{11111111-1111-1111-1111-111111111111}", NextHop: "192.0.2.254", Metric: 1}
	owner.state.Routes = []routeState{owned}
	if err := owner.persistLocked(); err != nil {
		t.Fatal(err)
	}
	if err := owner.releaseLocked(); err != nil {
		t.Fatal(err)
	}
	if err := other.Prepare(context.Background(), "Porta", testRemote()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(other.state.Routes, []routeState{owned}) || other.state.GuardKey != owner.state.GuardKey {
		t.Fatal("stale runner overwrote journal ownership after recovering the lock")
	}
}

func TestPreparePreservesJournaledDNSRouteKind(t *testing.T) {
	runner := testRunner(t)
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	dns := routeState{Kind: "dns", Prefix: "10.77.0.53/32", Interface: 77, GUID: runner.state.InterfaceGUID, NextHop: "0.0.0.0", Metric: 1}
	runner.state.Routes = []routeState{dns}
	if err := runner.persistLocked(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Prepare(context.Background(), "Porta", testRemote()); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewRunner(runner.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recovered.state.Routes, []routeState{dns}) {
		t.Fatal("preparation dropped the DNS route kind from the persistent journal")
	}
}

func TestHelperContainsNoBroadFirewallOrAddressCleanup(t *testing.T) {
	for _, forbidden := range []string{"Set-NetFirewallProfile", "New-NetFirewallRule", "Disable-NetAdapter", "SilentlyContinue", "Find-NetRoute"} {
		if strings.Contains(networkScript, forbidden) {
			t.Fatalf("helper contains unsafe/unreliable command %s", forbidden)
		}
	}
	if !strings.Contains(networkScript, "$file.Flush($true)") || !strings.Contains(networkScript, "[IO.File]::Replace") {
		t.Fatal("helper journal is not flushed and atomically replaced")
	}
}

func TestPrepareBlocksPayloadUntilInterfaceIsRevalidated(t *testing.T) {
	runner := testRunner(t)
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	previous := runner.state.InterfaceLUID
	runner.guard = &fakeGuard{replace: func(_ context.Context, spec guardSpec) error {
		if spec.InterfaceLUID != 0 {
			t.Fatal("pre-dial protection trusted a cached, possibly reused interface LUID")
		}
		return nil
	}}
	if err := runner.Prepare(context.Background(), "Porta", testRemote()); err != nil {
		t.Fatal(err)
	}
	if runner.state.InterfaceLUID != previous || !runner.NeedsCleanup() {
		t.Fatal("preparation discarded recovery ownership")
	}
}

func TestMTUIsValidatedAndPassedToWindows(t *testing.T) {
	for _, mtu := range []int{0, 575, 1100, 9001} {
		runner := testRunner(t)
		called := false
		runner.runCommand = func(_ context.Context, args ...string) (string, error) {
			if args[0] == "up" {
				called = true
				if len(args) != 5 || args[4] != "1100" {
					t.Fatalf("negotiated OS MTU not passed to helper: %v", args)
				}
			}
			return "", nil
		}
		lease := testLease()
		lease.MTU = mtu
		err := runner.Up(context.Background(), "Porta", testRemote(), lease)
		if (err == nil) != (mtu == 1100) || called != (mtu == 1100) {
			t.Fatalf("MTU %d: helper called=%t error=%v", mtu, called, err)
		}
	}
}
