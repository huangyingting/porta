//go:build linux

package linuxnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/huangyingting/porta/internal/tunnel"
)

type fakeSystem struct {
	t          *testing.T
	path       string
	links      map[string]*linkInfo
	addresses  map[string][]string
	routes     map[string][]routeInfo
	tables     map[string]string
	dns        map[string]string
	domains    map[string]string
	commands   []string
	scripts    []string
	mutations  int
	failAt     int
	failAfter  bool
	failMatch  string
	customRule bool
}

var testSequence atomic.Uint64

func testDirectory(t *testing.T) string {
	t.Helper()
	// Keep all test state inside the project, never in the host's temp folders.
	path := fmt.Sprintf(".linuxnetwork-test-%d-%d", os.Getpid(), testSequence.Add(1))
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	return path
}

func newFake(t *testing.T) (*Runner, *fakeSystem) {
	t.Helper()
	path := filepath.Join(testDirectory(t), "network.json")
	runner, err := NewRunner(path)
	if err != nil {
		t.Fatal(err)
	}
	physical := &linkInfo{Index: 2, Name: "eth0", MTU: 1500, Flags: []string{"UP"}}
	tun := &linkInfo{Index: 10, Name: "porta0", MTU: 1500, Flags: []string{"POINTOPOINT"}}
	tun.LinkInfo.Kind = "tun"
	system := &fakeSystem{
		t: t, path: runner.statePath,
		links:     map[string]*linkInfo{"eth0": physical, "porta0": tun},
		addresses: map[string][]string{}, routes: map[string][]routeInfo{},
		tables: map[string]string{}, dns: map[string]string{}, domains: map[string]string{},
	}
	bindFake(runner, system)
	t.Cleanup(func() { _ = runner.releaseLock() })
	return runner, system
}

func bindFake(runner *Runner, system *fakeSystem) {
	runner.runCommand = system.run
	runner.checkDNS = func() error { return nil }
}

func testEndpoint() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 443}
}

func testLease() tunnel.Lease {
	return tunnel.Lease{
		Address: netip.MustParsePrefix("10.77.0.2/24"),
		Gateway: netip.MustParseAddr("10.77.0.1"),
		DNS:     netip.MustParseAddr("1.1.1.1"),
		MTU:     1280,
	}
}

func (s *fakeSystem) run(ctx context.Context, name string, args []string, input string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	command := name + " " + strings.Join(args, " ")
	s.commands = append(s.commands, command)
	if s.failMatch != "" && strings.Contains(command, s.failMatch) {
		return "", errors.New("injected command failure")
	}
	mutating := input != "" || (name == "ip" && !contains(args, "show") && !contains(args, "get")) ||
		(name == "resolvectl" && (args[0] == "revert" || len(args) > 2))
	fail := false
	if mutating {
		s.mutations++
		fail = s.failAt > 0 && s.mutations == s.failAt
		var state networkState
		data, err := os.ReadFile(s.path)
		if err != nil || json.Unmarshal(data, &state) != nil || state.Table == "" {
			s.t.Fatalf("mutation without durable ownership journal: %s", command)
		}
		if name != "nft" && len(s.tables) == 0 {
			s.t.Fatalf("network mutation without active protection: %s", command)
		}
		journaled := name == "nft"
		for _, a := range state.Undo {
			switch {
			case name == "resolvectl":
				journaled = journaled || a.Kind == "dns" && a.Interface == args[1]
			case name == "ip" && args[0] == "link":
				journaled = journaled || a.Kind == "link" && a.Interface == args[3]
			case name == "ip" && args[1] == "address":
				journaled = journaled || a.Kind == "address" && a.Address == args[3] && a.Interface == args[5]
			case name == "ip" && args[1] == "route":
				journaled = journaled || a.Destination == args[3] && (a.Kind == "route" || a.Kind == "escape" || a.Kind == "dns-route")
			}
		}
		if !journaled {
			s.t.Fatalf("mutation missing its write-ahead undo action: %s", command)
		}
		if fail && !s.failAfter {
			return "", errors.New("injected pre-apply failure")
		}
	}
	output, err := s.apply(name, args, input)
	if fail {
		return "", errors.New("injected ambiguous post-apply failure")
	}
	return output, err
}

func jsonOutput(value any) (string, error) {
	data, err := json.Marshal(value)
	return string(data), err
}

func (s *fakeSystem) apply(name string, args []string, input string) (string, error) {
	switch name {
	case "nft":
		if input != "" {
			s.scripts = append(s.scripts, input)
			for _, line := range strings.Split(strings.TrimSpace(input), "\n") {
				fields := strings.Fields(line)
				switch {
				case strings.HasPrefix(line, "delete table "):
					delete(s.tables, fields[3])
				case strings.HasPrefix(line, "add table "):
					s.tables[fields[3]] = "Porta client " + fields[3]
				}
			}
			return "", nil
		}
		var entries []any
		for table, comment := range s.tables {
			if len(args) == 5 && args[4] != table {
				continue
			}
			entries = append(entries, map[string]any{"table": map[string]any{"family": "inet", "name": table, "comment": comment}})
		}
		return jsonOutput(map[string]any{"nftables": entries})
	case "resolvectl":
		switch args[0] {
		case "status":
			return "Global\nresolv.conf mode: stub", nil
		case "dns":
			if len(args) == 2 {
				return "Link 10 (" + args[1] + "): " + s.dns[args[1]], nil
			}
			s.dns[args[1]] = args[2]
		case "domain":
			if len(args) == 2 {
				return "Link 10 (" + args[1] + "): " + s.domains[args[1]], nil
			}
			s.domains[args[1]] = args[2]
		case "default-route":
		case "revert":
			delete(s.dns, args[1])
			delete(s.domains, args[1])
		default:
			return "", errors.New("unexpected resolver operation")
		}
		return "", nil
	case "ip":
		command := strings.Join(args, " ")
		if strings.Contains(command, "rule show") {
			if s.customRule {
				return `[{"priority":100,"src":"all","table":"100"}]`, nil
			}
			return `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`, nil
		}
		if command == "-j -d link show" {
			var links []*linkInfo
			for _, link := range s.links {
				links = append(links, link)
			}
			return jsonOutput(links)
		}
		if strings.HasPrefix(command, "link set dev ") {
			link := s.links[args[3]]
			link.MTU, _ = strconv.Atoi(args[5])
			link.Flags = []string{"POINTOPOINT"}
			if args[6] == "up" {
				link.Flags = append(link.Flags, "UP")
			}
			return "", nil
		}
		if strings.HasPrefix(command, "-j address show dev ") {
			var addresses []map[string]any
			for _, address := range s.addresses[args[4]] {
				prefix := netip.MustParsePrefix(address)
				addresses = append(addresses, map[string]any{"local": prefix.Addr().String(), "prefixlen": prefix.Bits()})
			}
			return jsonOutput([]any{map[string]any{"addr_info": addresses}})
		}
		if len(args) > 2 && args[1] == "address" {
			if args[2] == "add" {
				s.addresses[args[5]] = append(s.addresses[args[5]], args[3])
			} else {
				list := s.addresses[args[5]]
				for index, address := range list {
					if address == args[3] {
						s.addresses[args[5]] = append(list[:index], list[index+1:]...)
						break
					}
				}
			}
			return "", nil
		}
		if strings.Contains(command, "route show table main") {
			family, selector := args[2], args[len(args)-1]
			if selector == "default" {
				gateway := "192.0.2.1"
				if family == "-6" {
					gateway = "fe80::1"
				}
				return jsonOutput([]routeInfo{{Destination: "default", Device: "eth0", Gateway: gateway, Metric: 100}})
			}
			return jsonOutput(s.routes[family+" "+selector])
		}
		if strings.Contains(command, "route get") {
			device, gateway := "eth0", "192.0.2.1"
			if args[1] == "-6" {
				gateway = "fe80::1"
			} else if len(s.routes["-4 0.0.0.0/1"]) > 0 {
				device, gateway = "porta0", ""
			}
			return jsonOutput([]routeInfo{{Destination: args[4], Device: device, Gateway: gateway}})
		}
		if len(args) > 2 && args[1] == "route" {
			key := args[0] + " " + args[3]
			var route routeInfo
			route.Destination = args[3]
			for index := 4; index+1 < len(args); index += 2 {
				switch args[index] {
				case "dev":
					route.Device = args[index+1]
				case "via":
					route.Gateway = args[index+1]
				case "metric":
					route.Metric, _ = strconv.Atoi(args[index+1])
				case "proto":
					route.Protocol = json.RawMessage(args[index+1])
				}
			}
			if args[2] == "add" {
				if len(s.routes[key]) != 0 {
					return "", errors.New("route exists")
				}
				s.routes[key] = []routeInfo{route}
			} else {
				delete(s.routes, key)
			}
			return "", nil
		}
	}
	return "", fmt.Errorf("unexpected command: %s %v", name, args)
}

func TestAutomaticFullTunnelAndIntentionalCleanup(t *testing.T) {
	runner, system := newFake(t)
	ctx := context.Background()
	if err := runner.Prepare(ctx, testEndpoint()); err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(ctx, "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	if len(system.routes) != 4 || system.dns["porta0"] != "1.1.1.1" || system.domains["porta0"] != "~." || system.links["porta0"].MTU != 1280 {
		t.Fatalf("incomplete full tunnel: routes=%v DNS=%v domains=%v link=%+v", system.routes, system.dns, system.domains, system.links["porta0"])
	}
	if got := system.addresses["porta0"]; len(got) != 1 || got[0] != "10.77.0.2/24" {
		t.Fatalf("addresses: %v", got)
	}
	rules := system.scripts[len(system.scripts)-1]
	for _, required := range []string{`oifname "lo" accept`, `oifname "porta0" meta oif 10 accept`, "udp dport { 53, 853 } drop", "tcp dport { 53, 853 } drop", "ip daddr 198.51.100.10 udp dport 443 accept"} {
		if !strings.Contains(rules, required) {
			t.Errorf("missing firewall rule %q:\n%s", required, rules)
		}
	}
	if !strings.Contains(system.scripts[0], "policy drop") {
		t.Fatal("initial filter is not fail-closed")
	}
	for _, script := range system.scripts {
		if strings.Contains(script, "flush ruleset") || strings.Contains(script, "ct state") {
			t.Fatalf("overbroad firewall operation: %s", script)
		}
	}
	if err := runner.Down(ctx); err != nil {
		t.Fatal(err)
	}
	if len(system.tables) != 0 || len(system.routes) != 0 || len(system.addresses["porta0"]) != 0 || len(system.dns) != 0 {
		t.Fatalf("incomplete cleanup: %+v", system)
	}
	if system.links["porta0"].MTU != 1500 || contains(system.links["porta0"].Flags, "UP") {
		t.Fatal("original link settings were not restored")
	}
	if !strings.HasPrefix(system.scripts[len(system.scripts)-1], "delete table inet porta_") {
		t.Fatal("firewall was not removed last")
	}
	if _, err := os.Stat(runner.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains: %v", err)
	}
	if err := runner.Down(ctx); err != nil {
		t.Fatalf("second cleanup: %v", err)
	}
	if err := runner.Prepare(ctx, testEndpoint()); err != nil {
		t.Fatalf("runner cannot be reused after disconnect: %v", err)
	}
}

func TestReconfigureAddressDNSMTUAndEndpointWithoutProtectionGap(t *testing.T) {
	runner, system := newFake(t)
	ctx := context.Background()
	if err := runner.Up(ctx, "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.20"), Port: 8443}
	if err := runner.Prepare(ctx, remote); err != nil {
		t.Fatal(err)
	}
	script := system.scripts[len(system.scripts)-1]
	if !strings.Contains(script, "198.51.100.10") || !strings.Contains(script, "203.0.113.20") {
		t.Fatal("preparation did not retain old endpoint while admitting new endpoint")
	}
	lease := testLease()
	lease.Address = netip.MustParsePrefix("10.77.1.3/24")
	lease.DNS = netip.MustParseAddr("9.9.9.9")
	lease.MTU = 1420
	if err := runner.Reconfigure(ctx, "porta0", remote, lease); err != nil {
		t.Fatal(err)
	}
	if len(system.routes) != 4 || len(system.routes["-4 198.51.100.10/32"]) != 0 || len(system.routes["-4 203.0.113.20/32"]) != 1 {
		t.Fatalf("escape route reconfiguration: %v", system.routes)
	}
	if got := system.routes["-4 203.0.113.20/32"][0]; got.Device != "eth0" || got.Gateway != "192.0.2.1" {
		t.Fatalf("new endpoint did not escape via physical gateway: %+v", got)
	}
	if len(system.addresses["porta0"]) != 1 || system.addresses["porta0"][0] != lease.Address.String() ||
		system.dns["porta0"] != lease.DNS.String() || system.links["porta0"].MTU != lease.MTU {
		t.Fatal("lease changes were not applied")
	}
	for _, script := range system.scripts {
		if strings.Contains(script, "delete table") || strings.Contains(script, "delete chain") {
			t.Fatal("reconfiguration opened a protection gap")
		}
	}
	if strings.Contains(system.scripts[len(system.scripts)-1], "198.51.100.10") {
		t.Fatal("old endpoint remains allowed after successful reconfiguration")
	}
	if err := runner.Down(ctx); err != nil {
		t.Fatal(err)
	}
	if system.links["porta0"].MTU != 1500 {
		t.Fatal("reconfiguration lost original MTU")
	}
}

func TestIPv6TransportOnlyAllowsEndpointAndNeighborDiscovery(t *testing.T) {
	runner, system := newFake(t)
	remote := &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 443}
	if err := runner.Prepare(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	script := system.scripts[0]
	if !strings.Contains(script, "ip6 daddr 2001:db8::10 udp dport 443 accept") ||
		!strings.Contains(script, "ip6 hoplimit 255 icmpv6 type") || !strings.Contains(script, "policy drop") {
		t.Fatalf("incorrect IPv6 protection: %s", script)
	}
	if len(system.routes["-6 2001:db8::10/128"]) != 1 {
		t.Fatal("missing IPv6 endpoint escape")
	}
}

func TestEveryAmbiguousMutationIsJournaledAndRecoverable(t *testing.T) {
	baseline, baselineSystem := newFake(t)
	if err := baseline.Up(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	for failure := 1; failure <= baselineSystem.mutations; failure++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("mutation_%d_after_%t", failure, after), func(t *testing.T) {
				runner, system := newFake(t)
				system.failAt, system.failAfter = failure, after
				if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err == nil {
					t.Fatal("expected injected failure")
				}
				if failure > 1 && len(system.tables) == 0 {
					t.Fatal("setup failure removed protection")
				}
				if err := runner.releaseLock(); err != nil {
					t.Fatal(err)
				}
				recovered, err := NewRunner(runner.statePath)
				if err != nil {
					t.Fatal(err)
				}
				bindFake(recovered, system)
				t.Cleanup(func() { _ = recovered.releaseLock() })
				system.failAt = 0
				if err := recovered.Down(context.Background()); err != nil {
					t.Fatal(err)
				}
				if len(system.tables) != 0 || len(system.routes) != 0 || len(system.addresses["porta0"]) != 0 || len(system.dns) != 0 {
					t.Fatal("crash recovery left owned network changes")
				}
			})
		}
	}
}

func TestCleanupFailureKeepsFirewallAndJournalForRetry(t *testing.T) {
	runner, system := newFake(t)
	if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	system.failMatch = "resolvectl revert"
	if err := runner.Down(context.Background()); err == nil {
		t.Fatal("cleanup failure was hidden")
	}
	if len(system.tables) != 1 || len(runner.state.Undo) == 0 {
		t.Fatal("cleanup failure lost protection or recovery state")
	}
	system.failMatch = ""
	if err := runner.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReconfigureFailureCanBeRetriedWhileProtected(t *testing.T) {
	runner, system := newFake(t)
	if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	lease := testLease()
	lease.Address = netip.MustParsePrefix("10.77.0.4/24")
	lease.DNS = netip.MustParseAddr("9.9.9.9")
	system.failMatch = "resolvectl domain porta0 ~."
	if err := runner.Reconfigure(context.Background(), "porta0", testEndpoint(), lease); err == nil {
		t.Fatal("DNS failure was hidden")
	}
	if len(system.tables) != 1 {
		t.Fatal("DNS failure removed firewall")
	}
	system.failMatch = ""
	if err := runner.Reconfigure(context.Background(), "porta0", testEndpoint(), lease); err != nil {
		t.Fatal(err)
	}
	if len(system.addresses["porta0"]) != 1 || system.addresses["porta0"][0] != lease.Address.String() {
		t.Fatalf("old lease was not removed: %v", system.addresses)
	}
}

func TestPreexistingRoutesAndAddressesAreNotOverwritten(t *testing.T) {
	t.Run("endpoint route preserved", func(t *testing.T) {
		runner, system := newFake(t)
		preexisting := routeInfo{Destination: "198.51.100.10/32", Device: "eth0", Gateway: "192.0.2.5", Protocol: json.RawMessage("4")}
		system.routes["-4 198.51.100.10/32"] = []routeInfo{preexisting}
		if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
			t.Fatal(err)
		}
		if err := runner.Down(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(system.routes) != 1 || system.routes["-4 198.51.100.10/32"][0].Gateway != preexisting.Gateway {
			t.Fatal("preexisting endpoint route was changed")
		}
	})
	t.Run("split route conflict", func(t *testing.T) {
		runner, system := newFake(t)
		system.routes["-4 0.0.0.0/1"] = []routeInfo{{Destination: "0.0.0.0/1", Device: "eth0", Protocol: json.RawMessage("4")}}
		if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err == nil {
			t.Fatal("conflicting split route accepted")
		}
		if err := runner.Down(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(system.routes["-4 0.0.0.0/1"]) != 1 {
			t.Fatal("unrelated split route deleted")
		}
	})
	t.Run("interface address conflict", func(t *testing.T) {
		runner, system := newFake(t)
		system.addresses["porta0"] = []string{"10.9.0.1/24"}
		if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err == nil {
			t.Fatal("preexisting interface address overwritten")
		}
		if err := runner.Down(context.Background()); err != nil {
			t.Fatal(err)
		}
		if system.addresses["porta0"][0] != "10.9.0.1/24" {
			t.Fatal("unrelated address deleted")
		}
	})
	t.Run("DNS host route conflict", func(t *testing.T) {
		runner, system := newFake(t)
		system.routes["-4 1.1.1.1/32"] = []routeInfo{{Destination: "1.1.1.1/32", Device: "eth0", Protocol: json.RawMessage("4")}}
		if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err == nil || !strings.Contains(err.Error(), "route tunnel DNS") {
			t.Fatalf("physical DNS route did not fail explicitly: %v", err)
		}
		if err := runner.Down(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(system.routes) != 1 || system.routes["-4 1.1.1.1/32"][0].Device != "eth0" {
			t.Fatal("unrelated DNS host route changed")
		}
	})
}

func TestRecreatedInterfaceDoesNotReceiveStaleRestoration(t *testing.T) {
	runner, system := newFake(t)
	if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	system.links["porta0"].Index = 11
	system.links["porta0"].MTU = 1600
	system.links["porta0"].Flags = []string{"POINTOPOINT"}
	system.addresses["porta0"] = nil
	delete(system.routes, "-4 0.0.0.0/1")
	delete(system.routes, "-4 128.0.0.0/1")
	delete(system.routes, "-4 1.1.1.1/32")
	delete(system.dns, "porta0")
	delete(system.domains, "porta0")
	if err := runner.Reconfigure(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(system.scripts[len(system.scripts)-1], `oifname "porta0" meta oif 11 accept`) {
		t.Fatal("recreated TUN was not admitted by index")
	}
	if err := runner.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if system.links["porta0"].MTU != 1600 {
		t.Fatal("stale original interface MTU applied to replacement")
	}
}

func TestPrerequisitesFailExplicitlyWithoutMutation(t *testing.T) {
	for _, mode := range []string{"resolver", "policy", "resolvectl"} {
		t.Run(mode, func(t *testing.T) {
			runner, system := newFake(t)
			switch mode {
			case "resolver":
				runner.checkDNS = func() error { return errors.New("unsupported resolver") }
			case "policy":
				system.customRule = true
			case "resolvectl":
				system.failMatch = "resolvectl status"
			}
			if err := runner.Prepare(context.Background(), testEndpoint()); err == nil {
				t.Fatal("unsupported prerequisite silently accepted")
			}
			if system.mutations != 0 {
				t.Fatal("prerequisite failure mutated networking")
			}
		})
	}
}

func TestJournalLockAndOwnership(t *testing.T) {
	runner, system := newFake(t)
	if _, err := NewRunner(runner.statePath); err == nil {
		t.Fatal("second runner acquired active journal")
	}
	if err := runner.Prepare(context.Background(), testEndpoint()); err != nil {
		t.Fatal(err)
	}
	system.tables[runner.state.Table] = "not Porta"
	if err := runner.Down(context.Background()); err == nil {
		t.Fatal("foreign nftables table ownership ignored")
	}
	if len(system.tables) != 1 {
		t.Fatal("foreign nftables table deleted")
	}
}

func TestInvalidEndpointsAndLeases(t *testing.T) {
	for _, address := range []net.Addr{
		nil,
		&net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 443},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 53},
		&net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 853},
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 443, Zone: "eth0"},
	} {
		if _, err := parseEndpoint(address); err == nil {
			t.Errorf("invalid endpoint accepted: %v", address)
		}
	}
	lease := testLease()
	for _, name := range []string{"", "lo", `tun"; accept; #`, "way-too-long-interface"} {
		if err := validateLease(name, lease); err == nil {
			t.Errorf("invalid interface accepted: %q", name)
		}
	}
	lease.DNS = netip.Addr{}
	if err := validateLease("porta0", lease); err == nil {
		t.Fatal("missing DNS silently accepted")
	}
}
