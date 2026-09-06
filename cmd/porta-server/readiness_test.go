package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const readyNftTable = `{"nftables":[
 {"chain":{"name":"forward","type":"filter","hook":"forward","policy":"accept"}},
 {"chain":{"name":"postrouting","type":"nat","hook":"postrouting","policy":"accept"}},
 {"rule":{"chain":"forward","expr":[
   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"porta0"}},
   {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},{"accept":null}]}},
 {"rule":{"chain":"forward","expr":[
   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
   {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"porta0"}},
   {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}},
 {"rule":{"chain":"postrouting","expr":[
   {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},
   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.66.0.0","len":24}}}},
   {"masquerade":null}]}}
]}`

const readyNftGuard = `{"nftables":[
 {"chain":{"name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}},
 {"rule":{"chain":"input","expr":[
   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},
   {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},
   {"match":{"op":"==","left":{"&":[{"payload":{"protocol":"tcp","field":"flags"}},["fin","syn","rst","ack"]]},"right":"syn"}},
   {"meter":{"key":{"elem":{"val":{"payload":{"protocol":"ip","field":"saddr"}},"timeout":10}},"stmt":{"limit":{"rate":200,"burst":400,"per":"second","inv":true}},"size":65535,"name":"tcp4"}},
   {"counter":{"packets":0,"bytes":0}},{"drop":null}]}},
 {"rule":{"chain":"input","expr":[
   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},
   {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},
   {"match":{"op":"==","left":{"&":[{"payload":{"protocol":"tcp","field":"flags"}},["fin","syn","rst","ack"]]},"right":"syn"}},
   {"meter":{"key":{"elem":{"val":{"payload":{"protocol":"ip6","field":"saddr"}},"timeout":10}},"stmt":{"limit":{"rate":200,"burst":400,"per":"second","inv":true}},"size":65535,"name":"tcp6"}},
   {"counter":{"packets":0,"bytes":0}},{"drop":null}]}},
 {"rule":{"chain":"input","expr":[
   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
   {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":8443}},
   {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},
   {"meter":{"key":{"elem":{"val":{"payload":{"protocol":"ip","field":"saddr"}},"timeout":10}},"stmt":{"limit":{"rate":500,"burst":1000,"per":"second","inv":true}},"size":65535,"name":"udp4"}},
   {"counter":{"packets":0,"bytes":0}},{"drop":null}]}},
 {"rule":{"chain":"input","expr":[
   {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
   {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":8443}},
   {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},
   {"meter":{"key":{"elem":{"val":{"payload":{"protocol":"ip6","field":"saddr"}},"timeout":10}},"stmt":{"limit":{"rate":500,"burst":1000,"per":"second","inv":true}},"size":65535,"name":"udp6"}},
   {"counter":{"packets":0,"bytes":0}},{"drop":null}]}}
]}`

func readyTestConfig() forwardingReadinessConfig {
	return forwardingReadinessConfig{
		Interface: "porta0", Gateway: netip.MustParseAddr("10.66.0.1"), Pool: netip.MustParsePrefix("10.66.0.0/24"),
		EgressInterface: "eth0", RequireNAT: true, RequireInputGuard: true, PublicPort: 8443,
		Timeout: time.Second, DNSAddress: "1.1.1.1",
	}
}

func readyTestDependencies() readinessDependencies {
	return readinessDependencies{
		InterfaceByName: func(name string) (*net.Interface, error) {
			return &net.Interface{Name: name, Flags: net.FlagUp}, nil
		},
		Addresses: func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("10.66.0.1"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		ReadFile: func(string) ([]byte, error) { return []byte("1\n"), nil },
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "nft" {
				if strings.Contains(strings.Join(args, " "), "inet porta_guard") {
					return []byte(readyNftGuard), nil
				}
				return []byte(readyNftTable), nil
			}
			if strings.Contains(strings.Join(args, " "), "default") {
				return []byte(`[{"dst":"default","dev":"eth0"}]`), nil
			}
			return []byte(`[{"dst":"10.66.0.0/24","dev":"porta0"}]`), nil
		},
	}
}

func TestForwardingReadinessNftStateEncodings(t *testing.T) {
	for _, test := range []struct {
		name   string
		states string
		ready  bool
	}{
		{"nft-1.0.9-array", `["established","related"]`, true},
		{"set-object", `{"set":["established","related"]}`, true},
		{"reversed-array", `["related","established"]`, true},
		{"missing-related", `["established"]`, false},
		{"extra-state", `["established","related","new"]`, false},
		{"wrong-state", `{"set":["established","new"]}`, false},
		{"scalar", `"established"`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := readyTestDependencies()
			command := deps.Command
			deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "nft" && !strings.Contains(strings.Join(args, " "), "inet porta_guard") {
					return []byte(strings.Replace(readyNftTable, `["established","related"]`, test.states, 1)), nil
				}
				return command(ctx, name, args...)
			}
			readiness, err := newForwardingReadiness(readyTestConfig(), deps)
			if err != nil {
				t.Fatal(err)
			}
			report := readiness.Check(context.Background())
			if (report.Status == "ready") != test.ready {
				t.Fatalf("readiness for ct-state %s = %+v", test.states, report)
			}
			if !test.ready && report.Components["porta_forward_rules"].Status != "error" {
				t.Fatalf("invalid ct-state did not fail the forwarding check: %+v", report)
			}
		})
	}
}

func TestInputGuardReadinessRejectsMalformedRules(t *testing.T) {
	for _, test := range []struct {
		name string
		old  string
		new  string
	}{
		{"wrong-interface", `"right":"eth0"`, `"right":"eth1"`},
		{"wrong-port", `"right":8443`, `"right":9443`},
		{"wrong-protocol", `"protocol":"tcp","field":"dport"`, `"protocol":"udp","field":"dport"`},
		{"wrong-state", `"right":"new"`, `"right":"established"`},
		{"wrong-meter-rate", `"rate":200`, `"rate":201`},
		{"wrong-meter-size", `"size":65535`, `"size":1024`},
		{"byte-rate-units", `"per":"second","inv":true`, `"per":"second","rate_unit":"mbytes","burst_unit":"mbytes","inv":true`},
		{"wrong-verdict", `"drop":null`, `"accept":null`},
		{"wrong-policy", `"policy":"accept"`, `"policy":"drop"`},
		{"missing-counter", `{"counter":{"packets":0,"bytes":0}},`, ``},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := readyTestDependencies()
			command := deps.Command
			deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				data, err := command(ctx, name, args...)
				if name == "nft" && strings.Contains(strings.Join(args, " "), "inet porta_guard") {
					data = []byte(strings.Replace(string(data), test.old, test.new, 1))
				}
				return data, err
			}
			readiness, err := newForwardingReadiness(readyTestConfig(), deps)
			if err != nil {
				t.Fatal(err)
			}
			report := readiness.Check(context.Background())
			if report.Status != "not_ready" || report.Components["porta_input_guard"].Status != "error" {
				t.Fatalf("malformed guard was accepted: %+v", report)
			}
		})
	}
}

func TestInputGuardReadinessRejectsMeterBeforeSelectors(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal([]byte(readyNftGuard), &document); err != nil {
		t.Fatal(err)
	}
	entries, _ := document["nftables"].([]any)
	for _, value := range entries {
		entry, _ := value.(map[string]any)
		rule, _ := entry["rule"].(map[string]any)
		expressions, _ := rule["expr"].([]any)
		if len(expressions) == 7 {
			expressions[0], expressions[4] = expressions[4], expressions[0]
			break
		}
	}
	reordered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	deps := readyTestDependencies()
	command := deps.Command
	deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "nft" && strings.Contains(strings.Join(args, " "), "inet porta_guard") {
			return reordered, nil
		}
		return command(ctx, name, args...)
	}
	readiness, err := newForwardingReadiness(readyTestConfig(), deps)
	if err != nil {
		t.Fatal(err)
	}
	report := readiness.Check(context.Background())
	if report.Status != "not_ready" || report.Components["porta_input_guard"].Status != "error" {
		t.Fatalf("meter-first guard was accepted: %+v", report)
	}
}

func TestForwardingReadinessChecksRealComponents(t *testing.T) {
	for _, test := range []struct {
		name      string
		component string
		mutate    func(*readinessDependencies)
	}{
		{"ready", "", func(*readinessDependencies) {}},
		{"tun-down", "tun_link", func(deps *readinessDependencies) {
			deps.InterfaceByName = func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil }
		}},
		{"missing-address", "tun_address", func(deps *readinessDependencies) {
			deps.Addresses = func(*net.Interface) ([]net.Addr, error) { return nil, nil }
		}},
		{"forwarding-disabled", "ipv4_forwarding", func(deps *readinessDependencies) {
			deps.ReadFile = func(string) ([]byte, error) { return []byte("0\n"), nil }
		}},
		{"missing-route", "pool_route", func(deps *readinessDependencies) {
			command := deps.Command
			deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "ip" && strings.Contains(strings.Join(args, " "), "exact") {
					return []byte("[]"), nil
				}
				return command(ctx, name, args...)
			}
		}},
		{"egress-linkdown", "egress_route", func(deps *readinessDependencies) {
			command := deps.Command
			deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "ip" && strings.Contains(strings.Join(args, " "), "default") {
					return []byte(`[{"dev":"eth0","flags":["linkdown"]}]`), nil
				}
				return command(ctx, name, args...)
			}
		}},
		{"wrong-preferred-egress", "egress_route", func(deps *readinessDependencies) {
			command := deps.Command
			deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "ip" && strings.Contains(strings.Join(args, " "), "default") {
					return []byte(`[{"dev":"eth0","metric":200},{"dev":"eth1","metric":100}]`), nil
				}
				return command(ctx, name, args...)
			}
		}},
		{"nft-permission-denied", "porta_nat_rules", func(deps *readinessDependencies) {
			command := deps.Command
			deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "nft" {
					return nil, errors.New("permission denied")
				}
				return command(ctx, name, args...)
			}
		}},
		{"wrong-nat-pool", "porta_nat_rules", func(deps *readinessDependencies) {
			command := deps.Command
			deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				data, err := command(ctx, name, args...)
				if name == "nft" {
					data = []byte(strings.ReplaceAll(string(data), `"addr":"10.66.0.0"`, `"addr":"10.99.0.0"`))
				}
				return data, err
			}
		}},
		{"wrong-forward-verdict", "porta_forward_rules", func(deps *readinessDependencies) {
			command := deps.Command
			deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				data, err := command(ctx, name, args...)
				if name == "nft" {
					data = []byte(strings.ReplaceAll(string(data), `"accept":null`, `"drop":null`))
				}
				return data, err
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			deps := readyTestDependencies()
			test.mutate(&deps)
			readiness, err := newForwardingReadiness(readyTestConfig(), deps)
			if err != nil {
				t.Fatal(err)
			}
			report := readiness.Check(context.Background())
			if test.component == "" {
				if report.Status != "ready" || report.Components["external_dns"].Status != "disabled" {
					t.Fatalf("ready report = %+v", report)
				}
			} else if report.Status != "not_ready" || report.Components[test.component].Status != "error" ||
				report.Components[test.component].Error == "" {
				t.Fatalf("unhealthy component hidden: %+v", report)
			}
		})
	}
}

func TestOptionalReadinessProbesAreBoundedAndNotRequired(t *testing.T) {
	var queried atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer server.Close()
	config := readyTestConfig()
	config.Timeout, config.EgressURL, config.DNSName = 50*time.Millisecond, server.URL, "health.example"
	deps := readyTestDependencies()
	deps.HTTPClient = server.Client()
	deps.LookupDNS = func(ctx context.Context, address, name string) error {
		if address != config.DNSAddress || name != config.DNSName {
			t.Error("probe did not use the configured client DNS server/name")
		}
		queried.Store(true)
		<-ctx.Done()
		return ctx.Err()
	}
	readiness, err := newForwardingReadiness(config, deps)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	report := readiness.Check(context.Background())
	if time.Since(start) > time.Second || report.Status != "ready" || !queried.Load() ||
		report.Components["external_egress"].Status != "error" || report.Components["external_dns"].Status != "error" {
		t.Fatalf("optional probes incorrectly affected local readiness: %+v", report)
	}
}

func TestRoutedReadinessDoesNotClaimNATWorking(t *testing.T) {
	config := readyTestConfig()
	config.RequireNAT = false
	readiness, err := newForwardingReadiness(config, readyTestDependencies())
	if err != nil {
		t.Fatal(err)
	}
	report := readiness.Check(context.Background())
	if report.Status != "ready" || report.Components["porta_nat_rules"].Status != "disabled" ||
		report.Components["porta_nat_rules"].Required {
		t.Fatalf("routed readiness = %+v", report)
	}
}

func TestProxyBackendReadinessDoesNotRequirePublicInputGuard(t *testing.T) {
	config := readyTestConfig()
	config.RequireInputGuard = false
	deps := readyTestDependencies()
	command := deps.Command
	deps.Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "nft" && strings.Contains(strings.Join(args, " "), "inet porta_guard") {
			return nil, errors.New("guard unavailable")
		}
		return command(ctx, name, args...)
	}
	readiness, err := newForwardingReadiness(config, deps)
	if err != nil {
		t.Fatal(err)
	}
	report := readiness.Check(context.Background())
	if report.Status != "ready" || report.Components["porta_input_guard"].Status != "disabled" {
		t.Fatalf("proxy-backend readiness = %+v", report)
	}
}

func TestAutomaticMTURequiresWorkingICMPIngress(t *testing.T) {
	for _, test := range []struct {
		name, accept, allRPF, tunRPF string
		auto, ready                  bool
	}{
		{"fixed", "0", "1", "1", false, true},
		{"local-source-blocked", "0", "0", "0", true, false},
		{"strict-interface", "1", "0", "1", true, false},
		{"strict-global", "1", "1", "0", true, false},
		{"scoped-loose-overrides-strict", "1", "1", "2", true, true},
		{"loose-global", "1", "2", "1", true, true},
		{"rpf-disabled", "1", "0", "0", true, true},
		{"malformed-setting", "1", "unknown", "2", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := readyTestConfig()
			config.AutoMTU = test.auto
			deps := readyTestDependencies()
			deps.ReadFile = func(path string) ([]byte, error) {
				switch path {
				case "/proc/sys/net/ipv4/conf/porta0/accept_local":
					return []byte(test.accept), nil
				case "/proc/sys/net/ipv4/conf/porta0/rp_filter":
					return []byte(test.tunRPF), nil
				case "/proc/sys/net/ipv4/conf/all/rp_filter":
					return []byte(test.allRPF), nil
				case "/proc/sys/net/ipv4/ip_forward":
					return []byte("1"), nil
				default:
					return nil, errors.New("unexpected sysctl read")
				}
			}
			readiness, err := newForwardingReadiness(config, deps)
			if err != nil {
				t.Fatal(err)
			}
			report := readiness.Check(context.Background())
			if (report.Status == "ready") != test.ready {
				t.Fatalf("incorrect MTU feedback readiness: %+v", report)
			}
			component := report.Components["mtu_feedback"]
			if test.auto && component.Required != true {
				t.Fatal("MTU feedback prerequisite is not required")
			}
			if !test.auto && component.Status != "disabled" {
				t.Fatal("fixed mode acquired an MTU discovery requirement")
			}
		})
	}
}
