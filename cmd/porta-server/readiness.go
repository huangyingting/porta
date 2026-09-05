package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/huangyingting/porta/internal/gateway"
)

type forwardingReadinessConfig struct {
	Interface       string
	Gateway         netip.Addr
	Pool            netip.Prefix
	EgressInterface string
	RequireNAT      bool
	AutoMTU         bool
	Timeout         time.Duration
	EgressURL       string
	DNSName         string
	DNSAddress      string
}

type readinessDependencies struct {
	InterfaceByName func(string) (*net.Interface, error)
	Addresses       func(*net.Interface) ([]net.Addr, error)
	ReadFile        func(string) ([]byte, error)
	Command         func(context.Context, string, ...string) ([]byte, error)
	HTTPClient      *http.Client
	LookupDNS       func(context.Context, string, string) error
}

func localReadinessDependencies() readinessDependencies {
	return readinessDependencies{
		InterfaceByName: net.InterfaceByName,
		Addresses:       (*net.Interface).Addrs,
		ReadFile:        os.ReadFile,
		Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			if err != nil {
				return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
			}
			return output, nil
		},
		HTTPClient: &http.Client{
			Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		LookupDNS: func(ctx context.Context, server, name string) error {
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
			}}
			addresses, err := resolver.LookupNetIP(ctx, "ip4", name)
			if err == nil && len(addresses) == 0 {
				err = errors.New("DNS query returned no IPv4 addresses")
			}
			return err
		},
	}
}

func newForwardingReadiness(config forwardingReadinessConfig, deps readinessDependencies) (*gateway.Readiness, error) {
	if config.Timeout <= 0 {
		return nil, errors.New("--readiness-timeout must be positive")
	}
	if config.EgressURL != "" {
		u, err := url.Parse(config.EgressURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return nil, errors.New("--readiness-egress-url must be an HTTP(S) URL without credentials")
		}
	}
	if config.DNSName != "" {
		if _, err := netip.ParseAddr(config.DNSAddress); err != nil {
			return nil, errors.New("--dns must be an IP address when --readiness-dns-name is configured")
		}
	}
	link := func() (*net.Interface, error) {
		iface, err := deps.InterfaceByName(config.Interface)
		if err != nil {
			return nil, err
		}
		if iface.Flags&net.FlagUp == 0 {
			return nil, fmt.Errorf("interface %s is down", config.Interface)
		}
		return iface, nil
	}
	checks := []gateway.ReadinessCheck{
		{Name: "tun_link", Required: true, Probe: func(context.Context) error {
			_, err := link()
			return err
		}},
		{Name: "tun_address", Required: true, Probe: func(context.Context) error {
			iface, err := link()
			if err != nil {
				return err
			}
			addresses, err := deps.Addresses(iface)
			if err != nil {
				return err
			}
			for _, address := range addresses {
				prefix, err := netip.ParsePrefix(address.String())
				if err == nil && prefix.Addr() == config.Gateway && prefix.Bits() == config.Pool.Bits() {
					return nil
				}
			}
			return fmt.Errorf("%s lacks gateway address %s/%d", config.Interface, config.Gateway, config.Pool.Bits())
		}},
		{Name: "pool_route", Required: true, Probe: func(ctx context.Context) error {
			routes, err := readRoutes(ctx, deps, "exact", config.Pool.String())
			if err != nil {
				return err
			}
			for _, route := range routes {
				if route.Destination == config.Pool.String() && route.Device == config.Interface && route.usable() {
					return nil
				}
			}
			return fmt.Errorf("no pool route through %s", config.Interface)
		}},
		{Name: "egress_route", Required: true, Probe: func(ctx context.Context) error {
			_, err := readinessEgress(ctx, config, deps)
			return err
		}},
		{Name: "ipv4_forwarding", Required: true, Probe: func(context.Context) error {
			value, err := deps.ReadFile("/proc/sys/net/ipv4/ip_forward")
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(value)) != "1" {
				return errors.New("net.ipv4.ip_forward is not enabled")
			}
			return nil
		}},
		{Name: "porta_forward_rules", Required: true, Probe: func(ctx context.Context) error {
			return checkPortaRules(ctx, config, deps, false)
		}},
		{Name: "porta_nat_rules", Required: config.RequireNAT},
		{Name: "external_egress"},
		{Name: "external_dns"},
	}
	if config.RequireNAT {
		checks[6].Probe = func(ctx context.Context) error { return checkPortaRules(ctx, config, deps, true) }
	}
	if config.EgressURL != "" {
		checks[7].Probe = func(ctx context.Context) error {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.EgressURL, nil)
			if err != nil {
				return err
			}
			response, err := deps.HTTPClient.Do(request)
			if err != nil {
				return err
			}
			defer response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				return fmt.Errorf("egress HTTP status %d", response.StatusCode)
			}
			_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			return err
		}
	}
	if config.DNSName != "" {
		checks[8].Probe = func(ctx context.Context) error {
			return deps.LookupDNS(ctx, config.DNSAddress, config.DNSName)
		}
	}
	checks = append(checks, gateway.ReadinessCheck{
		Name: "mtu_feedback", Required: config.AutoMTU,
	})
	if config.AutoMTU {
		checks[len(checks)-1].Probe = func(context.Context) error {
			return checkMTUFeedback(config.Interface, deps.ReadFile)
		}
	}
	return &gateway.Readiness{Checks: checks, Timeout: config.Timeout}, nil
}

func checkMTUFeedback(iface string, readFile func(string) ([]byte, error)) error {
	value, err := readFile("/proc/sys/net/ipv4/conf/" + iface + "/accept_local")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(value)) != "1" {
		return fmt.Errorf("automatic MTU requires net/ipv4/conf/%s/accept_local=1 for ICMP feedback", iface)
	}
	effectiveRPF := 0
	for _, name := range []string{"all", iface} {
		path := "/proc/sys/net/ipv4/conf/" + name + "/rp_filter"
		value, err := readFile(path)
		if err != nil {
			return err
		}
		setting, err := strconv.Atoi(strings.TrimSpace(string(value)))
		if err != nil || setting < 0 || setting > 2 {
			return fmt.Errorf("invalid rp_filter setting at %s", path)
		}
		effectiveRPF = max(effectiveRPF, setting)
	}
	if effectiveRPF == 1 {
		return fmt.Errorf("strict reverse-path filtering blocks MTU feedback; set net/ipv4/conf/%s/rp_filter=2", iface)
	}
	return nil
}

type readinessRoute struct {
	Destination string   `json:"dst"`
	Device      string   `json:"dev"`
	Type        string   `json:"type"`
	Metric      int      `json:"metric"`
	Flags       []string `json:"flags"`
}

func (r readinessRoute) usable() bool {
	return (r.Type == "" || r.Type == "unicast") && !slices.Contains(r.Flags, "linkdown")
}

func readRoutes(ctx context.Context, deps readinessDependencies, selector ...string) ([]readinessRoute, error) {
	args := append([]string{"-j", "-4", "route", "show"}, selector...)
	data, err := deps.Command(ctx, "ip", args...)
	if err != nil {
		return nil, err
	}
	var routes []readinessRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, fmt.Errorf("decode routes: %w", err)
	}
	return routes, nil
}

func readinessEgress(ctx context.Context, config forwardingReadinessConfig, deps readinessDependencies) (string, error) {
	routes, err := readRoutes(ctx, deps, "default")
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", errors.New("no default route")
	}
	slices.SortStableFunc(routes, func(a, b readinessRoute) int {
		if a.Metric < b.Metric {
			return -1
		}
		if a.Metric > b.Metric {
			return 1
		}
		return 0
	})
	route := routes[0]
	if route.Device == "" || route.Device == config.Interface || !route.usable() ||
		(config.EgressInterface != "" && route.Device != config.EgressInterface) {
		return "", errors.New("preferred default route is not usable on the configured egress interface")
	}
	for _, other := range routes[1:] {
		if other.Metric == route.Metric && other.Device != route.Device {
			return "", errors.New("default routes have ambiguous equal-priority egress interfaces")
		}
	}
	iface, err := deps.InterfaceByName(route.Device)
	if err != nil {
		return "", err
	}
	if iface.Flags&net.FlagUp == 0 {
		return "", fmt.Errorf("egress interface %s is down", route.Device)
	}
	return route.Device, nil
}

type nftReadinessChain struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type nftReadinessRule struct {
	Chain string           `json:"chain"`
	Expr  []map[string]any `json:"expr"`
}

func checkPortaRules(ctx context.Context, config forwardingReadinessConfig, deps readinessDependencies, nat bool) error {
	egress, err := readinessEgress(ctx, config, deps)
	if err != nil {
		return err
	}
	data, err := deps.Command(ctx, "nft", "-j", "list", "table", "ip", "porta")
	if err != nil {
		return err
	}
	var table struct {
		Entries []struct {
			Chain *nftReadinessChain `json:"chain"`
			Rule  *nftReadinessRule  `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		return fmt.Errorf("decode Porta nftables rules: %w", err)
	}
	chainName, chainType, hook := "forward", "filter", "forward"
	if nat {
		chainName, chainType, hook = "postrouting", "nat", "postrouting"
	}
	foundChain := false
	var rules []nftReadinessRule
	for _, entry := range table.Entries {
		if chain := entry.Chain; chain != nil && chain.Name == chainName {
			foundChain = chain.Type == chainType && chain.Hook == hook && chain.Policy == "accept"
		}
		if rule := entry.Rule; rule != nil && rule.Chain == chainName {
			rules = append(rules, *rule)
		}
	}
	if !foundChain {
		return fmt.Errorf("Porta %s base chain is missing or has the wrong hook/type/policy", chainName)
	}
	if nat {
		if len(rules) == 0 || !matchesPortaRule(rules[0], "", egress, config.Pool, false, "masquerade") {
			return errors.New("Porta pool masquerade rule is missing or preceded by another rule")
		}
	} else if len(rules) < 2 ||
		!matchesPortaRule(rules[0], config.Interface, egress, netip.Prefix{}, false, "accept") ||
		!matchesPortaRule(rules[1], egress, config.Interface, netip.Prefix{}, true, "accept") {
		return errors.New("Porta outbound/established-return forwarding rules are missing or preceded by other rules")
	}
	return nil
}

func matchesPortaRule(rule nftReadinessRule, input, output string, pool netip.Prefix, established bool, verdict string) bool {
	want := map[string]bool{"oifname": true, verdict: true}
	if input != "" {
		want["iifname"] = true
	}
	if pool.IsValid() {
		want["source"] = true
	}
	if established {
		want["state"] = true
	}
	for _, expr := range rule.Expr {
		if len(expr) != 1 {
			return false
		}
		if _, ok := expr["counter"]; ok {
			continue
		}
		if value, ok := expr[verdict]; ok && value == nil {
			delete(want, verdict)
			continue
		}
		match, ok := expr["match"].(map[string]any)
		if !ok {
			return false
		}
		left, _ := match["left"].(map[string]any)
		if meta, ok := left["meta"].(map[string]any); ok && match["op"] == "==" {
			switch meta["key"] {
			case "iifname":
				if match["right"] != input || input == "" {
					return false
				}
				delete(want, "iifname")
				continue
			case "oifname":
				if match["right"] != output {
					return false
				}
				delete(want, "oifname")
				continue
			}
		}
		if payload, ok := left["payload"].(map[string]any); ok && pool.IsValid() &&
			payload["protocol"] == "ip" && payload["field"] == "saddr" && match["op"] == "==" {
			right, _ := match["right"].(map[string]any)
			prefix, _ := right["prefix"].(map[string]any)
			if prefix["addr"] != pool.Addr().String() || prefix["len"] != float64(pool.Bits()) {
				return false
			}
			delete(want, "source")
			continue
		}
		if ct, ok := left["ct"].(map[string]any); ok && ct["key"] == "state" && established &&
			(match["op"] == "in" || match["op"] == "==") {
			set, ok := match["right"].([]any)
			if !ok {
				right, _ := match["right"].(map[string]any)
				set, _ = right["set"].([]any)
			}
			if len(set) != 2 || !slices.Contains(set, any("established")) || !slices.Contains(set, any("related")) {
				return false
			}
			delete(want, "state")
			continue
		}
		return false
	}
	return len(want) == 0
}
