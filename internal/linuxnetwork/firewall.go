//go:build linux

package linuxnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

func (r *Runner) protect(ctx context.Context) error {
	exists, err := r.tableExists(ctx)
	if err != nil {
		return err
	}
	var rules strings.Builder
	if exists {
		fmt.Fprintf(&rules, "flush chain inet %s output\n", r.state.Table)
	} else {
		fmt.Fprintf(&rules, "add table inet %s { comment %q; }\n", r.state.Table, "Porta client "+r.state.Table)
		fmt.Fprintf(&rules, "add chain inet %s output { type filter hook output priority -150; policy drop; }\n", r.state.Table)
	}
	add := func(expression string) {
		fmt.Fprintf(&rules, "add rule inet %s output %s\n", r.state.Table, expression)
	}
	add(`oifname "lo" accept`)
	if r.state.Interface != "" {
		add(fmt.Sprintf("oifname %q meta oif %d accept", r.state.Interface, r.state.Index))
	}
	// No established/related shortcut: pre-existing physical connections must
	// also stop. DNS exceptions must not accidentally follow endpoint rules.
	add("udp dport { 53, 853 } drop")
	add("tcp dport { 53, 853 } drop")
	ipv6 := false
	for _, endpoint := range r.state.Endpoints {
		family := "ip"
		if netip.MustParseAddr(endpoint.IP).Is6() {
			family, ipv6 = "ip6", true
		}
		for _, protocol := range []string{"tcp", "udp"} {
			add(fmt.Sprintf("%s daddr %s %s dport %d accept", family, endpoint.IP, protocol, endpoint.Port))
		}
	}
	if ipv6 {
		// Neighbor discovery is needed to reach an IPv6 gateway. Hop limit 255
		// and link-local destinations prevent a general ICMPv6 escape hatch.
		add("ip6 daddr { fe80::/10, ff02::/16 } ip6 hoplimit 255 icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept")
	}
	_, err = r.invoke(ctx, "nft", []string{"-f", "-"}, rules.String())
	return err
}

func (r *Runner) tableExists(ctx context.Context) (bool, error) {
	output, err := r.invoke(ctx, "nft", []string{"-j", "list", "tables"}, "")
	if err != nil {
		return false, fmt.Errorf("nftables is required for fail-closed networking: %w", err)
	}
	var listing struct {
		Items []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(output), &listing); err != nil {
		return false, fmt.Errorf("decode nftables tables: %w", err)
	}
	for _, item := range listing.Items {
		if item.Table == nil || item.Table.Family != "inet" || item.Table.Name != r.state.Table {
			continue
		}
		output, err := r.invoke(ctx, "nft", []string{"-j", "list", "table", "inet", r.state.Table}, "")
		if err != nil {
			return false, err
		}
		var owned struct {
			Items []struct {
				Table *struct {
					Family  string `json:"family"`
					Name    string `json:"name"`
					Comment string `json:"comment"`
				} `json:"table"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal([]byte(output), &owned); err != nil {
			return false, err
		}
		for _, item := range owned.Items {
			if item.Table != nil && item.Table.Name == r.state.Table && item.Table.Family == "inet" && item.Table.Comment == "Porta client "+r.state.Table {
				return true, nil
			}
		}
		return false, errors.New("refusing to modify an nftables table without the journal ownership marker")
	}
	return false, nil
}

func checkStubResolver() error {
	target, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("inspect resolver configuration: %w", err)
	}
	if target != "/run/systemd/resolve/stub-resolv.conf" && target != "/usr/lib/systemd/resolv.conf" {
		return errors.New("automatic DNS requires /etc/resolv.conf linked to systemd-resolved's local stub; other resolver managers are unsupported")
	}
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("read resolver configuration: %w", err)
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "nameserver" {
			continue
		}
		if len(fields) < 2 || (fields[1] != "127.0.0.53" && fields[1] != "127.0.0.54") {
			return errors.New("automatic DNS requires exclusively systemd-resolved loopback stub nameservers")
		}
		found = true
	}
	if !found {
		return errors.New("systemd-resolved stub has no nameserver")
	}
	return nil
}
