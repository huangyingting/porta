//go:build linux

package linuxnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type linkInfo struct {
	Index    int      `json:"ifindex"`
	Name     string   `json:"ifname"`
	Address  string   `json:"address"`
	Alias    string   `json:"ifalias"`
	MTU      int      `json:"mtu"`
	Flags    []string `json:"flags"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

type routeInfo struct {
	Destination string          `json:"dst"`
	Device      string          `json:"dev"`
	Gateway     string          `json:"gateway"`
	Metric      int             `json:"metric"`
	Protocol    json.RawMessage `json:"protocol"`
	Type        string          `json:"type"`
	Multipath   json.RawMessage `json:"multipath,omitempty"`
	Nexthops    json.RawMessage `json:"nexthops,omitempty"`
	NextHopID   int             `json:"nhid,omitempty"`
}

func (route routeInfo) multipath() bool {
	return (len(route.Multipath) != 0 && string(route.Multipath) != "null") ||
		(len(route.Nexthops) != 0 && string(route.Nexthops) != "null") || route.NextHopID != 0
}

func (r *Runner) link(ctx context.Context, name string) (*linkInfo, error) {
	links, err := r.links(ctx)
	if err != nil {
		return nil, err
	}
	for index := range links {
		if links[index].Name == name {
			return &links[index], nil
		}
	}
	return nil, nil
}

func (r *Runner) linkByIndex(ctx context.Context, index int) (*linkInfo, error) {
	links, err := r.links(ctx)
	if err != nil {
		return nil, err
	}
	for linkIndex := range links {
		if links[linkIndex].Index == index {
			return &links[linkIndex], nil
		}
	}
	return nil, nil
}

func (r *Runner) links(ctx context.Context) ([]linkInfo, error) {
	output, err := r.invoke(ctx, "ip", []string{"-j", "-d", "link", "show"}, "")
	if err != nil {
		return nil, err
	}
	var links []linkInfo
	if err := json.Unmarshal([]byte(output), &links); err != nil {
		return nil, fmt.Errorf("decode interface state: %w", err)
	}
	return links, nil
}

func (r *Runner) addresses(ctx context.Context, name string) ([]string, error) {
	output, err := r.invoke(ctx, "ip", []string{"-j", "address", "show", "dev", name}, "")
	if err != nil {
		return nil, err
	}
	var links []struct {
		Addresses []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(output), &links); err != nil {
		return nil, err
	}
	var addresses []string
	for _, link := range links {
		for _, address := range link.Addresses {
			addresses = append(addresses, address.Local+"/"+strconv.Itoa(address.PrefixLen))
		}
	}
	return addresses, nil
}

func (r *Runner) checkRules(ctx context.Context, family int) error {
	output, err := r.invoke(ctx, "ip", []string{"-j", "-" + strconv.Itoa(family), "rule", "show"}, "")
	if err != nil {
		return err
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &rules); err != nil {
		return err
	}
	local, main := false, false
	for _, rule := range rules {
		for key := range rule {
			switch key {
			case "priority", "src", "dst", "table", "protocol":
			default:
				return errors.New("automatic full tunneling does not support custom policy-routing rules")
			}
		}
		var priority int
		var table, source, destination string
		_ = json.Unmarshal(rule["priority"], &priority)
		_ = json.Unmarshal(rule["table"], &table)
		_ = json.Unmarshal(rule["src"], &source)
		_ = json.Unmarshal(rule["dst"], &destination)
		if source != "" && source != "all" || destination != "" && destination != "all" {
			return errors.New("automatic full tunneling does not support source/destination policy routing")
		}
		switch {
		case priority == 0 && (table == "local" || string(rule["table"]) == "255"):
			local = true
		case priority == 32766 && (table == "main" || string(rule["table"]) == "254"):
			main = true
		case priority == 32767 && (table == "default" || string(rule["table"]) == "253"):
		default:
			return errors.New("automatic full tunneling requires the standard local/main/default routing policy")
		}
	}
	if !local || !main {
		return errors.New("automatic full tunneling requires local and main routing rules")
	}
	return nil
}

func (r *Runner) routes(ctx context.Context, family int, selector ...string) ([]routeInfo, error) {
	args := append([]string{"-j", "-N", "-" + strconv.Itoa(family), "route", "show", "table", "main"}, selector...)
	output, err := r.invoke(ctx, "ip", args, "")
	if err != nil {
		return nil, err
	}
	var routes []routeInfo
	if err := json.Unmarshal([]byte(output), &routes); err != nil {
		return nil, fmt.Errorf("decode routes: %w", err)
	}
	return routes, nil
}

func (r *Runner) ensureEscape(ctx context.Context, endpoint endpointState) error {
	family := 4
	if netip.MustParseAddr(endpoint.IP).Is6() {
		family = 6
	}
	routes, err := r.routes(ctx, family, "exact", endpoint.prefix())
	if err != nil {
		return err
	}
	if len(routes) > 1 {
		return errors.New("multiple endpoint host routes are unsupported")
	}
	for _, route := range routes {
		if !validInterface(route.Device) || route.Device == r.state.Interface || route.Type != "" && route.Type != "unicast" || route.multipath() {
			return errors.New("existing endpoint host route does not provide a supported physical escape")
		}
		link, err := r.link(ctx, route.Device)
		if err != nil {
			return err
		}
		if link == nil || link.LinkInfo.Kind == "tun" || link.LinkInfo.Kind == "wireguard" {
			return errors.New("existing endpoint host route uses a tunnel interface")
		}
		return nil // A pre-existing host route is never claimed or deleted.
	}
	output, err := r.invoke(ctx, "ip", []string{"-j", "-" + strconv.Itoa(family), "route", "get", endpoint.IP}, "")
	if err != nil {
		return err
	}
	var candidates []routeInfo
	if err := json.Unmarshal([]byte(output), &candidates); err != nil || len(candidates) != 1 {
		return errors.New("could not determine a unique physical endpoint route")
	}
	chosen := candidates[0]
	if chosen.Device == r.state.Interface && r.state.Interface != "" {
		candidates, err = r.routes(ctx, family, "default")
		if err != nil {
			return err
		}
		chosen = routeInfo{}
		for _, candidate := range candidates {
			if candidate.Device == r.state.Interface {
				continue
			}
			if chosen.Device == "" || candidate.Metric < chosen.Metric {
				chosen = candidate
			} else if candidate.Metric == chosen.Metric {
				return errors.New("multiple equal-cost physical gateways are unsupported")
			}
		}
	}
	if !validInterface(chosen.Device) || chosen.Type != "" && chosen.Type != "unicast" || chosen.multipath() {
		return errors.New("no supported physical gateway route for the tunnel endpoint")
	}
	link, err := r.link(ctx, chosen.Device)
	if err != nil {
		return err
	}
	if link == nil || link.LinkInfo.Kind == "tun" || link.LinkInfo.Kind == "wireguard" {
		return errors.New("tunnel endpoint escape must use a non-tunnel interface")
	}
	if chosen.Gateway != "" {
		gateway, err := netip.ParseAddr(chosen.Gateway)
		if err != nil || gateway.Is4() != (family == 4) {
			return errors.New("invalid physical gateway")
		}
	}
	return r.ensureRoute(ctx, action{
		Kind: "escape", Family: family, Destination: endpoint.prefix(), Interface: chosen.Device, Index: link.Index,
		LinkKind: link.LinkInfo.Kind, LinkAddress: link.Address, Gateway: chosen.Gateway,
	})
}

func (r *Runner) ensureRoute(ctx context.Context, a action) error {
	routes, err := r.routes(ctx, a.Family, "exact", a.Destination)
	if err != nil {
		return err
	}
	if len(routes) > 1 {
		return fmt.Errorf("multiple routes conflict with owned destination %s", a.Destination)
	}
	recorded := false
	for _, existing := range r.state.Undo {
		recorded = recorded || existing == a
	}
	for _, route := range routes {
		if recorded && r.ownedRoute(route, a) {
			return nil
		}
		return fmt.Errorf("refusing to overwrite existing route %s", a.Destination)
	}
	if !recorded {
		if err := r.record(a); err != nil {
			return err
		}
	}
	_, err = r.invoke(ctx, "ip", r.routeArguments("add", a), "")
	return err
}

func (r *Runner) ownedRoute(route routeInfo, a action) bool {
	protocol := strings.Trim(string(route.Protocol), `"`)
	return route.Device == a.Interface && route.Gateway == a.Gateway && route.Metric == r.state.Metric && protocol == strconv.Itoa(routeProtocol)
}

func (r *Runner) routeArguments(operation string, a action) []string {
	args := []string{"-" + strconv.Itoa(a.Family), "route", operation, a.Destination, "table", "main"}
	if a.Gateway != "" {
		args = append(args, "via", a.Gateway)
	}
	return append(args, "dev", a.Interface, "proto", strconv.Itoa(routeProtocol), "metric", strconv.Itoa(r.state.Metric))
}

func (r *Runner) cleanupMatching(ctx context.Context, wanted func(action) bool) error {
	for index := len(r.state.Undo) - 1; index >= 0; index-- {
		a := r.state.Undo[index]
		if !wanted(a) {
			continue
		}
		if err := r.undo(ctx, a); err != nil {
			return fmt.Errorf("restore %s on %s: %w", a.Kind, a.Interface, err)
		}
		previous := append([]action(nil), r.state.Undo...)
		r.state.Undo = append(r.state.Undo[:index], r.state.Undo[index+1:]...)
		if err := r.persist(); err != nil {
			r.state.Undo = previous
			return err
		}
	}
	return nil
}

func (r *Runner) undo(ctx context.Context, a action) error {
	link, err := r.actionLink(ctx, a)
	if err != nil {
		return err
	}
	if link == nil && a.Kind == "escape" && !stableLinkIdentity(a) {
		namedLink, namedErr := r.link(ctx, a.Interface)
		if namedErr != nil {
			return namedErr
		}
		if namedLink != nil && namedLink.Index == a.Index {
			link = namedLink
		} else {
			indexedLink, indexErr := r.linkByIndex(ctx, a.Index)
			if indexErr != nil {
				return indexErr
			}
			if indexedLink != nil {
				return errors.New("cannot verify renamed MAC-less escape interface ownership")
			}
		}
	}
	// The kernel removes interface-bound addresses/routes/DNS when a TUN is
	// destroyed. Never apply stale restoration to an unrelated reused name.
	if link == nil {
		return nil
	}
	a.Interface = link.Name
	switch a.Kind {
	case "alias":
		_, err := r.invoke(ctx, "ip", []string{"link", "set", "dev", a.Interface, "alias", a.PreviousAlias}, "")
		return err
	case "route", "escape", "dns-route":
		routes, err := r.routes(ctx, a.Family, "exact", a.Destination)
		if err != nil {
			return err
		}
		for _, route := range routes {
			if r.ownedRoute(route, a) {
				_, err := r.invoke(ctx, "ip", r.routeArguments("del", a), "")
				return err
			}
		}
	case "address":
		addresses, err := r.addresses(ctx, a.Interface)
		if err != nil {
			return err
		}
		if contains(addresses, a.Address) {
			_, err := r.invoke(ctx, "ip", []string{"-4", "address", "del", a.Address, "dev", a.Interface}, "")
			return err
		}
	case "dns":
		_, err := r.invoke(ctx, "resolvectl", []string{"revert", a.Interface}, "")
		return err
	case "link":
		state := "down"
		if a.WasUp {
			state = "up"
		}
		_, err := r.invoke(ctx, "ip", []string{"link", "set", "dev", a.Interface, "mtu", strconv.Itoa(a.MTU), state}, "")
		return err
	default:
		return errors.New("unsupported journal action")
	}
	return nil
}

func (r *Runner) actionLink(ctx context.Context, a action) (*linkInfo, error) {
	links, err := r.links(ctx)
	if err != nil {
		return nil, err
	}
	if a.LinkAlias != "" {
		for index := range links {
			if links[index].Alias == a.LinkAlias {
				return &links[index], nil
			}
		}
		return nil, nil
	}
	for index := range links {
		if links[index].Name == a.Interface && links[index].Index == a.Index &&
			sameLinkIdentity(a, &links[index]) {
			return &links[index], nil
		}
	}
	for index := range links {
		if links[index].Index == a.Index && sameLinkIdentity(a, &links[index]) {
			return &links[index], nil
		}
	}
	return nil, nil
}

func sameLinkIdentity(a action, link *linkInfo) bool {
	return stableLinkIdentity(a) &&
		strings.EqualFold(a.LinkAddress, link.Address) &&
		a.LinkKind == link.LinkInfo.Kind
}

func stableLinkIdentity(a action) bool {
	return a.LinkAddress != "" && a.LinkAddress != "00:00:00:00:00:00"
}
