//go:build linux

// Package linuxnetwork configures an IPv4 host tunnel with a persistent,
// fail-closed nftables OUTPUT filter. It requires root, iproute2, nftables, and
// systemd-resolved's local stub resolver. Forwarded/container traffic is outside
// the OUTPUT filter's scope. IPv6 payload traffic is blocked, not tunneled.
package linuxnetwork

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huangyingting/porta/internal/tunnel"
)

type Runner struct {
	mu         sync.Mutex
	statePath  string
	lock       *os.File
	state      networkState
	runCommand func(context.Context, string, []string, string) (string, error)
	checkDNS   func() error
}

// NewRunner opens an exclusively locked recovery journal. The parent directory
// must not be writable by other users. Existing state is retained, not silently
// torn down: a subsequent Prepare/Reconfigure resumes protection, and Down
// explicitly restores the network.
func NewRunner(statePath string) (*Runner, error) {
	r := &Runner{statePath: statePath}
	if err := r.openState(); err != nil {
		return nil, err
	}
	return r, nil
}

// Prepare activates protection before VPN routes are installed. The first
// handshake and DNS bootstrap can happen before Prepare; they are not protected.
// remoteAddr must be a resolved TCP/UDP address. Subsequent reconnects must pin
// their transport to a prepared endpoint: physical DNS is blocked after Prepare.
// Both TCP and UDP at the exact IP/port are permitted for H3/H2 failover.
// Additional calls admit new endpoints without removing the current guard.
func (r *Runner) Prepare(ctx context.Context, remoteAddr net.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensureLock(); err != nil {
		return err
	}
	return r.prepareLocked(ctx, remoteAddr)
}

// RecoveryEndpoints returns the journaled transport endpoints without resolving
// DNS or removing an existing guard. A caller restarting after a crash can use
// these literal addresses with the original TLS server name.
func (r *Runner) RecoveryEndpoints() []net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	endpoints := make([]net.Addr, 0, len(r.state.Endpoints))
	for _, endpoint := range r.state.Endpoints {
		endpoints = append(endpoints, &net.TCPAddr{IP: net.ParseIP(endpoint.IP), Port: endpoint.Port})
	}
	return endpoints
}

func (r *Runner) prepareLocked(ctx context.Context, remoteAddr net.Addr) error {
	endpoint, err := parseEndpoint(remoteAddr)
	if err != nil {
		return err
	}
	if err := r.preflight(ctx, endpoint); err != nil {
		return err
	}
	if r.state.Table == "" {
		if err := r.initializeState(); err != nil {
			return err
		}
	}
	found := false
	for _, existing := range r.state.Endpoints {
		found = found || existing == endpoint
	}
	if !found {
		if len(r.state.Endpoints) >= 256 {
			return errors.New("protected endpoint limit reached; explicit cleanup is required")
		}
		r.state.Endpoints = append(r.state.Endpoints, endpoint)
		if err := r.persist(); err != nil {
			r.state.Endpoints = r.state.Endpoints[:len(r.state.Endpoints)-1]
			return err
		}
	}
	// The firewall is installed before any routing change. Replacing its rules
	// is one nft transaction, never a delete/recreate protection gap.
	if err := r.protect(ctx); err != nil {
		return err
	}
	return r.ensureEscape(ctx, endpoint)
}

func (r *Runner) Up(ctx context.Context, interfaceName string, remoteAddr net.Addr, lease tunnel.Lease) error {
	return r.Reconfigure(ctx, interfaceName, remoteAddr, lease)
}

// Reconfigure updates a lease and MTU while the previous firewall remains
// active. On any error, protection and recovery state remain in place. Only an
// intentional Down removes protection.
func (r *Runner) Reconfigure(ctx context.Context, interfaceName string, remoteAddr net.Addr, lease tunnel.Lease) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := validateLease(interfaceName, lease); err != nil {
		return err
	}
	if err := r.ensureLock(); err != nil {
		return err
	}
	if err := r.prepareLocked(ctx, remoteAddr); err != nil {
		return err
	}
	endpoint, _ := parseEndpoint(remoteAddr)
	if endpoint.IP == lease.DNS.String() {
		return errors.New("tunnel DNS cannot be the physical transport endpoint")
	}
	link, err := r.link(ctx, interfaceName)
	if err != nil {
		return err
	}
	if link == nil || link.LinkInfo.Kind != "tun" || !contains(link.Flags, "POINTOPOINT") {
		return errors.New("automatic networking requires a point-to-point TUN interface")
	}
	linkAlias := "porta:" + r.state.Table
	previousName, previousIndex := r.state.Interface, r.state.Index
	if previousName == "" {
		for _, a := range r.state.Undo {
			if a.Kind == "link" {
				previousName, previousIndex = a.Interface, a.Index
				break
			}
		}
	}
	if previousName != "" &&
		(previousName != interfaceName || previousIndex != link.Index || link.Alias != linkAlias) {
		// Stale/recreated devices are cleaned while the existing OUTPUT guard
		// remains installed. Escape routes stay available for reconnect.
		if err := r.cleanupMatching(ctx, func(a action) bool { return a.Kind != "escape" }); err != nil {
			return fmt.Errorf("clean previous tunnel: %w", err)
		}
		r.state.Interface, r.state.Index = "", 0
		if err := r.persist(); err != nil {
			return err
		}
		link, err = r.link(ctx, interfaceName)
		if err != nil {
			return err
		}
		if link == nil || link.LinkInfo.Kind != "tun" || !contains(link.Flags, "POINTOPOINT") {
			return errors.New("automatic networking requires a point-to-point TUN interface")
		}
	}
	if link.Alias != linkAlias {
		if link.Alias != "" {
			return errors.New("automatic networking refuses to overwrite a pre-existing interface alias")
		}
		if err := r.record(action{
			Kind: "alias", Interface: interfaceName, Index: link.Index,
			LinkKind: link.LinkInfo.Kind, LinkAddress: link.Address,
			LinkAlias: linkAlias, PreviousAlias: link.Alias,
		}); err != nil {
			return err
		}
		if _, err := r.invoke(ctx, "ip", []string{"link", "set", "dev", interfaceName, "alias", linkAlias}, ""); err != nil {
			return err
		}
		link.Alias = linkAlias
	}
	if !r.hasAction("link", interfaceName, "") {
		addresses, err := r.addresses(ctx, interfaceName)
		if err != nil {
			return err
		}
		if len(addresses) != 0 {
			return errors.New("refusing to configure a TUN interface with pre-existing addresses")
		}
		if err := r.record(action{
			Kind: "link", Interface: interfaceName, Index: link.Index,
			LinkKind: link.LinkInfo.Kind, LinkAddress: link.Address,
			LinkAlias: link.Alias, MTU: link.MTU, WasUp: contains(link.Flags, "UP"),
		}); err != nil {
			return err
		}
	}
	if r.state.Interface != interfaceName || r.state.Index != link.Index {
		r.state.Interface, r.state.Index = interfaceName, link.Index
		if err := r.persist(); err != nil {
			return err
		}
	}
	if _, err := r.invoke(ctx, "ip", []string{"link", "set", "dev", interfaceName, "mtu", strconv.Itoa(lease.MTU), "up"}, ""); err != nil {
		return err
	}
	address := lease.Address.String()
	if !r.hasAction("address", interfaceName, address) {
		if err := r.record(action{
			Kind: "address", Interface: interfaceName, Index: link.Index,
			LinkKind: link.LinkInfo.Kind, LinkAddress: link.Address,
			LinkAlias: link.Alias, Address: address,
		}); err != nil {
			return err
		}
	}
	addresses, err := r.addresses(ctx, interfaceName)
	if err != nil {
		return err
	}
	if !contains(addresses, address) {
		if _, err := r.invoke(ctx, "ip", []string{"-4", "address", "add", address, "dev", interfaceName, "noprefixroute"}, ""); err != nil {
			return err
		}
	}
	for _, destination := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := r.ensureRoute(ctx, action{
			Kind: "route", Family: 4, Destination: destination, Interface: interfaceName, Index: link.Index,
			LinkKind: link.LinkInfo.Kind, LinkAddress: link.Address, LinkAlias: link.Alias,
		}); err != nil {
			return err
		}
	}
	dnsDestination := netip.PrefixFrom(lease.DNS, 32).String()
	if err := r.ensureRoute(ctx, action{
		Kind: "dns-route", Family: 4, Destination: dnsDestination, Interface: interfaceName, Index: link.Index,
		LinkKind: link.LinkInfo.Kind, LinkAddress: link.Address, LinkAlias: link.Alias,
	}); err != nil {
		return fmt.Errorf("route tunnel DNS: %w", err)
	}
	if !r.hasAction("dns", interfaceName, "") {
		for _, property := range []string{"dns", "domain"} {
			output, err := r.invoke(ctx, "resolvectl", []string{property, interfaceName}, "")
			if err != nil {
				return err
			}
			_, value, ok := strings.Cut(strings.TrimSpace(output), ":")
			if !ok || strings.TrimSpace(value) != "" {
				return errors.New("refusing to overwrite pre-existing TUN resolver configuration")
			}
		}
		if err := r.record(action{
			Kind: "dns", Interface: interfaceName, Index: link.Index,
			LinkKind: link.LinkInfo.Kind, LinkAddress: link.Address, LinkAlias: link.Alias,
		}); err != nil {
			return err
		}
	}
	for _, args := range [][]string{
		{"dns", interfaceName, lease.DNS.String()},
		{"domain", interfaceName, "~."},
		{"default-route", interfaceName, "yes"},
	} {
		if _, err := r.invoke(ctx, "resolvectl", args, ""); err != nil {
			return err
		}
	}
	previousEndpoints := r.state.Endpoints
	r.state.Endpoints = []endpointState{endpoint}
	if err := r.persist(); err != nil {
		r.state.Endpoints = previousEndpoints
		return err
	}
	if err := r.protect(ctx); err != nil {
		return err
	}
	return r.cleanupMatching(ctx, func(a action) bool {
		return (a.Kind == "address" && a.Address != address) ||
			(a.Kind == "dns-route" && a.Destination != dnsDestination) ||
			(a.Kind == "escape" && a.Destination != endpoint.prefix())
	})
}

// Down is an explicit disconnect/recovery operation. Failed cleanup is
// retryable, including after process restart. The firewall is removed LAST and
// remains installed if any route, address, DNS, or link restoration fails.
func (r *Runner) Down(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensureLock(); err != nil {
		return err
	}
	if err := r.cleanupMatching(ctx, func(action) bool { return true }); err != nil {
		return err
	}
	if r.state.Table != "" {
		exists, err := r.tableExists(ctx)
		if err != nil {
			return err
		}
		if exists {
			if _, err := r.invoke(ctx, "nft", []string{"-f", "-"}, "delete table inet "+r.state.Table+"\n"); err != nil {
				return err
			}
		}
	}
	if err := r.removeState(); err != nil {
		return err
	}
	r.state = networkState{}
	return r.releaseLock()
}

func (r *Runner) preflight(ctx context.Context, endpoint endpointState) error {
	check := r.checkDNS
	if check == nil {
		check = checkStubResolver
	}
	if err := check(); err != nil {
		return err
	}
	if _, err := r.invoke(ctx, "resolvectl", []string{"status"}, ""); err != nil {
		return fmt.Errorf("systemd-resolved is required for automatic DNS: %w", err)
	}
	if err := r.checkRules(ctx, 4); err != nil {
		return err
	}
	if netip.MustParseAddr(endpoint.IP).Is6() {
		return r.checkRules(ctx, 6)
	}
	return nil
}

func (r *Runner) invoke(ctx context.Context, name string, args []string, input string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if r.runCommand != nil {
		return r.runCommand(commandCtx, name, args, input)
	}
	if os.Geteuid() != 0 {
		return "", errors.New("automatic Linux networking requires root")
	}
	command := exec.CommandContext(commandCtx, name, args...)
	command.Stdin = strings.NewReader(input)
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		if commandCtx.Err() != nil {
			return "", fmt.Errorf("%s: %w", name, commandCtx.Err())
		}
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func parseEndpoint(address net.Addr) (endpointState, error) {
	if address == nil {
		return endpointState{}, errors.New("a resolved tunnel endpoint is required")
	}
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		return endpointState{}, errors.New("invalid tunnel endpoint")
	}
	ip, err := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || !ip.IsGlobalUnicast() || ip.Zone() != "" || portErr != nil || port < 1 || port > 65535 || port == 53 || port == 853 {
		return endpointState{}, errors.New("tunnel endpoint requires a unicast IP and non-DNS TCP/UDP port")
	}
	switch address.Network() {
	case "tcp", "tcp4", "tcp6":
	case "udp", "udp4", "udp6":
	default:
		return endpointState{}, errors.New("tunnel endpoint must be TCP or UDP")
	}
	return endpointState{IP: ip.Unmap().String(), Port: port}, nil
}

func validateLease(name string, lease tunnel.Lease) error {
	if !validInterface(name) {
		return errors.New("invalid Linux TUN interface name")
	}
	if !lease.Address.IsValid() || !lease.Address.Addr().Is4() || !lease.Address.Addr().IsGlobalUnicast() ||
		!lease.DNS.IsValid() || !lease.DNS.Is4() || !lease.DNS.IsGlobalUnicast() || lease.DNS == lease.Address.Addr() || lease.MTU < 576 || lease.MTU > 65535 {
		return errors.New("automatic Linux networking requires an IPv4 unicast lease and DNS server, and MTU 576..65535")
	}
	return nil
}

func validInterface(name string) bool {
	if len(name) == 0 || len(name) > 15 || name == "lo" {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
