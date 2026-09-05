package winnetwork

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/huangyingting/porta/internal/tunnel"
)

// RunHelper is the shared implementation used by the explicit Windows scripts.
// A client executable must dispatch this before its normal argument parser.
// The same executable path must carry the transport: WFP exempts that app only.
func RunHelper(ctx context.Context, args []string) (handled bool, err error) {
	if len(args) == 0 || (args[0] != "network-up" && args[0] != "network-down") {
		return false, nil
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	statePath := flags.String("state-path", "", "persistent network ownership journal")
	name := flags.String("interface", "Porta", "dedicated tunnel interface")
	server := flags.String("server-address", "", "numeric transport IP:port")
	address := flags.String("address", "", "IPv4 tunnel CIDR")
	dns := flags.String("dns", "", "IPv4 tunnel DNS")
	mtu := flags.Int("mtu", 1100, "negotiated tunnel MTU")
	if err := flags.Parse(args[1:]); err != nil {
		return true, err
	}
	if flags.NArg() != 0 {
		return true, fmt.Errorf("unexpected network helper arguments")
	}
	runner, err := NewRunner(*statePath)
	if err != nil {
		return true, err
	}
	if args[0] == "network-down" {
		if runner.state.Interface != "" && runner.state.Interface != *name {
			return true, fmt.Errorf("network journal belongs to interface %q", runner.state.Interface)
		}
		if err := runner.Down(ctx); err != nil {
			return true, err
		}
		_, err := fmt.Fprintln(os.Stdout, "PORTA_NETWORK_DOWN_OK")
		return true, err
	}
	remote, err := netip.ParseAddrPort(*server)
	if err != nil {
		return true, fmt.Errorf("numeric server-address is required: %w", err)
	}
	prefix, err := netip.ParsePrefix(*address)
	if err != nil {
		return true, fmt.Errorf("invalid tunnel address: %w", err)
	}
	resolver, err := netip.ParseAddr(*dns)
	if err != nil {
		return true, fmt.Errorf("invalid tunnel DNS: %w", err)
	}
	if err := runner.Up(ctx, *name, net.TCPAddrFromAddrPort(remote), tunnel.Lease{Address: prefix, DNS: resolver, MTU: *mtu}); err != nil {
		return true, err
	}
	_, err = fmt.Fprintln(os.Stdout, "PORTA_NETWORK_UP_OK")
	return true, err
}
