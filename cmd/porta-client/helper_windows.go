package main

import (
	"context"
	"flag"
	"io"

	"github.com/huangyingting/porta/internal/winnetwork"
)

func runNetworkHelper(ctx context.Context, args []string) (bool, error) {
	if handled, err := winnetwork.RunHelper(ctx, args); handled {
		return true, err
	}
	if requiresWintun(args) {
		if err := winnetwork.PrepareWintun(); err != nil {
			return true, err
		}
	}
	return false, nil
}

// Parse rather than searching arguments: paths and URLs can themselves look
// like flags, and repeated boolean flags use the last value. Unknown options
// fail closed by requiring verification before the main parser handles them.
func requiresWintun(args []string) bool {
	flags := flag.NewFlagSet("wintun-boundary", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cleanup := flags.Bool("cleanup-network", false, "")
	for _, name := range []string{"server", "transport", "interface", "identity", "ca", "thumbprint", "reconnect-max-delay", "network-state"} {
		flags.String(name, "", "")
	}
	for _, name := range []string{"insecure", "reconnect", "manual-network"} {
		flags.Bool(name, false, "")
	}
	err := flags.Parse(args)
	if err == flag.ErrHelp {
		return false
	}
	return err != nil || !*cleanup
}
