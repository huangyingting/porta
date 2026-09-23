//go:build !windows

package winnetwork

import (
	"context"
	"errors"
	"os/exec"
)

func networkCommand(context.Context, string, []string) (*exec.Cmd, error) {
	return nil, errors.New("Windows network configuration is unavailable on this platform")
}

func hideNetworkCommand(*exec.Cmd) {}
