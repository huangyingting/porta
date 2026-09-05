//go:build !linux && !windows

package main

import (
	"errors"

	"github.com/huangyingting/porta/internal/clientapp"
)

func newNetworkConfigurator(string) (clientapp.NetworkConfigurator, error) {
	return nil, errors.New("automatic network configuration is supported only on Linux and Windows; use --manual-network")
}
