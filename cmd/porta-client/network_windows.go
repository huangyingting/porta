package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/winnetwork"
)

var _ clientapp.NetworkInterfacePreparer = (*winnetwork.Runner)(nil)
var _ clientapp.NetworkReconfigurer = (*winnetwork.Runner)(nil)
var _ clientapp.NetworkRecoveryEndpoints = (*winnetwork.Runner)(nil)

func newNetworkConfigurator(statePath string) (clientapp.NetworkConfigurator, error) {
	if statePath == "" {
		directory, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("locate network recovery state: %w", err)
		}
		statePath = filepath.Join(directory, "Porta", "network-state.json")
	}
	return winnetwork.NewRunner(statePath)
}
