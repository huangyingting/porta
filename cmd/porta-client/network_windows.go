package main

import (
	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/winnetwork"
)

var _ clientapp.NetworkInterfacePreparer = (*winnetwork.Runner)(nil)
var _ clientapp.NetworkReconfigurer = (*winnetwork.Runner)(nil)
var _ clientapp.NetworkRecoveryEndpoints = (*winnetwork.Runner)(nil)

func newNetworkConfigurator(statePath string) (clientapp.NetworkConfigurator, error) {
	if statePath == "" {
		var err error
		statePath, err = winnetwork.DefaultStatePath()
		if err != nil {
			return nil, err
		}
	}
	return winnetwork.NewRunner(statePath)
}
