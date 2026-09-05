package main

import (
	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/linuxnetwork"
)

var _ clientapp.NetworkPreparer = (*linuxnetwork.Runner)(nil)
var _ clientapp.NetworkReconfigurer = (*linuxnetwork.Runner)(nil)
var _ clientapp.NetworkRecoveryEndpoints = (*linuxnetwork.Runner)(nil)

func newNetworkConfigurator(statePath string) (clientapp.NetworkConfigurator, error) {
	if statePath == "" {
		statePath = "/var/lib/porta/network-state.json"
	}
	return linuxnetwork.NewRunner(statePath)
}
