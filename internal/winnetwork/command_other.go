//go:build !windows

package winnetwork

import "os/exec"

func hideNetworkCommand(*exec.Cmd) {}
