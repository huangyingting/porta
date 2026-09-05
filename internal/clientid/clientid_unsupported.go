//go:build (!linux && !windows) || android

package clientid

import (
	"fmt"
	"runtime"
)

func Current() (*Identity, error) {
	return nil, fmt.Errorf("automatic device identity is not supported on %s", runtime.GOOS)
}
