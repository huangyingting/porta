//go:build (!linux && !windows) || android

package clientid

import (
	"fmt"
	"runtime"
)

func Current() (string, error) {
	return "", fmt.Errorf("automatic OS device identity is not supported on %s", runtime.GOOS)
}
