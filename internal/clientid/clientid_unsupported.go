//go:build (!linux && !windows) || android

package clientid

import (
	"fmt"
	"runtime"
)

func Current() (*Identity, error) {
	return nil, fmt.Errorf("automatic device identity is not supported on %s", runtime.GOOS)
}

func prepareIdentityStorage(string) error {
	return fmt.Errorf("persistent device identity is not supported on %s", runtime.GOOS)
}

func secureIdentityFile(string) error {
	return fmt.Errorf("persistent device identity is not supported on %s", runtime.GOOS)
}

func withFileLock(string, func() error) error {
	return fmt.Errorf("persistent device identity is not supported on %s", runtime.GOOS)
}
