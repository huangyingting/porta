//go:build !windows

package winnetwork

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Non-Windows builds use this only for isolated runner tests; native leak
// protection remains unavailable outside the supported Windows architectures.
func lockJournal(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open network ownership lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrStateInUse
		}
		return nil, fmt.Errorf("lock network ownership: %w", err)
	}
	return file, nil
}
