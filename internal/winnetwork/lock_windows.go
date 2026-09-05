//go:build windows

package winnetwork

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func lockJournal(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open network ownership lock: %w", err)
	}
	var overlap windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap); err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrStateInUse
		}
		return nil, fmt.Errorf("lock network ownership: %w", err)
	}
	return file, nil
}
