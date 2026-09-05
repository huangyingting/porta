//go:build linux && !android

package clientid

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func Current() (*Identity, error) {
	name, err := fromHostname(os.Hostname)
	if err != nil {
		return nil, err
	}
	path, err := identityPath()
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreate(path, passthrough, passthrough)
	if err != nil {
		return nil, err
	}
	return New(key, name)
}

func identityPath() (string, error) {
	if os.Geteuid() == 0 {
		return "/var/lib/porta/client-identity.json", nil
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config directory: %w", err)
	}
	if !filepath.IsAbs(directory) {
		return "", errors.New("user config directory is not absolute")
	}
	return filepath.Join(directory, "porta", "client-identity.json"), nil
}

func passthrough(value []byte) ([]byte, error) {
	return append([]byte(nil), value...), nil
}

func withFileLock(path string, action func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(file.Fd()), unix.LOCK_UN) //nolint:errcheck
	return action()
}
