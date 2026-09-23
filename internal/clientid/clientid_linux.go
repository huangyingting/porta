//go:build linux && !android

package clientid

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func Current() (*Identity, error) {
	return CurrentAt("")
}

func CurrentAt(path string) (*Identity, error) {
	name, err := fromHostname(os.Hostname)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path, err = identityPath()
		if err != nil {
			return nil, err
		}
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("device identity path must be absolute")
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

func prepareIdentityStorage(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create device identity directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(directory, &stat); err != nil {
		return err
	}
	if !info.IsDir() || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
		return fmt.Errorf("device identity directory must be owned by UID %d and not writable by others (owner=%d mode=%#o)", os.Geteuid(), stat.Uid, stat.Mode)
	}
	return nil
}

func secureIdentityFile(path string) error {
	file, err := openIdentityFile(path, unix.O_RDONLY)
	if err != nil {
		return err
	}
	return file.Close()
}

func readIdentityFile(path string) ([]byte, error) {
	file, err := openIdentityFile(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err == nil && len(data) > 64<<10 {
		return nil, errors.New("device identity file is too large")
	}
	return data, err
}

func openIdentityFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&0077 != 0 {
		_ = file.Close()
		return nil, errors.New("device identity must be a private, singly linked regular file owned by the current user")
	}
	return file, nil
}

func withFileLock(path string, action func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := openIdentityFile(path, unix.O_CREAT|unix.O_RDWR)
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
