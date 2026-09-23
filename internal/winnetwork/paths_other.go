//go:build !windows

package winnetwork

import (
	"errors"
	"os"
)

func PrepareProtectedDirectory(path string) (*os.File, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func ValidateProtectedDirectory(*os.File) error { return nil }

func OpenProtectedFile(path string, write bool) (*os.File, error) {
	flags := os.O_RDONLY
	if write {
		flags = os.O_RDWR
	}
	return os.OpenFile(path, flags, 0o600)
}

func CreateProtectedFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
}

func RemoveProtectedFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
