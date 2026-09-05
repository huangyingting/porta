//go:build !windows

package winnetwork

import (
	"os"
	"path/filepath"
)

func replaceJournal(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
