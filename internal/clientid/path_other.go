//go:build !linux || android

package clientid

import "errors"

func CurrentAt(path string) (*Identity, error) {
	if path != "" {
		return nil, errors.New("an explicit device identity path is only supported on Linux")
	}
	return Current()
}
