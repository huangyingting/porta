//go:build linux && !android

package clientid

import (
	"fmt"
	"os"
)

func Current() (string, error) {
	return fromMachineIDFile("/etc/machine-id")
}

func fromMachineIDFile(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Linux machine ID: %w", err)
	}
	id, err := derive("linux", string(value))
	if err != nil {
		return "", fmt.Errorf("read Linux machine ID: %w", err)
	}
	return id, nil
}
