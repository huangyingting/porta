package clientid

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func Current() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open Windows machine identity: %w", err)
	}
	defer key.Close()
	value, kind, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("read Windows MachineGuid: %w", err)
	}
	if kind != registry.SZ {
		return "", errors.New("Windows MachineGuid must be a registry string")
	}
	return derive("windows", value)
}
