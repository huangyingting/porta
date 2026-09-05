//go:build windows

package clientid

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
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
	key, err := loadOrCreate(path, protectMachine, unprotectMachine)
	if err != nil {
		return nil, err
	}
	return New(key, name)
}

func identityPath() (string, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", fmt.Errorf("locate ProgramData: %w", err)
	}
	if !filepath.IsAbs(programData) {
		return "", errors.New("ProgramData path is not absolute")
	}
	return filepath.Join(programData, "Porta", "client-identity.json"), nil
}

func protectMachine(plain []byte) ([]byte, error) {
	return cryptMachineData(plain, true)
}

func unprotectMachine(protected []byte) ([]byte, error) {
	return cryptMachineData(protected, false)
}

func cryptMachineData(data []byte, protect bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("device identity key is empty")
	}
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	var err error
	if protect {
		name, nameErr := windows.UTF16PtrFromString("Porta native device identity")
		if nameErr != nil {
			return nil, nameErr
		}
		err = windows.CryptProtectData(
			&input, name, nil, 0, nil,
			windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE,
			&output,
		)
	} else {
		err = windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	result := make([]byte, output.Size)
	copy(result, unsafe.Slice(output.Data, output.Size))
	return result, nil
}

func withFileLock(path string, action func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open device identity lock: %w", err)
	}
	defer file.Close()
	var overlap windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlap); err != nil {
		return fmt.Errorf("lock device identity: %w", err)
	}
	return action()
}
