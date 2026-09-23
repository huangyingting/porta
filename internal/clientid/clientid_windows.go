//go:build windows

package clientid

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/winnetwork"
	"golang.org/x/sys/windows"
)

const maxWindowsIdentitySize = 64 << 10

func Current() (*Identity, error) {
	name, err := fromHostname(os.Hostname)
	if err != nil {
		return nil, err
	}
	path, err := identityPath()
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreateWindows(path, protectMachine, unprotectMachine)
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

func prepareIdentityStorage(path string) error {
	directory, err := winnetwork.OpenOrCreateProtectedDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("validate device identity directory: %w", err)
	}
	return directory.Close()
}

func secureIdentityFile(path string) error {
	file, err := openPrivateIdentityFile(path)
	if err != nil {
		return err
	}
	return file.Close()
}

func readIdentityFile(path string) ([]byte, error) {
	file, err := openPrivateIdentityFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxWindowsIdentitySize {
		return nil, errors.New("device identity file exceeds 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWindowsIdentitySize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxWindowsIdentitySize {
		return nil, errors.New("device identity file exceeds 64 KiB")
	}
	return data, nil
}

func openPrivateIdentityFile(path string) (*os.File, error) {
	file, err := winnetwork.OpenRegularFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ)
	if err != nil {
		return nil, err
	}
	if err := winnetwork.ValidateProtectedFile(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func loadOrCreateWindows(path string, protect, unprotect func([]byte) ([]byte, error)) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("device identity path is required")
	}
	var key *ecdsa.PrivateKey
	err := withFileLock(path+".lock", func() error {
		data, err := readIdentityFile(path)
		if err == nil {
			key, err = decodeState(data, unprotect)
			return err
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read device identity: %w", err)
		}
		key, err = deviceauth.GenerateKey()
		if err != nil {
			return err
		}
		return persistWindowsIdentity(path, key, protect)
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

func persistWindowsIdentity(path string, key *ecdsa.PrivateKey, protect func([]byte) ([]byte, error)) (result error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(encoded)
	protected, err := protect(encoded)
	if err != nil {
		return fmt.Errorf("protect device identity key: %w", err)
	}
	defer clear(protected)
	data, err := json.MarshalIndent(state{Version: stateVersion, PrivateKey: base64.RawStdEncoding.EncodeToString(protected)}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	defer clear(data)
	if len(data) > maxWindowsIdentitySize {
		return errors.New("device identity file exceeds 64 KiB")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	pending := filepath.Join(filepath.Dir(path), ".device-identity-"+hex.EncodeToString(nonce[:])+".pending")
	file, err := winnetwork.CreateProtectedFile(pending)
	if err != nil {
		return fmt.Errorf("create private device identity temporary file: %w", err)
	}
	defer func() {
		if err := winnetwork.RemoveProtectedFile(pending); err != nil {
			result = errors.Join(result, fmt.Errorf("remove device identity temporary file: %w", err))
		}
	}()
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return fmt.Errorf("flush device identity: %w", err)
	}
	source, err := windows.UTF16PtrFromString(pending)
	if err != nil {
		return err
	}
	destination, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// A new identity must never replace an object that appeared after the read.
	if err := windows.MoveFileEx(source, destination, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("publish device identity: %w", err)
	}
	return secureIdentityFile(path)
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
	// Keep the verified directory pinned without delete sharing until all reads
	// and writes finish; a pathname check alone races directory replacement.
	directory, err := winnetwork.OpenOrCreateProtectedDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	file, err := winnetwork.CreateProtectedFile(path)
	if errors.Is(err, os.ErrExist) {
		file, err = winnetwork.OpenProtectedFile(path, true)
	}
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
