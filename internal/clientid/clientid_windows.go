//go:build windows

package clientid

import (
	"errors"
	"fmt"
	"io"
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

func prepareIdentityStorage(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create device identity directory: %w", err)
	}
	handle, err := openIdentityPath(directory, true, 0, windows.OPEN_EXISTING)
	if err != nil {
		return fmt.Errorf("secure device identity directory: %w", err)
	}
	return windows.CloseHandle(handle)
}

func secureIdentityFile(path string) error {
	handle, err := openIdentityPath(path, false, 0, windows.OPEN_EXISTING)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

func readIdentityFile(path string) ([]byte, error) {
	handle, err := openIdentityPath(path, false, windows.GENERIC_READ, windows.OPEN_EXISTING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	return io.ReadAll(file)
}

func openIdentityPath(path string, directory bool, access, creation uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, err := windows.CreateFile(
		name, access|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, creation,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(handle, &info)
	if err == nil {
		err = validateIdentityFileInfo(info, directory)
	}
	if err == nil {
		err = restrictIdentityHandle(handle)
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	return handle, nil
}

func validateIdentityFileInfo(info windows.ByHandleFileInformation, directory bool) error {
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("device identity path must not be a reparse point")
	}
	if (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("device identity path has an unexpected file type")
	}
	if !directory && info.NumberOfLinks != 1 {
		return errors.New("device identity files must not have hard links")
	}
	return nil
}

func restrictIdentityHandle(handle windows.Handle) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	current, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := current.Owner()
	if err != nil {
		return err
	}
	// Replacing a DACL does not revoke the owner's right to replace it again.
	if owner == nil || (!owner.Equals(user.User.Sid) &&
		!owner.IsWellKnown(windows.WinLocalSystemSid) &&
		!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return errors.New("device identity path is owned by another user")
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")",
	)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
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
	directory, err := openIdentityPath(filepath.Dir(path), true, 0, windows.OPEN_EXISTING)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(directory)
	handle, err := openIdentityPath(path, false, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.OPEN_ALWAYS)
	if err != nil {
		return fmt.Errorf("open device identity lock: %w", err)
	}
	defer windows.CloseHandle(handle)
	var overlap windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlap); err != nil {
		return fmt.Errorf("lock device identity: %w", err)
	}
	return action()
}
