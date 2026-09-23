//go:build windows

package winnetwork

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const adminFileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;HI)"
const adminDirectorySDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NW;;;HI)"
const (
	fileAllAccess           = 0x001f01ff
	mandatoryLabelACEType   = 0x11
	mandatoryLabelNoWriteUp = 0x1
)

// CurrentStatePath uses the Windows known folder, never a caller-controlled
// environment variable, for privileged recovery state.
func CurrentStatePath() (string, error) {
	directory, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "Porta", "network-state.json"), nil
}

func DefaultStatePath() (string, error) {
	current, err := CurrentStatePath()
	if err != nil {
		return "", err
	}
	directory, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	if err != nil {
		return "", err
	}
	legacy := filepath.Join(directory, "Porta", "network-state.json")
	if _, err := os.Lstat(legacy); err == nil {
		return "", fmt.Errorf("legacy network recovery state exists at %s; restore it with the previous Porta client before upgrading", legacy)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return current, nil
}

// PrepareProtectedDirectory excludes old writers while hardening the ACL.
// The returned no-delete pin permits child replacements (FILE_SHARE_WRITE).
func PrepareProtectedDirectory(path string) (*os.File, error) {
	descriptor, err := windows.SecurityDescriptorFromString(adminDirectorySDDL)
	if err != nil {
		return nil, err
	}
	created, err := createProtectedDirectory(path, descriptor)
	if err != nil {
		return nil, err
	}
	probe, err := openPath(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ, windows.OPEN_EXISTING, true, nil)
	if err != nil {
		return nil, err
	}
	defer probe.Close()
	if err := validatePathType(probe, true); err != nil {
		return nil, err
	}
	if !created {
		if err := validateAdoptableOwner(probe); err != nil {
			return nil, err
		}
	}
	pin, err := openPath(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.OPEN_EXISTING, true, nil)
	if err != nil {
		return nil, err
	}
	if err := sameFile(probe, pin); err != nil {
		pin.Close()
		return nil, err
	}
	if err := applyAdminSecurity(pin, descriptor); err != nil {
		pin.Close()
		return nil, err
	}
	if err := ValidateProtectedDirectory(pin); err != nil {
		pin.Close()
		return nil, err
	}
	return pin, nil
}

func ValidateProtectedDirectory(file *os.File) error {
	if err := validatePathType(file, true); err != nil {
		return err
	}
	return validateAdminSecurity(file, true)
}

// OpenOrCreateProtectedDirectory never adopts an insecure existing directory.
// Identity storage must not repair an ACL that might already have exposed keys.
func OpenOrCreateProtectedDirectory(path string) (*os.File, error) {
	descriptor, err := windows.SecurityDescriptorFromString(adminDirectorySDDL)
	if err != nil {
		return nil, err
	}
	if _, err := createProtectedDirectory(path, descriptor); err != nil {
		return nil, err
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY)
	probe, err := openPath(path, access, windows.FILE_SHARE_READ, windows.OPEN_EXISTING, true, nil)
	if err != nil {
		return nil, err
	}
	defer probe.Close()
	if err := ValidateProtectedDirectory(probe); err != nil {
		return nil, err
	}
	pin, err := openPath(path, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.OPEN_EXISTING, true, nil)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(sameFile(probe, pin), ValidateProtectedDirectory(pin)); err != nil {
		pin.Close()
		return nil, err
	}
	return pin, nil
}

func createProtectedDirectory(path string, descriptor *windows.SECURITY_DESCRIPTOR) (bool, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	err = windows.CreateDirectory(name, &attributes)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return false, nil
	}
	return err == nil, err
}

func ValidateProtectedFile(file *os.File) error {
	if err := validatePathType(file, false); err != nil {
		return err
	}
	return validateAdminSecurity(file, false)
}

// OpenRegularFile opens the object itself and pins it against replacement.
// Callers must validate before writing; no truncation is performed here.
func OpenRegularFile(path string, access, sharing uint32) (*os.File, error) {
	file, err := openPath(path, access|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, sharing, windows.OPEN_EXISTING, false, nil)
	if err != nil {
		return nil, err
	}
	if err := validatePathType(file, false); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func OpenProtectedFile(path string, write bool) (*os.File, error) {
	access := uint32(windows.GENERIC_READ)
	if write {
		access |= windows.GENERIC_WRITE
	}
	file, err := OpenRegularFile(path, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		return nil, err
	}
	if err := validateAdminSecurity(file, false); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func CreateProtectedFile(path string) (*os.File, error) {
	descriptor, err := windows.SecurityDescriptorFromString(adminFileSDDL)
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	file, err := openPath(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.CREATE_NEW, false, &attributes)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(validatePathType(file, false), validateAdminSecurity(file, false)); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func RemoveProtectedFile(path string) error {
	file, err := OpenProtectedFile(path, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

func openPath(path string, access, sharing, disposition uint32, directory bool, attributes *windows.SecurityAttributes) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, access, sharing, attributes, disposition, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open protected path", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func fileInformation(file *os.File) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info)
	return info, err
}

func validatePathType(file *os.File, directory bool) error {
	info, err := fileInformation(file)
	if err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory ||
		(!directory && info.NumberOfLinks != 1) {
		return fmt.Errorf("%w: privileged path must be non-reparse and files must have a single link", os.ErrPermission)
	}
	return nil
}

func sameFile(left, right *os.File) error {
	a, err := fileInformation(left)
	if err != nil {
		return err
	}
	b, err := fileInformation(right)
	if err != nil {
		return err
	}
	if a.VolumeSerialNumber != b.VolumeSerialNumber || a.FileIndexHigh != b.FileIndexHigh || a.FileIndexLow != b.FileIndexLow {
		return fmt.Errorf("%w: privileged path changed during preparation", os.ErrPermission)
	}
	return nil
}

func validateAdoptableOwner(file *os.File) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner != nil && (owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return fmt.Errorf("%w: privileged path is owned by another user", os.ErrPermission)
	}
	return nil
}

func applyAdminSecurity(file *os.File, descriptor *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	sacl, _, err := descriptor.SACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION,
		owner, nil, dacl, sacl)
}

func validateAdminSecurity(file *os.File, directory bool) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, ownerErr := sd.Owner()
	control, _, controlErr := sd.Control()
	dacl, _, daclErr := sd.DACL()
	sacl, _, saclErr := sd.SACL()
	if err := errors.Join(ownerErr, controlErr, daclErr, saclErr); err != nil {
		return err
	}
	if owner == nil || !(owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)) ||
		control&windows.SE_DACL_PROTECTED == 0 || !adminDACL(dacl, directory) || !highIntegritySACL(sacl) {
		return fmt.Errorf("%w: privileged path requires Porta's administrator-only ACL and high integrity label", os.ErrPermission)
	}
	return nil
}

func adminDACL(acl *windows.ACL, directory bool) bool {
	if acl == nil || acl.AceCount != 2 {
		return false
	}
	flags := byte(0)
	if directory {
		flags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	var system, administrators bool
	for index := uint32(0); index < 2; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != flags || ace.Mask != fileAllAccess {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinLocalSystemSid) && !system {
			system = true
		} else if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !administrators {
			administrators = true
		} else {
			return false
		}
	}
	return system && administrators
}

func highIntegritySACL(acl *windows.ACL) bool {
	if acl == nil {
		return false
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil {
			return false
		}
		if ace.Header.AceType == mandatoryLabelACEType && ace.Mask&mandatoryLabelNoWriteUp != 0 &&
			(*windows.SID)(unsafe.Pointer(&ace.SidStart)).IsWellKnown(windows.WinHighLabelSid) {
			return true
		}
	}
	return false
}
