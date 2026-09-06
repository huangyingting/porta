//go:build windows

package clientid

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/huangyingting/porta/internal/deviceauth"
	"golang.org/x/sys/windows"
)

func TestIdentityFileInfoRejectsUnexpectedObjects(t *testing.T) {
	for _, test := range []struct {
		name      string
		info      windows.ByHandleFileInformation
		directory bool
	}{
		{"reparse file", windows.ByHandleFileInformation{FileAttributes: windows.FILE_ATTRIBUTE_REPARSE_POINT, NumberOfLinks: 1}, false},
		{"reparse directory", windows.ByHandleFileInformation{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT}, true},
		{"directory instead of file", windows.ByHandleFileInformation{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY}, false},
		{"file instead of directory", windows.ByHandleFileInformation{NumberOfLinks: 1}, true},
		{"hard linked file", windows.ByHandleFileInformation{NumberOfLinks: 2}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateIdentityFileInfo(test.info, test.directory); err == nil {
				t.Fatal("unexpected identity object accepted")
			}
		})
	}
	if err := validateIdentityFileInfo(windows.ByHandleFileInformation{NumberOfLinks: 1}, false); err != nil {
		t.Fatal(err)
	}
	if err := validateIdentityFileInfo(windows.ByHandleFileInformation{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY}, true); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPersistentIdentityAndProtectedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity", "identity.json")
	first, err := loadOrCreate(path, protectMachine, unprotectMachine)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreate(path, protectMachine, unprotectMachine)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := deviceauth.DeviceID(first.Public())
	secondID, _ := deviceauth.DeviceID(second.Public())
	if firstID != secondID {
		t.Fatal("persistent identity changed")
	}
	for _, candidate := range []string{filepath.Dir(path), path, path + ".lock"} {
		descriptor, err := windows.GetNamedSecurityInfo(candidate, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := descriptor.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("identity ACL is not protected: %s: %v", candidate, err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil || dacl == nil {
			t.Fatalf("identity DACL is missing: %s: %v", candidate, err)
		}
	}
}

func TestWindowsIdentityRejectsLinksWithoutChangingTarget(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink", "lock-symlink", "directory-symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "target")
			original := []byte("preserve this unrelated file")
			if err := os.WriteFile(target, original, 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "identity", "identity.json")
			if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			linkPath := path
			var err error
			switch kind {
			case "hardlink":
				err = os.Link(target, linkPath)
			case "symlink":
				err = os.Symlink(target, linkPath)
			case "lock-symlink":
				err = os.Symlink(target, path+".lock")
			case "directory-symlink":
				if err := os.Remove(filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(directory, filepath.Dir(path))
			}
			if err != nil {
				t.Skipf("link creation unavailable: %v", err)
			}
			if _, err := loadOrCreate(path, protectMachine, unprotectMachine); err == nil {
				t.Fatal("linked identity storage was accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(data, original) {
				t.Fatalf("linked target changed: %q: %v", data, err)
			}
		})
	}
}

func TestWindowsIdentityPinsDirectoryDuringTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity", "identity.json")
	if err := prepareIdentityStorage(path); err != nil {
		t.Fatal(err)
	}
	if err := withFileLock(path+".lock", func() error {
		if err := os.Rename(filepath.Dir(path), filepath.Dir(path)+"-replaced"); err == nil {
			t.Fatal("verified directory could be replaced during identity access")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
