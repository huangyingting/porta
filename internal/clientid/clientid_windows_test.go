//go:build windows

package clientid

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/winnetwork"
	"golang.org/x/sys/windows"
)

func privateIdentityPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity", "identity.json")
	if err := prepareIdentityStorage(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePrivateIdentityFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := winnetwork.CreateProtectedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
}

func identitySecurity(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.String()
}

func setIdentitySecurity(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, ownerErr := descriptor.Owner()
	dacl, _, daclErr := descriptor.DACL()
	sacl, _, saclErr := descriptor.SACL()
	if err := errors.Join(ownerErr, daclErr, saclErr); err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION,
		owner, nil, dacl, sacl); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPersistentIdentityAndProtectedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity", "identity.json")
	first, err := loadOrCreateWindows(path, protectMachine, unprotectMachine)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateWindows(path, protectMachine, unprotectMachine)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := deviceauth.DeviceID(first.Public())
	secondID, _ := deviceauth.DeviceID(second.Public())
	if firstID != secondID {
		t.Fatal("persistent identity changed")
	}
	directory, err := winnetwork.OpenOrCreateProtectedDirectory(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	directory.Close()
	for _, candidate := range []string{path, path + ".lock"} {
		file, err := openPrivateIdentityFile(candidate)
		if err != nil {
			t.Fatalf("identity object is not administrator-only/high integrity: %s: %v", candidate, err)
		}
		file.Close()
	}
}

func TestWindowsIdentityRejectsInsecureExistingStorageWithoutRepair(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range []string{"directory", "identity", "lock"} {
		for _, damage := range []string{"readable DACL", "user owner", "medium integrity"} {
			t.Run(object+"/"+damage, func(t *testing.T) {
				path := privateIdentityPath(t)
				original := []byte("never decrypt or replace this existing identity")
				writePrivateIdentityFixture(t, path, original)
				writePrivateIdentityFixture(t, path+".lock", nil)
				target, inherit := path, ""
				if object == "directory" {
					target, inherit = filepath.Dir(path), "OICI"
				} else if object == "lock" {
					target = path + ".lock"
				}
				owner, extra, label := "BA", "", "HI"
				switch damage {
				case "readable DACL":
					extra = "(A;" + inherit + ";GR;;;BU)"
				case "user owner":
					owner = user.User.Sid.String()
				case "medium integrity":
					label = "ME"
				}
				sddl := "O:" + owner + "D:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)" +
					extra + "S:(ML;" + inherit + ";NW;;;" + label + ")"
				setIdentitySecurity(t, target, sddl)
				before := identitySecurity(t, target)
				_, err := loadOrCreateWindows(path, protectMachine, func([]byte) ([]byte, error) {
					t.Fatal("attempted to decrypt insecure identity storage")
					return nil, nil
				})
				if !errors.Is(err, os.ErrPermission) {
					t.Fatalf("insecure identity storage was not rejected by security validation: %v", err)
				}
				if after := identitySecurity(t, target); after != before {
					t.Fatalf("rejected storage was silently repaired:\nbefore %s\nafter %s", before, after)
				}
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, original) {
					t.Fatalf("insecure identity was replaced: %q, %v", data, err)
				}
			})
		}
	}
}

func TestWindowsIdentityRejectsLinksWithoutChangingTarget(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink", "lock-hardlink", "lock-symlink", "directory-symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := privateIdentityPath(t)
			directory := filepath.Dir(filepath.Dir(path))
			target := filepath.Join(directory, "target")
			original := []byte("preserve this unrelated file")
			if err := os.WriteFile(target, original, 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "hardlink":
				err = os.Link(target, path)
			case "symlink":
				err = os.Symlink(target, path)
			case "lock-hardlink":
				err = os.Link(target, path+".lock")
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
			before := identitySecurity(t, target)
			if _, err := loadOrCreateWindows(path, protectMachine, unprotectMachine); err == nil {
				t.Fatal("linked identity storage was accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(data, original) || identitySecurity(t, target) != before {
				t.Fatalf("linked target or its ACL changed: %q: %v", data, err)
			}
		})
	}
}

func TestWindowsIdentityPinsDirectoryAndLockDuringTransaction(t *testing.T) {
	path := privateIdentityPath(t)
	if err := withFileLock(path+".lock", func() error {
		for _, candidate := range []string{filepath.Dir(path), path + ".lock"} {
			if err := os.Rename(candidate, candidate+"-replaced"); err == nil {
				t.Fatalf("verified object could be replaced during identity access: %s", candidate)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsIdentityReadRejectsConcurrentWriters(t *testing.T) {
	path := privateIdentityPath(t)
	writePrivateIdentityFixture(t, path, []byte("private"))
	writer, err := winnetwork.OpenProtectedFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readIdentityFile(path)
	writer.Close()
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("identity read raced a preexisting writer: %v", err)
	}
	file, err := openPrivateIdentityFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(path, path+"-replaced"); err == nil {
		t.Fatal("private identity read did not pin its file")
	}
}

func TestWindowsIdentityReadIsCappedAt64KiB(t *testing.T) {
	for _, size := range []int{maxWindowsIdentitySize, maxWindowsIdentitySize + 1} {
		path := privateIdentityPath(t)
		writePrivateIdentityFixture(t, path, bytes.Repeat([]byte(" "), size))
		data, err := readIdentityFile(path)
		if size == maxWindowsIdentitySize {
			if err != nil || len(data) != size {
				t.Fatalf("exactly 64 KiB read = %d, %v", len(data), err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "64 KiB") || data != nil {
			t.Fatalf("oversized identity read = %d, %v", len(data), err)
		}
	}
}

func TestWindowsIdentityPublicationNeverOverwritesExistingFiles(t *testing.T) {
	path := privateIdentityPath(t)
	original := []byte("existing identity")
	writePrivateIdentityFixture(t, path, original)
	key, err := deviceauth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	err = withFileLock(path+".lock", func() error { return persistWindowsIdentity(path, key, protectMachine) })
	if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		t.Fatalf("identity publication did not reject an existing destination: %v", err)
	}
	data, err := readIdentityFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatalf("existing identity changed: %q, %v", data, err)
	}
	pending, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".device-identity-*.pending"))
	if err != nil || len(pending) != 0 {
		t.Fatalf("failed publication left pending state: %v, %v", pending, err)
	}
}

func TestWindowsIdentityCannotPersistOversizedProtectedState(t *testing.T) {
	path := privateIdentityPath(t)
	_, err := loadOrCreateWindows(path, func([]byte) ([]byte, error) {
		return bytes.Repeat([]byte("x"), maxWindowsIdentitySize), nil
	}, unprotectMachine)
	if err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("oversized identity publication was accepted: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized identity was published: %v", err)
	}
}

func TestWindowsConcurrentIdentityCreationConverges(t *testing.T) {
	path := privateIdentityPath(t)
	var workers sync.WaitGroup
	results := make(chan string, 4)
	failures := make(chan error, 4)
	for range 4 {
		workers.Go(func() {
			key, err := loadOrCreateWindows(path, protectMachine, unprotectMachine)
			if err != nil {
				failures <- err
				return
			}
			id, err := deviceauth.DeviceID(key.Public())
			if err != nil {
				failures <- err
				return
			}
			results <- id
		})
	}
	workers.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	var first string
	for id := range results {
		if first == "" {
			first = id
		} else if id != first {
			t.Fatal("concurrent creators returned different device identities")
		}
	}
	if first == "" {
		t.Fatal("no creator obtained an identity")
	}
}
