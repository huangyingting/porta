package winnetwork

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

const wintunSHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
const maxWintunSize = 8 << 20

var wintunLibrary struct {
	sync.Mutex
	handle windows.Handle
	file   *os.File
	pins   []*os.File
}

// PrepareWintun verifies the packaged Wintun release before any DLL code runs.
// It pins a protected copy named wintun.dll in the loaded-module list so the
// WireGuard adapter's lazy loader cannot fall back to an untrusted app DLL.
func PrepareWintun() error {
	wintunLibrary.Lock()
	defer wintunLibrary.Unlock()
	if wintunLibrary.handle != 0 {
		return nil
	}
	if runtime.GOARCH != "amd64" {
		return errors.New("the pinned Windows Wintun release requires amd64")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	source, err := openVerifiedWintun(filepath.Join(filepath.Dir(executable), "wintun.dll"))
	if err != nil {
		return err
	}
	defer source.Close()
	statePath, err := CurrentStatePath()
	if err != nil {
		return err
	}
	root := filepath.Dir(statePath)
	directory := filepath.Join(root, "wintun")
	release := filepath.Join(directory, wintunSHA256)
	var pins []*os.File
	keep := false
	defer func() {
		if !keep {
			for _, pin := range pins {
				pin.Close()
			}
		}
	}()
	for _, path := range []string{root, directory, release} {
		pin, err := PrepareProtectedDirectory(path)
		if err != nil {
			return fmt.Errorf("secure Wintun staging directory: %w", err)
		}
		pins = append(pins, pin)
	}
	path := filepath.Join(release, "wintun.dll")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := stageWintun(source, path); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	protected, err := OpenProtectedFile(path, false)
	if err != nil {
		return fmt.Errorf("validate staged Wintun permissions: %w", err)
	}
	protected.Close()
	file, err := openVerifiedWintun(path)
	if err != nil {
		return err
	}
	defer func() {
		if !keep {
			file.Close()
		}
	}()
	moduleName, _ := windows.UTF16PtrFromString("wintun.dll")
	var existing windows.Handle
	if windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, moduleName, &existing) == nil {
		return errors.New("Wintun was loaded before its integrity boundary")
	}
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return fmt.Errorf("load verified Wintun: %w", err)
	}
	var name [32768]uint16
	length, err := windows.GetModuleFileName(handle, &name[0], uint32(len(name)))
	if err != nil || length == 0 || length >= uint32(len(name)) ||
		!strings.EqualFold(filepath.Clean(windows.UTF16ToString(name[:length])), filepath.Clean(path)) {
		windows.FreeLibrary(handle)
		return errors.New("loaded Wintun path does not match the verified release")
	}
	wintunLibrary.handle, wintunLibrary.file, wintunLibrary.pins = handle, file, pins
	keep = true
	return nil
}

func openVerifiedWintun(path string) (*os.File, error) {
	file, err := OpenRegularFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ)
	if err != nil {
		return nil, fmt.Errorf("open Wintun library: %w", err)
	}
	if err := verifyWintunHash(file, wintunSHA256); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func verifyWintunHash(file *os.File, expected string) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() <= 0 || info.Size() > maxWintunSize {
		return errors.New("Wintun library is empty or exceeds 8 MiB")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	length, err := io.Copy(hash, io.LimitReader(file, maxWintunSize+1))
	if err != nil {
		return err
	}
	if length != info.Size() || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("Wintun library does not match the pinned official release")
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func stageWintun(source *os.File, path string) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	pending := path + "." + hex.EncodeToString(nonce[:]) + ".pending"
	file, err := CreateProtectedFile(pending)
	if err != nil {
		return err
	}
	defer os.Remove(pending)
	_, copyErr := io.Copy(file, source)
	err = errors.Join(copyErr, file.Sync(), file.Close())
	if err != nil {
		return fmt.Errorf("stage verified Wintun: %w", err)
	}
	from, err := windows.UTF16PtrFromString(pending)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return nil
	}
	return err
}
