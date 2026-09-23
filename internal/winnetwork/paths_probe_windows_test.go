package winnetwork

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDirectoryHardeningRejectsPreexistingWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsecured")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	const fileAddFile = 0x0002
	writer, err := openPath(path, fileAddFile|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.OPEN_EXISTING, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := PrepareProtectedDirectory(path)
	writer.Close()
	if pin != nil {
		pin.Close()
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("preexisting writer was not excluded before ACL hardening: %v", err)
	}
	pin, err = PrepareProtectedDirectory(path)
	if err != nil {
		t.Fatalf("closed-writer retry failed: %v", err)
	}
	pin.Close()
}

func TestLegacyDirectoryReadSharingBlocksJournalRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected")
	pin, err := PrepareProtectedDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	state := filepath.Join(path, "state.json")
	pending := state + ".pending"
	for _, filename := range []string{state, pending} {
		file, err := CreateProtectedFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(filename); err != nil {
			file.Close()
			t.Fatal(err)
		}
		file.Close()
	}
	legacy, err := openPath(path, windows.FILE_LIST_DIRECTORY|windows.READ_CONTROL,
		windows.FILE_SHARE_READ, windows.OPEN_EXISTING, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = replaceJournal(pending, state)
	legacy.Close()
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("legacy sharing conflict was not reproduced: %v", err)
	}
	data, err := os.ReadFile(state)
	if err != nil || string(data) != state {
		t.Fatalf("legacy sharing failure destroyed old bytes: %v", err)
	}
	if err := replaceJournal(pending, state); err != nil {
		t.Fatalf("compatible directory pin blocked retry: %v", err)
	}
}
