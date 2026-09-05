//go:build linux && !android

package clientid

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMachineIDFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-id")
	if id, err := fromMachineIDFile(path); id != "" || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing OS identity did not fail explicitly: %q, %v", id, err)
	}
	if err := os.WriteFile(path, []byte("00112233445566778899aabbccddeeff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, _ := derive("linux", "00112233445566778899aabbccddeeff")
	if id, err := fromMachineIDFile(path); err != nil || id != want {
		t.Fatalf("machine ID file was not used: %v", err)
	}
	if err := os.WriteFile(path, []byte("uninitialized\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if id, err := fromMachineIDFile(path); id != "" || err == nil {
		t.Fatalf("uninitialized OS identity did not fail explicitly: %q, %v", id, err)
	}
}
