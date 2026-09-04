//go:build ignore

package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func packageFixture(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".package-windows-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	for _, name := range []string{"porta.exe", "porta-cli.exe", "wintun.dll"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func TestPackageWindowsDeterministic(t *testing.T) {
	directory := packageFixture(t)
	output := filepath.Join(directory, "porta.zip")
	if err := packageWindows(output, directory); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := packageWindows(output, directory); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("package changed: %v", err)
	}
	archive, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	if len(archive.File) != 3 {
		t.Fatalf("got %d archive entries", len(archive.File))
	}
	for _, entry := range archive.File {
		if entry.UncompressedSize64 == 0 || entry.Mode().Perm() != 0o755 {
			t.Errorf("invalid entry: %+v", entry.FileHeader)
		}
	}
}

func TestPackageWindowsRejectsInvalidInputWithoutReplacingOutput(t *testing.T) {
	for _, invalid := range []string{"missing", "directory", "empty"} {
		t.Run(invalid, func(t *testing.T) {
			directory := packageFixture(t)
			output := filepath.Join(directory, "porta.zip")
			previous := []byte("previous release")
			if err := os.WriteFile(output, previous, 0o644); err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(directory, "wintun.dll")
			if err := os.Remove(input); err != nil {
				t.Fatal(err)
			}
			switch invalid {
			case "directory":
				if err := os.Mkdir(input, 0o755); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(input, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := packageWindows(output, directory); err == nil {
				t.Fatal("invalid input was accepted")
			}
			got, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(got, previous) {
				t.Fatalf("previous package was changed: %q, %v", got, err)
			}
			staging, err := filepath.Glob(filepath.Join(directory, ".porta.zip.tmp-*"))
			if err != nil || len(staging) != 0 {
				t.Fatalf("staging files leaked: %v, %v", staging, err)
			}
		})
	}
}

func TestPackageWindowsFailedCommitCleansStaging(t *testing.T) {
	directory := packageFixture(t)
	output := filepath.Join(directory, "porta.zip")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := packageWindows(output, directory); err == nil {
		t.Fatal("replacing a directory unexpectedly succeeded")
	}
	staging, err := filepath.Glob(filepath.Join(directory, ".porta.zip.tmp-*"))
	if err != nil || len(staging) != 0 {
		t.Fatalf("staging files leaked: %v, %v", staging, err)
	}
}
