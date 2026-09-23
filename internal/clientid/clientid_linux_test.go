//go:build linux && !android

package clientid

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/huangyingting/porta/internal/deviceauth"
)

func TestPersistentIdentityReusesKeyAndRefreshesName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "identity.json")
	firstKey, err := loadOrCreate(path, passthrough, passthrough)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := loadOrCreate(path, passthrough, passthrough)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := deviceauth.DeviceID(firstKey.Public())
	secondID, _ := deviceauth.DeviceID(secondKey.Public())
	if firstID != secondID {
		t.Fatalf("persistent device ID changed: %q != %q", firstID, secondID)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("identity permissions = %v, %v", info, err)
	}
}

func TestConcurrentCreationProducesOneIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "identity.json")
	const workers = 12
	results := make(chan string, workers)
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			key, err := loadOrCreate(path, passthrough, passthrough)
			if err != nil {
				results <- "error:" + err.Error()
				return
			}

			id, _ := deviceauth.DeviceID(key.Public())
			results <- id
		})
	}
	group.Wait()
	close(results)
	var expected string
	for result := range results {
		if strings.HasPrefix(result, "error:") {
			t.Fatal(result)
		}
		if expected == "" {
			expected = result
		}
		if result != expected {
			t.Fatalf("concurrent identity mismatch: %q != %q", result, expected)
		}
	}
}

func TestExplicitIdentityRejectsRelativeOrUnsafeStorage(t *testing.T) {
	if _, err := CurrentAt("relative/identity.json"); err == nil {
		t.Fatal("relative identity path accepted")
	}
	for _, kind := range []string{"permissions", "symlink", "hardlink", "lock-symlink", "public-directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			path := filepath.Join(dir, "identity.json")
			if _, err := CurrentAt(path); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink", "lock-symlink":
				if kind == "lock-symlink" {
					path += ".lock"
				}
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "public-directory":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := CurrentAt(filepath.Join(dir, "identity.json")); err == nil {
				t.Fatal("unsafe identity storage accepted")
			}
		})
	}
}
