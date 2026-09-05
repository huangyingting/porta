//go:build linux && !android

package clientid

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/huangyingting/porta/internal/deviceauth"
)

func TestPersistentIdentityReusesKeyAndRefreshesName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
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
	path := filepath.Join(t.TempDir(), "identity.json")
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
		if expected == "" {
			expected = result
		}
		if result != expected {
			t.Fatalf("concurrent identity mismatch: %q != %q", result, expected)
		}
	}
}
