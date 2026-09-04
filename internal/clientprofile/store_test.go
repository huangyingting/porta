package clientprofile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/huangyingting/porta/internal/tunnel"
)

type testProtector struct{}

func (testProtector) Protect(value []byte) ([]byte, error) {
	return append([]byte("protected:"), value...), nil
}

func (testProtector) Unprotect(value []byte) ([]byte, error) {
	return bytes.TrimPrefix(value, []byte("protected:")), nil
}

func TestStorePersistsProfilesAndProtectedTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	store, err := Open(path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}

	profile, err := store.Save(Profile{
		Name:      "Work",
		ServerURL: "https://vpn.example.com",
		ClientID:  "workstation",
		Transport: tunnel.TransportHTTP3,
		Reconnect: true,
	}, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("secret-token")) {
		t.Fatal("profile store contains the plaintext token")
	}

	reopened, err := Open(path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if profiles := reopened.List(); len(profiles) != 1 || profiles[0].Name != "Work" {
		t.Fatalf("profiles = %#v", profiles)
	}
	token, err := reopened.Token(profile.ID)
	if err != nil || token != "secret-token" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
	if err := reopened.Delete(profile.ID); err != nil {
		t.Fatal(err)
	}
	if len(reopened.List()) != 0 {
		t.Fatal("deleted profile remains")
	}
}

func TestStoreRetainsProtectedTokenOnEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	store, err := Open(path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Save(Profile{Name: "Original", ServerURL: "https://gateway", ClientID: "laptop"}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	edited := original
	edited.Name = "Updated"
	saved, err := store.Save(edited, "")
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID != original.ID || saved.CreatedAt != original.CreatedAt {
		t.Fatal("editing changed profile identity")
	}
	store, err = Open(path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.Token(saved.ID)
	if err != nil || token != "secret" {
		t.Fatalf("saved token = %q, %v", token, err)
	}
}

func TestStoreRollsBackFailedMutations(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "profiles.json"), testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Save(Profile{Name: "Original", ServerURL: "https://gateway", ClientID: "laptop"}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	store.path = dir // A directory cannot be atomically replaced by the JSON file.
	edited := original
	edited.Name = "Updated"
	if _, err := store.Save(edited, "new-token"); err == nil {
		t.Fatal("unwritable save succeeded")
	}
	if err := store.Delete(original.ID); err == nil {
		t.Fatal("unwritable deletion succeeded")
	}
	profiles := store.List()
	if len(profiles) != 1 || profiles[0] != original {
		t.Fatalf("failed mutation changed in-memory profiles: %+v", profiles)
	}
	token, err := store.Token(original.ID)
	if err != nil || token != "secret" {
		t.Fatalf("failed mutation changed token: %q, %v", token, err)
	}
}
