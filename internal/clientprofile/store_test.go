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
