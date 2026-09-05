package clientprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/huangyingting/porta/internal/tunnel"
)

type unavailableProtector struct{}

func (unavailableProtector) Protect([]byte) ([]byte, error) {
	return nil, errors.New("secret protection unavailable")
}

func (unavailableProtector) Unprotect([]byte) ([]byte, error) {
	return nil, errors.New("secret protection unavailable")
}

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
	original, err := store.Save(Profile{Name: "Original", ServerURL: "https://gateway"}, "secret")
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

	original, err := store.Save(Profile{Name: "Original", ServerURL: "https://gateway"}, "secret")
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

func TestStoreAutomaticDefaultPreservesExplicitTransport(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "profiles.json"), testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []tunnel.Transport{"", tunnel.TransportAuto, tunnel.TransportHTTP3, tunnel.TransportHTTP2} {
		profile, err := store.Save(Profile{
			Name: "Profile", ServerURL: "https://gateway", Transport: transport,
		}, "secret")
		if err != nil {
			t.Fatal(err)
		}
		want := transport
		if want == "" {
			want = tunnel.TransportAuto
		}
		if profile.Transport != want {
			t.Fatalf("transport %q became %q, want %q", transport, profile.Transport, want)
		}
	}
	reopened, err := Open(store.path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.List()) != 4 {
		t.Fatal("profiles missing after reopen")
	}
}

func TestOldProfilesDiscardDeviceIDsWithoutChangingSettingsOrSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	store, err := Open(path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Save(Profile{
		Name: "Original", ServerURL: "https://gateway", Transport: tunnel.TransportHTTP2,
		CAPath: "private-ca.pem", Thumbprint: "pinned-certificate", Reconnect: false,
	}, "retained-token")
	if err != nil {
		t.Fatal(err)
	}
	protected := store.state.Profiles[0].ProtectedToken
	legacyData := oldProfileData(t, store)
	if err := os.WriteFile(path, legacyData, 0o600); err != nil {
		t.Fatal(err)
	}

	// DPAPI blobs do not bind the old device ID, so migration must only copy them.
	migrated, err := Open(path, unavailableProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if profiles := migrated.List(); len(profiles) != 1 || profiles[0] != original {
		t.Fatalf("migration changed profile settings: %+v", profiles)
	}
	if migrated.state.Profiles[0].ProtectedToken != protected {
		t.Fatal("migration changed the protected token")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("client_id")) || bytes.Contains(data, []byte("old-editable-device")) {
		t.Fatal("obsolete per-profile identity survived migration")
	}
	reopened, err := Open(path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if token, err := reopened.Token(original.ID); err != nil || token != "retained-token" {
		t.Fatalf("migrated token could not be recovered: %v", err)
	}
	if reopened.state.Version != stateVersion {
		t.Fatal("profile store was not upgraded")
	}
}

func TestInvalidOldProfileDoesNotPartiallyMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	store, err := Open(path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(Profile{Name: "Valid", ServerURL: "https://gateway"}, "token"); err != nil {
		t.Fatal(err)
	}
	invalid := store.state.Profiles[0]
	invalid.ID = "invalid-profile"
	invalid.Name = ""
	store.state.Profiles = append(store.state.Profiles, invalid)
	original := oldProfileData(t, store)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, testProtector{}); err == nil {
		t.Fatal("invalid profile was silently accepted or dropped")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatal("failed migration rewrote the original record set")
	}
}

func oldProfileData(t *testing.T, store *Store) []byte {
	t.Helper()
	profiles := make([]map[string]json.RawMessage, len(store.state.Profiles))
	for index, record := range store.state.Profiles {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &profiles[index]); err != nil {
			t.Fatal(err)
		}
		profiles[index]["client_id"] = json.RawMessage(`"old-editable-device"`)
	}
	data, err := json.Marshal(struct {
		Version  int                          `json:"version"`
		Profiles []map[string]json.RawMessage `json:"profiles"`
	}{1, profiles})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
