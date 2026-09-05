package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/gateway"
)

func registryProof(t *testing.T, key *ecdsa.PrivateKey, name, token string, at time.Time) deviceauth.Proof {
	t.Helper()
	proof, err := deviceauth.NewProof(key, name, token, http.MethodPost, gateway.TunnelPath, at, nil)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestClientRegistryRejectsReplayedDeviceProof(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), token)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := deviceauth.GenerateKey()
	proof := registryProof(t, key, "Office-PC", token, time.Now())
	if _, err := authenticateDeviceProof(registry, token, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateDeviceProof(registry, token, proof); !errors.Is(err, errClientUnauthorized) {
		t.Fatalf("replayed proof error = %v, want unauthorized", err)
	}
}

func TestClientRegistryBoundsAndScopesReplayState(t *testing.T) {
	now := time.Now().UTC()
	key := registryDeviceKey{accountID: "account", deviceID: "device"}
	otherKey := registryDeviceKey{accountID: "other", deviceID: "device"}
	window := &deviceNonceWindow{
		values:     make(map[string]time.Time, maxDeviceNonces),
		nextExpiry: now.Add(time.Minute),
	}
	for index := 0; index < maxDeviceNonces; index++ {
		window.values[string(rune(index))] = now.Add(time.Minute)
	}
	otherWindow := &deviceNonceWindow{
		values:     map[string]time.Time{"expired": now.Add(-time.Second)},
		nextExpiry: now.Add(-time.Second),
	}
	registry := &clientRegistry{nonces: map[registryDeviceKey]*deviceNonceWindow{
		key:      window,
		otherKey: otherWindow,
	}}
	if !registry.nonceSeenLocked(key, "new", now) {
		t.Fatal("full replay window accepted another nonce")
	}
	if len(otherWindow.values) != 1 {
		t.Fatal("checking one device scanned another device's replay state")
	}

	window.values = map[string]time.Time{"expired": now.Add(-time.Second)}
	window.nextExpiry = now.Add(-time.Second)
	if registry.nonceSeenLocked(key, "new", now) {
		t.Fatal("expired replay window rejected a fresh nonce")
	}
	if _, exists := registry.nonces[key]; exists {
		t.Fatal("empty replay window was not removed")
	}
}

func TestClientRegistryClearsReplayStateWithEnrollmentLifecycle(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	tests := []struct {
		name   string
		remove func(*clientRegistry, string, string) error
	}{
		{
			name: "forget device",
			remove: func(registry *clientRegistry, accountID, deviceID string) error {
				return registry.DeleteDevice(accountID, deviceID)
			},
		},
		{
			name: "rotate token",
			remove: func(registry *clientRegistry, accountID, _ string) error {
				_, err := registry.RotateToken(accountID)
				return err
			},
		},
		{
			name: "delete account",
			remove: func(registry *clientRegistry, accountID, _ string) error {
				return registry.Delete(accountID)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), token)
			if err != nil {
				t.Fatal(err)
			}
			key, err := deviceauth.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			proof := registryProof(t, key, "Office-PC", token, time.Now())
			if _, err := authenticateDeviceProof(registry, token, proof); err != nil {
				t.Fatal(err)
			}
			if len(registry.nonces) != 1 {
				t.Fatalf("replay windows before removal = %d, want 1", len(registry.nonces))
			}
			accountID := registry.List()[0].ID
			if err := test.remove(registry, accountID, proof.DeviceID); err != nil {
				t.Fatal(err)
			}
			if len(registry.nonces) != 0 {
				t.Fatalf("replay windows after removal = %d, want 0", len(registry.nonces))
			}
		})
	}
}

func TestClientRegistryRepeatedForgetDoesNotRetainReplayWindows(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), token)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deviceauth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	accountID := registry.List()[0].ID
	for cycle := 0; cycle < 3; cycle++ {
		proof := registryProof(t, key, "Office-PC", token, time.Now())
		if _, err := authenticateDeviceProof(registry, token, proof); err != nil {
			t.Fatal(err)
		}
		if err := registry.DeleteDevice(accountID, proof.DeviceID); err != nil {
			t.Fatal(err)
		}
		if len(registry.nonces) != 0 {
			t.Fatalf("cycle %d retained %d replay windows", cycle+1, len(registry.nonces))
		}
	}
}

func TestClientRegistryUsesKeyIDAndUpdatesDeviceName(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), token)
	if err != nil {
		t.Fatal(err)
	}
	firstKey, _ := deviceauth.GenerateKey()
	secondKey, _ := deviceauth.GenerateKey()
	first := registryProof(t, firstKey, "Shared-Name", token, time.Now())
	second := registryProof(t, secondKey, "Shared-Name", token, time.Now())
	for _, proof := range []deviceauth.Proof{first, second} {
		if _, err := authenticateDeviceProof(registry, token, proof); err != nil {
			t.Fatal(err)
		}
	}
	summary := registry.List()[0]
	if len(summary.Devices) != 2 || summary.Devices[0].ID == summary.Devices[1].ID {
		t.Fatalf("same-name devices = %#v", summary.Devices)
	}

	renamed := registryProof(t, firstKey, "Renamed-PC", token, time.Now())
	if _, err := authenticateDeviceProof(registry, token, renamed); err != nil {
		t.Fatal(err)
	}
	summary = registry.List()[0]
	if len(summary.Devices) != 2 {
		t.Fatalf("rename changed enrollment count to %d", len(summary.Devices))
	}
	for _, device := range summary.Devices {
		if device.ID == first.DeviceID && device.Name != "Renamed-PC" {
			t.Fatalf("renamed device = %#v", device)
		}
	}
}

func TestClientRegistryLastSeenThrottleUsesPersistedTimestamp(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), token)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deviceauth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateDeviceProof(
		registry,
		token,
		registryProof(t, key, "Office-PC", token, time.Now()),
	); err != nil {
		t.Fatal(err)
	}
	registry.clients[0].Devices[0].LastSeen = time.Now().Add(-2 * time.Minute)
	if _, err := authenticateDeviceProof(
		registry,
		token,
		registryProof(t, key, "Office-PC", token, time.Now()),
	); err != nil {
		t.Fatal(err)
	}
	persistedLastSeen := registry.clients[0].Devices[0].LastSeen
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := authenticateDeviceProof(
			registry,
			token,
			registryProof(t, key, "Office-PC", token, time.Now()),
		); err != nil {
			t.Fatal(err)
		}
		if !registry.clients[0].Devices[0].LastSeen.Equal(persistedLastSeen) {
			t.Fatal("frequent authentication advanced the LastSeen persistence baseline")
		}
	}
}

func TestValidateStoredClientRejectsInvalidDeviceKeys(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	key, err := deviceauth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	proof := registryProof(t, key, "Office-PC", token, time.Now())
	client := clientRecord{
		ID:         "0011223344556677",
		Name:       "Test",
		TokenHash:  hashToken(token),
		MaxDevices: 1,
		Enabled:    true,
		Devices: []deviceRecord{{
			ID:        proof.DeviceID,
			Name:      proof.Name,
			PublicKey: proof.PublicKey,
		}},
	}
	if err := validateStoredClient(client); err != nil {
		t.Fatalf("valid client rejected: %v", err)
	}

	invalidKey := client
	invalidKey.Devices = append([]deviceRecord(nil), client.Devices...)
	invalidKey.Devices[0].PublicKey = "eA"
	if err := validateStoredClient(invalidKey); err == nil {
		t.Fatal("invalid public key was accepted")
	}

	nonCanonicalKey := client
	nonCanonicalKey.Devices = append([]deviceRecord(nil), client.Devices...)
	nonCanonicalKey.Devices[0].PublicKey =
		proof.PublicKey[:len(proof.PublicKey)/2] + "\n" + proof.PublicKey[len(proof.PublicKey)/2:]
	if err := validateStoredClient(nonCanonicalKey); err == nil {
		t.Fatal("non-canonical public key was accepted")
	}

	mismatchedID := client
	mismatchedID.Devices = append([]deviceRecord(nil), client.Devices...)
	otherKey, err := deviceauth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	mismatchedID.Devices[0].ID, err = deviceauth.DeviceID(otherKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStoredClient(mismatchedID); err == nil {
		t.Fatal("public key with a mismatched device ID was accepted")
	}
}

func TestClientRegistryRejectsLegacyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	state := registryState{Version: 1, Clients: []clientRecord{}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openClientRegistry(path, ""); err == nil {
		t.Fatal("legacy registry state was accepted")
	}
}
