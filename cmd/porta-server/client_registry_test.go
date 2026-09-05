package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestClientRegistrySharedTokenAndDeviceLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	registry, err := openClientRegistry(path, "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	first, err := authenticateTestDevice(registry, "bootstrap-token-0123456789", "phone")
	if err != nil {
		t.Fatal(err)
	}
	second, err := authenticateTestDevice(registry, "bootstrap-token-0123456789", "tablet")
	if err != nil {
		t.Fatal(err)
	}
	if first.AccountID != second.AccountID || first.LeaseID == second.LeaseID {
		t.Fatalf("identities = %#v, %#v", first, second)
	}

	client := registry.List()[0]
	if _, err := registry.Update(client.ID, client.Name, 2, true); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateTestDevice(registry, "bootstrap-token-0123456789", "laptop"); !errors.Is(err, errDeviceLimit) {
		t.Fatalf("third device error = %v, want device limit", err)
	}
	if err := registry.DeleteDevice(client.ID, testDeviceID("tablet")); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateTestDevice(registry, "bootstrap-token-0123456789", "laptop"); err != nil {
		t.Fatalf("replacement device rejected: %v", err)
	}
}

func TestClientRegistryCreateRotateDisableAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	registry, err := openClientRegistry(path, "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	client, token, err := registry.Create("Engineering", 3)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("created token is empty")
	}
	if _, err := authenticateTestDevice(registry, token, "workstation"); err != nil {
		t.Fatal(err)
	}
	rotated, err := registry.RotateToken(client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == token {
		t.Fatal("token rotation returned the previous token")
	}
	if _, err := authenticateTestDevice(registry, token, "workstation"); !errors.Is(err, errClientUnauthorized) {
		t.Fatalf("old token error = %v", err)
	}
	if _, err := authenticateTestDevice(registry, rotated, "workstation"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Update(client.ID, "Engineering", 3, false); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateTestDevice(registry, rotated, "workstation"); !errors.Is(err, errClientDisabled) {
		t.Fatalf("disabled client error = %v", err)
	}

	reopened, err := openClientRegistry(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.List()) != 2 {
		t.Fatalf("reopened clients = %d, want 2", len(reopened.List()))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("registry mode = %o, want 600", info.Mode().Perm())
	}
}

func TestClientRegistryNamespacesSameDeviceAcrossClients(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := registry.Create("Second client", 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authenticateTestDevice(registry, "bootstrap-token-0123456789", "phone")
	if err != nil {
		t.Fatal(err)
	}
	second, err := authenticateTestDevice(registry, token, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if first.LeaseID == second.LeaseID {
		t.Fatal("same device ID across clients shared a lease identity")
	}
}
