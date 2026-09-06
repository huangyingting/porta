package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/forwardproxy"
)

func TestDisconnectEpochChurn(t *testing.T) {
	const cycles = 1000
	registry := &clientRegistry{writeState: func([]byte) error { return nil }}
	for cycle := range cycles {
		client, token, err := registry.Create(fmt.Sprintf("client-%d", cycle), 1)
		if err != nil {
			t.Fatal(err)
		}
		_, _, release, err := registry.AuthenticateProxySession(context.Background(), token)
		if err != nil {
			t.Fatal(err)
		}
		release()
		for _, deviceID := range []string{forwardproxy.DeviceID, ""} {
			if _, err := registry.Disconnect(client.ID, deviceID); err != nil {
				t.Fatal(err)
			}
		}
		if err := registry.DeleteDevice(client.ID, forwardproxy.DeviceID); err != nil {
			t.Fatal(err)
		}
		if err := registry.Delete(client.ID); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("churn=%d accounts=%d devices=%d", cycles, len(registry.accountDisconnect), len(registry.deviceDisconnect))
	if len(registry.accountDisconnect) != 0 || len(registry.deviceDisconnect) != 0 {
		t.Fatal("completed disconnects retained fencing state without authentication attempts")
	}
}

func TestAdminMissingPersistencePathIsInternalError(t *testing.T) {
	registry := sessionTestRegistry(t)
	authenticateProxyForTest(t, registry, sessionTestToken)
	clientPath := "/api/clients/" + registry.clients[0].ID
	registry.writeState = func([]byte) error {
		return fmt.Errorf("replace client registry: %w", &os.PathError{
			Op: "rename", Path: "private-registry-path", Err: os.ErrNotExist,
		})
	}
	handler := adminHandler(http.NotFoundHandler(), registry, testAdminToken)
	for _, test := range []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/clients", `{"name":"Operations","max_devices":4}`},
		{http.MethodPut, clientPath, `{"name":"Operations","max_devices":4}`},
		{http.MethodPost, clientPath + "/token", ""},
		{http.MethodDelete, clientPath + "/devices/" + forwardproxy.DeviceID, ""},
		{http.MethodDelete, clientPath, ""},
	} {
		response := adminRequest(t, handler, test.method, test.path, test.body)
		t.Logf("%s persistence ENOENT status=%d", test.method, response.Code)
		if response.Code != http.StatusInternalServerError {
			t.Errorf("persistence failure returned %d, want 500: %s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "private-registry-path") {
			t.Fatal("persistence failure exposed the private path")
		}
	}
	for _, test := range []struct {
		method, path, body string
	}{
		{http.MethodPut, "/api/clients/missing", `{"name":"Operations","max_devices":4}`},
		{http.MethodPost, "/api/clients/missing/token", ""},
		{http.MethodDelete, "/api/clients/missing", ""},
		{http.MethodDelete, clientPath + "/devices/missing", ""},
		{http.MethodPost, clientPath + "/devices/missing/disconnect", ""},
		{http.MethodPost, "/api/clients/missing/disconnect", ""},
	} {
		response := adminRequest(t, handler, test.method, test.path, test.body)
		if response.Code != http.StatusNotFound {
			t.Errorf("missing resource returned %d, want 404: %s", response.Code, response.Body.String())
		}
	}
}

func TestDisconnectEpochPinsQueuedAuthentication(t *testing.T) {
	for _, scope := range []string{"account", "device"} {
		t.Run(scope, func(t *testing.T) {
			registry := sessionTestRegistry(t)
			authenticateProxyForTest(t, registry, sessionTestToken)
			accountID := registry.clients[0].ID
			deviceID := forwardproxy.DeviceID
			if scope == "account" {
				deviceID = ""
			}
			before := registry.beginAuthentication()
			secondBefore := registry.beginAuthentication()
			if _, err := registry.Disconnect(accountID, deviceID); err != nil {
				t.Fatal(err)
			}
			fresh := registry.beginAuthentication()
			registry.mu.Lock()
			registry.endAuthenticationLocked(before)
			_, oldErr := registry.authenticateProxyLocked(sessionTestToken, secondBefore)
			registry.endAuthenticationLocked(secondBefore)
			entries := len(registry.accountDisconnect) + len(registry.deviceDisconnect)
			_, freshErr := registry.authenticateProxyLocked(sessionTestToken, fresh)
			registry.endAuthenticationLocked(fresh)
			registry.mu.Unlock()
			if !errors.Is(oldErr, errDeviceDraining) {
				t.Fatalf("queued authentication escaped disconnect: %v", oldErr)
			}
			if freshErr != nil {
				t.Fatalf("fresh authentication rejected: %v", freshErr)
			}
			if entries != 0 {
				t.Fatalf("retained %d epochs after all older attempts finished", entries)
			}
		})
	}
}

func TestAuthenticationEpochReleasedOnRejection(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, reason := range []string{"unauthorized", "canceled", "closed"} {
			t.Run(fmt.Sprintf("native-%v/%s", native, reason), func(t *testing.T) {
				registry := sessionTestRegistry(t)
				ctx := context.Background()
				token := "invalid-token"
				switch reason {
				case "canceled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case "closed":
					if err := registry.Close(); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				if native {
					_, _, _, err = registry.AuthenticateDeviceSession(ctx, token, deviceauth.Proof{}, "", "")
				} else {
					_, _, _, err = registry.AuthenticateProxySession(ctx, token)
				}
				if err == nil || len(registry.authenticationEpochs) != 0 {
					t.Fatalf("rejected authentication leaked epoch: err=%v epochs=%v", err, registry.authenticationEpochs)
				}
			})
		}
	}
}

func TestDisconnectEpochConcurrentForgetAndDelete(t *testing.T) {
	for _, deleteAccount := range []bool{false, true} {
		t.Run(fmt.Sprintf("delete-account-%v", deleteAccount), func(t *testing.T) {
			registry := sessionTestRegistry(t)
			id, ctx, release, err := registry.AuthenticateProxySession(context.Background(), sessionTestToken)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(release)
			key := registryDeviceKey{id.AccountID, forwardproxy.DeviceID}
			done := make(chan error, 4)
			for _, deviceID := range []string{"", forwardproxy.DeviceID} {
				go func() {
					_, err := registry.Disconnect(id.AccountID, deviceID)
					done <- err
				}()
			}
			waitSessionDone(t, ctx.Done())
			waitRegistryCondition(t, registry, func() bool {
				return registry.retiringAccounts[id.AccountID] == 1 && registry.retiring[key] == 1
			})
			// Completing an attempt during draining can reclaim the start
			// tombstones, but retirement must still block every new session.
			if _, _, _, err := registry.AuthenticateProxySession(context.Background(), sessionTestToken); !errors.Is(err, errDeviceDraining) {
				t.Fatalf("authentication during disconnect = %v", err)
			}
			during := registry.beginAuthentication()
			go func() { done <- registry.DeleteDevice(id.AccountID, key.deviceID) }()
			waitRegistryCondition(t, registry, func() bool { return registry.retiring[key] == 2 })
			operations := 3
			if deleteAccount {
				go func() { done <- registry.Delete(id.AccountID) }()
				waitRegistryCondition(t, registry, func() bool { return registry.findLocked(id.AccountID) == nil })
				operations++
			}
			release()
			for range operations {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("concurrent retirement did not drain")
				}
			}
			registry.mu.Lock()
			_, err = registry.authenticateProxyLocked(sessionTestToken, during)
			registry.endAuthenticationLocked(during)
			retained := len(registry.accountDisconnect) + len(registry.deviceDisconnect) +
				len(registry.retiring) + len(registry.retiringAccounts)
			registry.mu.Unlock()
			wantErr := errDeviceDraining
			if deleteAccount {
				wantErr = errClientUnauthorized
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("queued authentication after drain = %v, want %v", err, wantErr)
			}
			if retained != 0 {
				t.Fatalf("completed retirements retained %d entries", retained)
			}
			if !deleteAccount {
				authenticateProxyForTest(t, registry, sessionTestToken)
			}
		})
	}
}

func waitRegistryCondition(t *testing.T, registry *clientRegistry, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		registry.mu.Lock()
		ok := condition()
		registry.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("registry operation did not reach the drain barrier")
		}
		runtime.Gosched()
	}
}
