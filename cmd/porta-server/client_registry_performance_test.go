package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/forwardproxy"
)

func TestClientRegistryTokenIndexLifecycle(t *testing.T) {
	const bootstrapToken = "bootstrap-token-0123456789"
	path := t.TempDir() + "/clients.json"
	registry, err := openClientRegistry(path, bootstrapToken)
	if err != nil {
		t.Fatal(err)
	}
	defaultID := registry.clients[0].ID
	assertTokenIndex(t, registry, bootstrapToken, defaultID)

	created, token, err := registry.Create("Indexed client", 2)
	if err != nil {
		t.Fatal(err)
	}
	assertTokenIndex(t, registry, token, created.ID)

	rotated, err := registry.RotateToken(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := registry.tokenIndex[sha256.Sum256([]byte(token))]; exists {
		t.Fatal("rotated token remained in the index")
	}
	assertTokenIndex(t, registry, rotated, created.ID)
	if _, err := registry.AuthenticatePortal(token); !errors.Is(err, errClientUnauthorized) {
		t.Fatalf("old token error = %v", err)
	}

	incorrectDigest := sha256.Sum256([]byte("incorrect-token"))
	registry.tokenIndex[incorrectDigest] = registry.tokenIndex[sha256.Sum256([]byte(rotated))]
	if _, err := registry.AuthenticatePortal("incorrect-token"); !errors.Is(err, errClientUnauthorized) {
		t.Fatalf("mismatched indexed hash error = %v", err)
	}
	delete(registry.tokenIndex, incorrectDigest)

	if err := registry.Delete(defaultID); err != nil {
		t.Fatal(err)
	}
	assertTokenIndex(t, registry, rotated, created.ID)
	if entry := registry.tokenIndex[sha256.Sum256([]byte(rotated))]; entry.clientIndex != 0 {
		t.Fatalf("shifted client index = %d, want 0", entry.clientIndex)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openClientRegistry(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertTokenIndex(t, reopened, rotated, created.ID)
}

func TestClientRegistryTokenIndexPreservesFirstDuplicateSemantics(t *testing.T) {
	const token = "duplicate-token-0123456789"
	registry := &clientRegistry{
		clients: []clientRecord{
			{ID: "0011223344556677", TokenHash: hashToken(token), Enabled: false},
			{ID: "8899aabbccddeeff", TokenHash: hashToken(token), Enabled: true},
		},
	}
	registry.rebuildTokenIndexLocked()
	if _, err := registry.AuthenticatePortal(token); !errors.Is(err, errClientDisabled) {
		t.Fatalf("duplicate token error = %v, want first client's disabled result", err)
	}
}

func TestClientRegistryTokenIndexConcurrentRotation(t *testing.T) {
	const initialToken = "bootstrap-token-0123456789"
	registry, err := openClientRegistry(t.TempDir()+"/clients.json", initialToken)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	clientID := registry.clients[0].ID
	var currentToken atomic.Value
	currentToken.Store(initialToken)
	stop := make(chan struct{})
	errs := make(chan error, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, err := registry.AuthenticatePortal(currentToken.Load().(string))
				if err != nil && !errors.Is(err, errClientUnauthorized) {
					select {
					case errs <- err:
					default:
					}
					return
				}
			}
		})
	}
	for range 25 {
		token, err := registry.RotateToken(clientID)
		if err != nil {
			t.Fatal(err)
		}
		currentToken.Store(token)
		assertTokenIndex(t, registry, token, clientID)
	}
	close(stop)
	workers.Wait()
	select {
	case err := <-errs:
		t.Fatalf("concurrent authentication error = %v", err)
	default:
	}
	if _, err := registry.AuthenticatePortal(currentToken.Load().(string)); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationEpochFenceRejectsPreDisconnectAttempts(t *testing.T) {
	key := registryDeviceKey{accountID: "account", deviceID: "device"}
	registry := &clientRegistry{
		accountDisconnect: map[string]uint64{"account": 4},
		deviceDisconnect:  map[registryDeviceKey]uint64{key: 6},
	}
	if !registry.authenticationBlockedLocked("account", key, 3) {
		t.Fatal("account disconnect did not reject an older authentication attempt")
	}
	if !registry.authenticationBlockedLocked("account", key, 5) {
		t.Fatal("device disconnect did not reject an older authentication attempt")
	}
	if registry.authenticationBlockedLocked("account", key, 6) {
		t.Fatal("post-disconnect authentication attempt was rejected")
	}
}

func TestClientRegistryPostCommitSyncFailureKeepsInstalledToken(t *testing.T) {
	const initialToken = "bootstrap-token-0123456789"
	path := t.TempDir() + "/clients.json"
	registry, err := openClientRegistry(path, initialToken)
	if err != nil {
		t.Fatal(err)
	}
	clientID := registry.clients[0].ID
	syncError := errors.New("directory sync failed")
	registry.syncDirectory = func(*os.File) error { return syncError }
	rotated, err := registry.RotateToken(clientID)
	if err != nil {
		t.Fatalf("committed rotation returned an error: %v", err)
	}
	if _, err := registry.AuthenticatePortal(initialToken); !errors.Is(err, errClientUnauthorized) {
		t.Fatalf("old token error = %v", err)
	}
	if _, err := registry.AuthenticatePortal(rotated); err != nil {
		t.Fatalf("new token was not installed in memory: %v", err)
	}
	if err := registry.Close(); !errors.Is(err, syncError) {
		t.Fatalf("Close error = %v, want durability error %v", err, syncError)
	}

	reopened, err := openClientRegistry(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.AuthenticatePortal(rotated); err != nil {
		t.Fatalf("new token was not installed on disk: %v", err)
	}
}

func TestProxyLastSeenWriteDoesNotHoldRegistryLock(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	registry, err := openClientRegistry(t.TempDir()+"/clients.json", token)
	if err != nil {
		t.Fatal(err)
	}
	authenticateProxyForTest(t, registry, token)
	ageProxyLastSeen(t, registry, 2*time.Minute)

	writeStarted := make(chan struct{})
	allowWrite := make(chan struct{})
	originalWrite := registry.writeState
	registry.metadataDebounce = 0
	registry.writeState = func(data []byte) error {
		close(writeStarted)
		<-allowWrite
		return originalWrite(data)
	}

	authenticateProxyForTest(t, registry, token)
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("debounced metadata write did not start")
	}

	authDone := make(chan error, 1)
	go func() {
		_, _, release, err := registry.AuthenticateProxySession(context.Background(), token)
		if err == nil {
			release()
		}
		authDone <- err
	}()
	select {
	case err := <-authDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("authentication blocked on the durable LastSeen write")
	}
	close(allowWrite)
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyLastSeenEventuallyPersists(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	path := t.TempDir() + "/clients.json"
	registry, err := openClientRegistry(path, token)
	if err != nil {
		t.Fatal(err)
	}
	authenticateProxyForTest(t, registry, token)
	ageProxyLastSeen(t, registry, 2*time.Minute)
	registry.mu.Lock()
	before := proxyLastSeenLocked(t, registry, registry.clients[0].ID)
	registry.metadataDebounce = 10 * time.Millisecond
	registry.mu.Unlock()

	authenticateProxyForTest(t, registry, token)
	deadline := time.Now().Add(2 * time.Second)
	for {
		reopened, err := openClientRegistry(path, "")
		if err != nil {
			t.Fatal(err)
		}
		reopened.mu.Lock()
		persisted := proxyLastSeenLocked(t, reopened, reopened.clients[0].ID)
		reopened.mu.Unlock()
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		if persisted.After(before) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy LastSeen was not eventually persisted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyLastSeenUpdatesCoalesceAndFlushOnClose(t *testing.T) {
	const bootstrapToken = "bootstrap-token-0123456789"
	path := t.TempDir() + "/clients.json"
	registry, err := openClientRegistry(path, bootstrapToken)
	if err != nil {
		t.Fatal(err)
	}
	second, secondToken, err := registry.Create("Second", 2)
	if err != nil {
		t.Fatal(err)
	}
	authenticateProxyForTest(t, registry, bootstrapToken)
	authenticateProxyForTest(t, registry, secondToken)

	before := make(map[string]time.Time)
	registry.mu.Lock()
	for clientIndex := range registry.clients {
		for deviceIndex := range registry.clients[clientIndex].Devices {
			device := &registry.clients[clientIndex].Devices[deviceIndex]
			if device.ID == forwardproxy.DeviceID {
				device.LastSeen = time.Now().Add(-2 * time.Minute)
				before[registry.clients[clientIndex].ID] = device.LastSeen
			}
		}
	}
	registry.metadataDebounce = time.Hour
	registry.mu.Unlock()

	originalWrite := registry.writeState
	var writes atomic.Int32
	registry.writeState = func(data []byte) error {
		writes.Add(1)
		return originalWrite(data)
	}
	authenticateProxyForTest(t, registry, bootstrapToken)
	authenticateProxyForTest(t, registry, secondToken)
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("coalesced metadata writes = %d, want 1", got)
	}
	if _, _, _, err := registry.AuthenticateProxySession(context.Background(), bootstrapToken); !errors.Is(err, errRegistryClosed) {
		t.Fatalf("authentication after close error = %v", err)
	}

	reopened, err := openClientRegistry(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, client := range reopened.clients {
		for _, device := range client.Devices {
			if device.ID == forwardproxy.DeviceID && !device.LastSeen.After(before[client.ID]) {
				t.Fatalf("client %s LastSeen was not flushed: %v", client.ID, device.LastSeen)
			}
		}
	}
	assertTokenIndex(t, reopened, secondToken, second.ID)
}

func TestProxyLastSeenCloseReportsFinalFlushFailure(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	registry, err := openClientRegistry(t.TempDir()+"/clients.json", token)
	if err != nil {
		t.Fatal(err)
	}
	authenticateProxyForTest(t, registry, token)
	ageProxyLastSeen(t, registry, 2*time.Minute)
	registry.metadataDebounce = time.Hour
	wantErr := errors.New("write failed")
	registry.writeState = func([]byte) error { return wantErr }
	authenticateProxyForTest(t, registry, token)
	if err := registry.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close error = %v, want %v", err, wantErr)
	}
}

func TestProxyLastSeenConcurrentAuthenticationCoalesces(t *testing.T) {
	const token = "bootstrap-token-0123456789"
	registry, err := openClientRegistry(t.TempDir()+"/clients.json", token)
	if err != nil {
		t.Fatal(err)
	}
	authenticateProxyForTest(t, registry, token)
	ageProxyLastSeen(t, registry, 2*time.Minute)

	originalWrite := registry.writeState
	var writes atomic.Int32
	registry.metadataDebounce = 20 * time.Millisecond
	registry.writeState = func(data []byte) error {
		writes.Add(1)
		return originalWrite(data)
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			<-start
			_, _, release, err := registry.AuthenticateProxySession(context.Background(), token)
			if err != nil {
				t.Error(err)
				return
			}
			release()
		})
	}
	close(start)
	workers.Wait()
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("concurrent LastSeen writes = %d, want 1", got)
	}
}

func BenchmarkClientRegistryAuthenticatePortal(b *testing.B) {
	for _, clients := range []int{1, 1000, 10_000} {
		b.Run(fmt.Sprintf("clients-%d", clients), func(b *testing.B) {
			registry := &clientRegistry{clients: make([]clientRecord, clients)}
			var token string
			for index := range clients {
				token = fmt.Sprintf("benchmark-token-%d-0123456789", index)
				registry.clients[index] = clientRecord{
					ID:        fmt.Sprintf("%016x", index),
					Name:      "Benchmark",
					TokenHash: hashToken(token),
					Enabled:   true,
				}
			}
			registry.rebuildTokenIndexLocked()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := registry.AuthenticatePortal(token); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func assertTokenIndex(t *testing.T, registry *clientRegistry, token, wantID string) {
	t.Helper()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry, exists := registry.tokenIndex[sha256.Sum256([]byte(token))]
	if !exists || entry.clientIndex < 0 || entry.clientIndex >= len(registry.clients) {
		t.Fatalf("token index entry = %d, %v", entry.clientIndex, exists)
	}
	if got := registry.clients[entry.clientIndex].ID; got != wantID {
		t.Fatalf("indexed client = %s, want %s", got, wantID)
	}
}

func authenticateProxyForTest(t *testing.T, registry *clientRegistry, token string) {
	t.Helper()
	_, _, release, err := registry.AuthenticateProxySession(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func ageProxyLastSeen(t *testing.T, registry *clientRegistry, age time.Duration) {
	t.Helper()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for clientIndex := range registry.clients {
		for deviceIndex := range registry.clients[clientIndex].Devices {
			device := &registry.clients[clientIndex].Devices[deviceIndex]
			if device.ID == forwardproxy.DeviceID {
				device.LastSeen = time.Now().Add(-age)
				return
			}
		}
	}
	t.Fatal("forward proxy device not found")
}

func proxyLastSeenLocked(t *testing.T, registry *clientRegistry, clientID string) time.Time {
	t.Helper()
	for _, client := range registry.clients {
		if client.ID != clientID {
			continue
		}
		for _, device := range client.Devices {
			if device.ID == forwardproxy.DeviceID {
				return device.LastSeen
			}
		}
	}
	t.Fatal("forward proxy device not found")
	return time.Time{}
}
