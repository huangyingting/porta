package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/forwardproxy"
	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/usage"
)

const (
	clientRegistryVersion = 2
	maxDeviceNonces       = 2048
	proxyMetadataDebounce = time.Second
)

var (
	errClientUnauthorized = errors.New("client token is invalid")
	errClientDisabled     = errors.New("client is disabled")
	errDeviceLimit        = errors.New("client device limit reached")
	errDeviceDraining     = errors.New("device sessions are being disconnected")
	errRegistryClosed     = errors.New("client registry is closed")
	dummyTokenDigest      = sha256.Sum256(nil)
)

type clientInputError string

func (e clientInputError) Error() string {
	return string(e)
}

type tokenIndexEntry struct {
	clientIndex int
	digest      [sha256.Size]byte
}

type clientRegistry struct {
	mu                sync.Mutex
	path              string
	logger            *slog.Logger
	clients           []clientRecord
	tokenIndex        map[[sha256.Size]byte]tokenIndexEntry
	sessions          map[registryDeviceKey]map[*activeClientSession]struct{}
	retiring          map[registryDeviceKey]int
	retiringAccounts  map[string]int
	disconnectEpoch   atomic.Uint64
	accountDisconnect map[string]uint64
	deviceDisconnect  map[registryDeviceKey]uint64
	nonces            map[registryDeviceKey]*deviceNonceWindow

	persistMu          sync.Mutex
	durabilityMu       sync.Mutex
	nextPersistSeq     uint64
	persistedSeq       uint64
	writeState         func([]byte) error
	syncDirectory      func(*os.File) error
	durabilityErr      error
	metadataDirty      bool
	metadataVersion    uint64
	metadataDebounce   time.Duration
	metadataWake       chan struct{}
	metadataStop       chan struct{}
	metadataDone       chan struct{}
	metadataWorkerOpen bool
	closed             bool
	closeErr           error
}

type registryDeviceKey struct {
	accountID string
	deviceID  string
}

type deviceNonceWindow struct {
	values     map[string]time.Time
	nextExpiry time.Time
}

type activeClientSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type clientRecord struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	TokenHash  string         `json:"token_hash"`
	MaxDevices int            `json:"max_devices"`
	Enabled    bool           `json:"enabled"`
	CreatedAt  time.Time      `json:"created_at"`
	Devices    []deviceRecord `json:"devices,omitempty"`
}

type deviceRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type registryState struct {
	Version int            `json:"version"`
	Clients []clientRecord `json:"clients"`
}

type clientSummary struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	MaxDevices        int             `json:"max_devices"`
	Enabled           bool            `json:"enabled"`
	CreatedAt         time.Time       `json:"created_at"`
	DeviceCount       int             `json:"device_count"`
	ActiveSessions    int             `json:"active_sessions"`
	ConnectionsTotal  uint64          `json:"connections_total"`
	BytesUploaded     uint64          `json:"bytes_uploaded"`
	BytesDownloaded   uint64          `json:"bytes_downloaded"`
	PacketsUploaded   uint64          `json:"packets_uploaded"`
	PacketsDownloaded uint64          `json:"packets_downloaded"`
	LastConnected     *time.Time      `json:"last_connected,omitempty"`
	LastDisconnected  *time.Time      `json:"last_disconnected,omitempty"`
	Devices           []deviceSummary `json:"devices"`
}

type deviceSummary struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	FirstSeen         time.Time  `json:"first_seen"`
	LastSeen          time.Time  `json:"last_seen"`
	ActiveSessions    int        `json:"active_sessions"`
	ConnectionsTotal  uint64     `json:"connections_total"`
	BytesUploaded     uint64     `json:"bytes_uploaded"`
	BytesDownloaded   uint64     `json:"bytes_downloaded"`
	PacketsUploaded   uint64     `json:"packets_uploaded"`
	PacketsDownloaded uint64     `json:"packets_downloaded"`
	LastConnected     *time.Time `json:"last_connected,omitempty"`
	LastDisconnected  *time.Time `json:"last_disconnected,omitempty"`
	Transport         string     `json:"transport,omitempty"`
	AssignedAddress   string     `json:"assigned_address,omitempty"`
	Target            string     `json:"target,omitempty"`
}

type clientPortalIdentity struct {
	ID   string
	Name string
}

func openClientRegistry(path, bootstrapToken string) (*clientRegistry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("client registry path is required")
	}
	registry := &clientRegistry{
		path:             path,
		logger:           slog.Default(),
		metadataDebounce: proxyMetadataDebounce,
	}
	registry.writeState = registry.writeStateFile
	registry.syncDirectory = func(directory *os.File) error { return directory.Sync() }
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if strings.TrimSpace(bootstrapToken) == "" {
			return nil, errors.New("client registry does not exist and no bootstrap token was provided")
		}
		clientID, err := randomHex(8)
		if err != nil {
			return nil, err
		}
		tokenHash := hashToken(bootstrapToken)
		registry.clients = []clientRecord{{
			ID:         clientID,
			Name:       "Default client",
			TokenHash:  tokenHash,
			MaxDevices: 5,
			Enabled:    true,
			CreatedAt:  time.Now().UTC(),
		}}
		registry.rebuildTokenIndexLocked()
		if err := registry.persistLocked(); err != nil {
			return nil, err
		}
		return registry, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read client registry: %w", err)
	}
	var state registryState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode client registry: %w", err)
	}
	if state.Version != clientRegistryVersion {
		return nil, fmt.Errorf("unsupported client registry version %d", state.Version)
	}
	for index := range state.Clients {
		if err := validateStoredClient(state.Clients[index]); err != nil {
			return nil, fmt.Errorf("client registry entry %d: %w", index+1, err)
		}
	}
	registry.clients = state.Clients
	registry.rebuildTokenIndexLocked()
	return registry, nil
}

// AuthenticateDeviceSession registers cancellation under the same lock as authentication.
// release must run after all packet/copy workers and usage accounting have drained.
func (r *clientRegistry) AuthenticateDeviceSession(parent context.Context, token string, proof deviceauth.Proof, method, path string) (gateway.ClientIdentity, context.Context, func(), error) {
	attemptEpoch := r.disconnectEpoch.Load()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := parent.Err(); err != nil {
		return gateway.ClientIdentity{}, nil, nil, err
	}
	if r.closed {
		return gateway.ClientIdentity{}, nil, nil, errRegistryClosed
	}
	identity, err := r.authenticateDeviceLocked(token, proof, method, path, attemptEpoch)
	if err != nil {
		return gateway.ClientIdentity{}, nil, nil, err
	}
	return r.registerSessionLocked(parent, identity, proof.DeviceID)
}

func (r *clientRegistry) AuthenticateProxySession(parent context.Context, token string) (gateway.ClientIdentity, context.Context, func(), error) {
	attemptEpoch := r.disconnectEpoch.Load()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := parent.Err(); err != nil {
		return gateway.ClientIdentity{}, nil, nil, err
	}
	if r.closed {
		return gateway.ClientIdentity{}, nil, nil, errRegistryClosed
	}
	identity, err := r.authenticateProxyLocked(token, attemptEpoch)
	if err != nil {
		return gateway.ClientIdentity{}, nil, nil, err
	}
	return r.registerSessionLocked(parent, identity, forwardproxy.DeviceID)
}

func (r *clientRegistry) registerSessionLocked(parent context.Context, identity gateway.ClientIdentity, deviceID string) (gateway.ClientIdentity, context.Context, func(), error) {
	ctx, cancel := context.WithCancel(parent)
	key := registryDeviceKey{identity.AccountID, deviceID}
	session := &activeClientSession{cancel: cancel, done: make(chan struct{})}
	if r.sessions == nil {
		r.sessions = make(map[registryDeviceKey]map[*activeClientSession]struct{})
	}
	if r.sessions[key] == nil {
		r.sessions[key] = make(map[*activeClientSession]struct{})
	}
	r.sessions[key][session] = struct{}{}
	var once sync.Once
	return identity, ctx, func() {
		once.Do(func() {
			cancel()
			r.mu.Lock()
			delete(r.sessions[key], session)
			if len(r.sessions[key]) == 0 {
				delete(r.sessions, key)
			}
			r.mu.Unlock()
			close(session.done)
		})
	}, nil
}

func (r *clientRegistry) authenticateDeviceLocked(token string, proof deviceauth.Proof, method, path string, attemptEpoch uint64) (gateway.ClientIdentity, error) {
	client, err := r.clientForTokenLocked(token)
	if err != nil {
		return gateway.ClientIdentity{}, err
	}
	key := registryDeviceKey{client.ID, proof.DeviceID}
	if r.authenticationBlockedLocked(client.ID, key, attemptEpoch) {
		return gateway.ClientIdentity{}, errDeviceDraining
	}
	encodedKey, signedAt, err := deviceauth.Verify(proof, token, method, path, time.Now().UTC())
	if err != nil {
		return gateway.ClientIdentity{}, errClientUnauthorized
	}
	if r.nonceSeenLocked(key, proof.Nonce, signedAt) {
		return gateway.ClientIdentity{}, errClientUnauthorized
	}
	canonicalKey := base64.RawURLEncoding.EncodeToString(encodedKey)
	now := time.Now().UTC()
	for deviceIndex := range client.Devices {
		device := &client.Devices[deviceIndex]
		if device.ID != proof.DeviceID {
			continue
		}
		if device.PublicKey != canonicalKey {
			return gateway.ClientIdentity{}, errClientUnauthorized
		}
		previous := *device
		device.Name = proof.Name
		if previous.Name != device.Name || now.Sub(previous.LastSeen) >= time.Minute {
			device.LastSeen = now
			if err := r.persistLocked(); err != nil {
				*device = previous
				return gateway.ClientIdentity{}, err
			}
		}
		r.rememberNonceLocked(key, proof.Nonce, signedAt)
		return registryIdentity(*client, proof.DeviceID), nil
	}
	if len(client.Devices) >= client.MaxDevices {
		return gateway.ClientIdentity{}, errDeviceLimit
	}
	client.Devices = append(client.Devices, deviceRecord{
		ID:        proof.DeviceID,
		Name:      proof.Name,
		PublicKey: canonicalKey,
		FirstSeen: now,
		LastSeen:  now,
	})
	if err := r.persistLocked(); err != nil {
		client.Devices = client.Devices[:len(client.Devices)-1]
		return gateway.ClientIdentity{}, err
	}
	r.rememberNonceLocked(key, proof.Nonce, signedAt)
	return registryIdentity(*client, proof.DeviceID), nil
}

func (r *clientRegistry) authenticateProxyLocked(token string, attemptEpoch uint64) (gateway.ClientIdentity, error) {
	client, err := r.clientForTokenLocked(token)
	if err != nil {
		return gateway.ClientIdentity{}, err
	}
	deviceID := forwardproxy.DeviceID
	key := registryDeviceKey{client.ID, deviceID}
	if r.authenticationBlockedLocked(client.ID, key, attemptEpoch) {
		return gateway.ClientIdentity{}, errDeviceDraining
	}
	now := time.Now().UTC()
	for deviceIndex := range client.Devices {
		device := &client.Devices[deviceIndex]
		if device.ID != deviceID {
			continue
		}
		if now.Sub(device.LastSeen) >= time.Minute {
			device.LastSeen = now
			r.markMetadataDirtyLocked()
		}
		return registryIdentity(*client, deviceID), nil
	}
	if len(client.Devices) >= client.MaxDevices {
		return gateway.ClientIdentity{}, errDeviceLimit
	}
	client.Devices = append(client.Devices, deviceRecord{
		ID:        deviceID,
		Name:      "Forward proxy",
		FirstSeen: now,
		LastSeen:  now,
	})
	if err := r.persistLocked(); err != nil {
		client.Devices = client.Devices[:len(client.Devices)-1]
		return gateway.ClientIdentity{}, err
	}
	return registryIdentity(*client, deviceID), nil
}

func (r *clientRegistry) clientForTokenLocked(token string) (*clientRecord, error) {
	tokenDigest := sha256.Sum256([]byte(token))
	entry, exists := r.tokenIndex[tokenDigest]
	if !exists {
		entry.digest = dummyTokenDigest
	}
	hashMatches := subtle.ConstantTimeCompare(entry.digest[:], tokenDigest[:])
	if !exists || entry.clientIndex < 0 || entry.clientIndex >= len(r.clients) || hashMatches != 1 {
		return nil, errClientUnauthorized
	}
	client := &r.clients[entry.clientIndex]
	if !client.Enabled {
		return nil, errClientDisabled
	}
	return client, nil
}

func (r *clientRegistry) nonceSeenLocked(key registryDeviceKey, nonce string, signedAt time.Time) bool {
	now := time.Now().UTC()
	if signedAt.Add(deviceauth.MaxClockSkew).Before(now) {
		return true
	}
	window := r.nonces[key]
	if window == nil {
		return false
	}
	if !window.nextExpiry.After(now) {
		window.nextExpiry = time.Time{}
		for value, expires := range window.values {
			if !expires.After(now) {
				delete(window.values, value)
				continue
			}
			if window.nextExpiry.IsZero() || expires.Before(window.nextExpiry) {
				window.nextExpiry = expires
			}
		}
		if len(window.values) == 0 {
			delete(r.nonces, key)
			return false
		}
	}
	if _, exists := window.values[nonce]; exists {
		return true
	}
	return len(window.values) >= maxDeviceNonces
}

func (r *clientRegistry) rememberNonceLocked(key registryDeviceKey, nonce string, signedAt time.Time) {
	if r.nonces == nil {
		r.nonces = make(map[registryDeviceKey]*deviceNonceWindow)
	}
	window := r.nonces[key]
	if window == nil {
		window = &deviceNonceWindow{values: make(map[string]time.Time)}
		r.nonces[key] = window
	}
	expires := signedAt.Add(deviceauth.MaxClockSkew)
	window.values[nonce] = expires
	if window.nextExpiry.IsZero() || expires.Before(window.nextExpiry) {
		window.nextExpiry = expires
	}
}

func (r *clientRegistry) AuthenticatePortal(token string) (clientPortalIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	client, err := r.clientForTokenLocked(token)
	if err != nil {
		return clientPortalIdentity{}, err
	}
	return clientPortalIdentity{ID: client.ID, Name: client.Name}, nil
}

func (r *clientRegistry) PortalClientActive(clientID, tokenHash string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, client := range r.clients {
		if client.ID == clientID {
			return client.Enabled &&
				subtle.ConstantTimeCompare([]byte(client.TokenHash), []byte(tokenHash)) == 1
		}
	}
	return false
}

func (r *clientRegistry) List(usageSnapshot ...usage.Snapshot) []clientSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	var snapshot usage.Snapshot
	if len(usageSnapshot) > 0 {
		snapshot = usageSnapshot[0]
	}
	summaries := make([]clientSummary, 0, len(r.clients))
	for _, client := range r.clients {
		devices := append([]deviceRecord(nil), client.Devices...)
		sort.Slice(devices, func(i, j int) bool { return devices[i].LastSeen.After(devices[j].LastSeen) })
		summaries = append(summaries, summarizeClient(client, devices, snapshot))
	}
	sort.Slice(summaries, func(i, j int) bool {
		return strings.ToLower(summaries[i].Name) < strings.ToLower(summaries[j].Name)
	})
	return summaries
}

func (r *clientRegistry) Create(name string, maxDevices int) (clientSummary, string, error) {
	name, err := validateClientInput(name, maxDevices)
	if err != nil {
		return clientSummary{}, "", err
	}
	token, err := randomToken()
	if err != nil {
		return clientSummary{}, "", err
	}
	clientID, err := randomHex(8)
	if err != nil {
		return clientSummary{}, "", err
	}
	client := clientRecord{
		ID:         clientID,
		Name:       name,
		TokenHash:  hashToken(token),
		MaxDevices: maxDevices,
		Enabled:    true,
		CreatedAt:  time.Now().UTC(),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients = append(r.clients, client)
	if err := r.persistLocked(); err != nil {
		r.clients = r.clients[:len(r.clients)-1]
		return clientSummary{}, "", err
	}
	r.rebuildTokenIndexLocked()
	return summarizeClient(client, nil, usage.Snapshot{}), token, nil
}

func (r *clientRegistry) Update(id, name string, maxDevices int, enabled bool) (clientSummary, error) {
	name, err := validateClientInput(name, maxDevices)
	if err != nil {
		return clientSummary{}, err
	}
	r.mu.Lock()
	var stopped []*activeClientSession
	defer func() {
		r.mu.Unlock()
		drainClientSessions(stopped)
	}()
	client := r.findLocked(id)
	if client == nil {
		return clientSummary{}, os.ErrNotExist
	}
	if maxDevices < len(client.Devices) {
		return clientSummary{}, clientInputError(fmt.Sprintf(
			"device limit cannot be below the %d enrolled devices", len(client.Devices),
		))
	}
	previous := *client
	client.Name = name
	client.MaxDevices = maxDevices
	client.Enabled = enabled
	if err := r.persistLocked(); err != nil {
		*client = previous
		return clientSummary{}, err
	}
	if !enabled {
		stopped = r.sessionsLocked(id, "")
	}
	return summarizeClient(*client, append([]deviceRecord(nil), client.Devices...), usage.Snapshot{}), nil
}

func (r *clientRegistry) RotateToken(id string) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	var stopped []*activeClientSession
	defer func() {
		r.mu.Unlock()
		drainClientSessions(stopped)
	}()
	client := r.findLocked(id)
	if client == nil {
		return "", os.ErrNotExist
	}
	previous := client.TokenHash
	client.TokenHash = hashToken(token)
	if err := r.persistLocked(); err != nil {
		client.TokenHash = previous
		return "", err
	}
	r.rebuildTokenIndexLocked()
	r.deleteAccountNoncesLocked(id)
	stopped = r.sessionsLocked(id, "")
	return token, nil
}

func (r *clientRegistry) Delete(id string) error {
	r.mu.Lock()
	var stopped []*activeClientSession
	defer func() {
		r.mu.Unlock()
		drainClientSessions(stopped)
	}()
	for index := range r.clients {
		if r.clients[index].ID != id {
			continue
		}
		previous := append([]clientRecord(nil), r.clients...)
		r.clients = append(r.clients[:index], r.clients[index+1:]...)
		if err := r.persistLocked(); err != nil {
			r.clients = previous
			return err
		}
		r.rebuildTokenIndexLocked()
		r.deleteAccountNoncesLocked(id)
		stopped = r.sessionsLocked(id, "")
		return nil
	}
	return os.ErrNotExist
}

func (r *clientRegistry) DeleteDevice(clientID, deviceID string) error {
	return r.forgetDevice(clientID, deviceID, nil)
}

func (r *clientRegistry) forgetDevice(clientID, deviceID string, store *usage.Store) error {
	r.mu.Lock()
	var stopped []*activeClientSession
	retired := false
	key := registryDeviceKey{clientID, deviceID}
	defer func() {
		r.mu.Unlock()
		drainClientSessions(stopped)
		if retired {
			if store != nil {
				store.DeleteDevice(clientID, deviceID)
			}
			r.mu.Lock()
			r.endDeviceRetirementLocked(key)
			r.mu.Unlock()
		}
	}()
	client := r.findLocked(clientID)
	if client == nil {
		return os.ErrNotExist
	}
	for index := range client.Devices {
		if client.Devices[index].ID != deviceID {
			continue
		}
		previous := append([]deviceRecord(nil), client.Devices...)
		client.Devices = append(client.Devices[:index], client.Devices[index+1:]...)
		if err := r.persistLocked(); err != nil {
			client.Devices = previous
			return err
		}
		delete(r.nonces, key)
		stopped = r.sessionsLocked(clientID, deviceID)
		if r.retiring == nil {
			r.retiring = make(map[registryDeviceKey]int)
		}
		r.retiring[key]++
		retired = true
		return nil
	}
	return os.ErrNotExist
}

func (r *clientRegistry) deleteAccountNoncesLocked(accountID string) {
	for key := range r.nonces {
		if key.accountID == accountID {
			delete(r.nonces, key)
		}
	}
}

func (r *clientRegistry) Disconnect(clientID, deviceID string) (int, error) {
	r.mu.Lock()
	client := r.findLocked(clientID)
	if client == nil {
		r.mu.Unlock()
		return 0, os.ErrNotExist
	}
	if deviceID != "" {
		found := false
		for _, device := range client.Devices {
			found = found || device.ID == deviceID
		}
		if !found {
			r.mu.Unlock()
			return 0, os.ErrNotExist
		}
	}
	if deviceID == "" {
		if r.retiringAccounts == nil {
			r.retiringAccounts = make(map[string]int)
		}
		if r.accountDisconnect == nil {
			r.accountDisconnect = make(map[string]uint64)
		}
		r.accountDisconnect[clientID] = r.disconnectEpoch.Add(1)
		r.retiringAccounts[clientID]++
	} else {
		key := registryDeviceKey{clientID, deviceID}
		if r.retiring == nil {
			r.retiring = make(map[registryDeviceKey]int)
		}
		if r.deviceDisconnect == nil {
			r.deviceDisconnect = make(map[registryDeviceKey]uint64)
		}
		r.deviceDisconnect[key] = r.disconnectEpoch.Add(1)
		r.retiring[key]++
	}
	stopped := r.sessionsLocked(clientID, deviceID)
	r.mu.Unlock()
	drainClientSessions(stopped)
	r.mu.Lock()
	if deviceID == "" {
		r.accountDisconnect[clientID] = r.disconnectEpoch.Add(1)
		r.retiringAccounts[clientID]--
		if r.retiringAccounts[clientID] == 0 {
			delete(r.retiringAccounts, clientID)
		}
	} else {
		key := registryDeviceKey{clientID, deviceID}
		r.deviceDisconnect[key] = r.disconnectEpoch.Add(1)
		r.endDeviceRetirementLocked(key)
	}
	r.mu.Unlock()
	return len(stopped), nil
}

func (r *clientRegistry) authenticationBlockedLocked(accountID string, key registryDeviceKey, attemptEpoch uint64) bool {
	return r.retiringAccounts[accountID] > 0 ||
		r.retiring[key] > 0 ||
		r.accountDisconnect[accountID] > attemptEpoch ||
		r.deviceDisconnect[key] > attemptEpoch
}

func (r *clientRegistry) endDeviceRetirementLocked(key registryDeviceKey) {
	r.retiring[key]--
	if r.retiring[key] == 0 {
		delete(r.retiring, key)
	}
}

func (r *clientRegistry) sessionsLocked(accountID, deviceID string) []*activeClientSession {
	var sessions []*activeClientSession
	for key, active := range r.sessions {
		if key.accountID == accountID && (deviceID == "" || key.deviceID == deviceID) {
			for session := range active {
				sessions = append(sessions, session)
			}
		}
	}
	return sessions
}

func drainClientSessions(sessions []*activeClientSession) {
	// Signal every lane before waiting for any of them. Never wait under r.mu.
	for _, session := range sessions {
		session.cancel()
	}
	for _, session := range sessions {
		<-session.done
	}
}

func (r *clientRegistry) findLocked(id string) *clientRecord {
	for index := range r.clients {
		if r.clients[index].ID == id {
			return &r.clients[index]
		}
	}
	return nil
}

func (r *clientRegistry) rebuildTokenIndexLocked() {
	r.tokenIndex = make(map[[sha256.Size]byte]tokenIndexEntry, len(r.clients))
	for index := range r.clients {
		decoded, err := hex.DecodeString(r.clients[index].TokenHash)
		if err != nil || len(decoded) != sha256.Size {
			continue
		}
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		if _, exists := r.tokenIndex[digest]; !exists {
			r.tokenIndex[digest] = tokenIndexEntry{clientIndex: index, digest: digest}
		}
	}
}

func (r *clientRegistry) markMetadataDirtyLocked() {
	r.metadataDirty = true
	r.metadataVersion++
	if !r.metadataWorkerOpen {
		r.metadataWake = make(chan struct{}, 1)
		r.metadataStop = make(chan struct{})
		r.metadataDone = make(chan struct{})
		r.metadataWorkerOpen = true
		go r.runMetadataPersister()
	}
	select {
	case r.metadataWake <- struct{}{}:
	default:
	}
}

func (r *clientRegistry) runMetadataPersister() {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	timerActive := false
	persistFailed := false
	defer func() {
		timer.Stop()
		close(r.metadataDone)
	}()
	for {
		select {
		case <-r.metadataWake:
			if !timerActive {
				r.mu.Lock()
				delay := r.metadataDebounce
				r.mu.Unlock()
				timer.Reset(delay)
				timerActive = true
			}
		case <-timer.C:
			timerActive = false
			if err := r.flushMetadata(); err != nil {
				if !persistFailed {
					r.logger.Error("persist client registry metadata", "error", err)
				}
				persistFailed = true
				r.mu.Lock()
				delay := r.metadataDebounce
				r.mu.Unlock()
				timer.Reset(delay)
				timerActive = true
			} else if persistFailed {
				r.logger.Info("client registry metadata persistence recovered")
				persistFailed = false
			}
		case <-r.metadataStop:
			err := r.flushMetadata()
			if err == nil && persistFailed {
				r.logger.Info("client registry metadata persistence recovered")
			}
			r.mu.Lock()
			r.closeErr = err
			r.mu.Unlock()
			return
		}
	}
}

func (r *clientRegistry) flushMetadata() error {
	r.mu.Lock()
	if !r.metadataDirty {
		r.mu.Unlock()
		return nil
	}
	version := r.metadataVersion
	data, sequence, err := r.snapshotLocked()
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if err := r.persistSnapshot(sequence, data); err != nil {
		return err
	}
	r.mu.Lock()
	if r.metadataVersion == version {
		r.metadataDirty = false
	}
	r.mu.Unlock()
	return nil
}

func (r *clientRegistry) Close() error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		if r.metadataWorkerOpen {
			close(r.metadataStop)
		}
	}
	done := r.metadataDone
	err := r.closeErr
	r.mu.Unlock()
	if done == nil {
		return errors.Join(err, r.retryDurabilitySync())
	}
	<-done
	r.mu.Lock()
	err = r.closeErr
	r.mu.Unlock()
	return errors.Join(err, r.retryDurabilitySync())
}

func (r *clientRegistry) persistLocked() error {
	data, sequence, err := r.snapshotLocked()
	if err != nil {
		return err
	}
	if err := r.persistSnapshot(sequence, data); err != nil {
		return err
	}
	r.metadataDirty = false
	return nil
}

func (r *clientRegistry) snapshotLocked() ([]byte, uint64, error) {
	state := registryState{Version: clientRegistryVersion, Clients: r.clients}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("encode client registry: %w", err)
	}
	data = append(data, '\n')
	r.nextPersistSeq++
	return data, r.nextPersistSeq, nil
}

func (r *clientRegistry) persistSnapshot(sequence uint64, data []byte) error {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	if sequence <= r.persistedSeq {
		return nil
	}
	if err := r.writeState(data); err != nil {
		return err
	}
	r.persistedSeq = sequence
	return nil
}

func (r *clientRegistry) writeStateFile(data []byte) error {
	directoryPath := filepath.Dir(r.path)
	if err := os.MkdirAll(directoryPath, 0o700); err != nil {
		return fmt.Errorf("create client registry directory: %w", err)
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open client registry directory: %w", err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			r.logger.Warn("close client registry directory", "error", err)
		}
	}()
	temp, err := os.CreateTemp(directoryPath, ".clients-*")
	if err != nil {
		return fmt.Errorf("create client registry temporary file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, r.path); err != nil {
		return fmt.Errorf("replace client registry: %w", err)
	}
	if err := r.syncDirectory(directory); err != nil {
		err = fmt.Errorf("sync client registry directory after commit: %w", err)
		r.setDurabilityError(err)
		r.logger.Error("client registry update committed without directory sync", "error", err)
		return nil
	}
	r.setDurabilityError(nil)
	return nil
}

func (r *clientRegistry) setDurabilityError(err error) {
	r.durabilityMu.Lock()
	r.durabilityErr = err
	r.durabilityMu.Unlock()
}

func (r *clientRegistry) currentDurabilityError() error {
	r.durabilityMu.Lock()
	defer r.durabilityMu.Unlock()
	return r.durabilityErr
}

func (r *clientRegistry) retryDurabilitySync() error {
	if r.currentDurabilityError() == nil {
		return nil
	}
	directory, err := os.Open(filepath.Dir(r.path))
	if err != nil {
		return fmt.Errorf("reopen client registry directory for sync: %w", err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			r.logger.Warn("close client registry directory", "error", err)
		}
	}()
	if err := r.syncDirectory(directory); err != nil {
		return fmt.Errorf("retry client registry directory sync: %w", err)
	}
	r.setDurabilityError(nil)
	return nil
}

func validateStoredClient(client clientRecord) error {
	if len(client.ID) != 16 {
		return errors.New("invalid client ID")
	}
	if _, err := hex.DecodeString(client.ID); err != nil {
		return errors.New("invalid client ID")
	}
	if _, err := validateClientInput(client.Name, client.MaxDevices); err != nil {
		return err
	}
	hash, err := hex.DecodeString(client.TokenHash)
	if err != nil || len(hash) != sha256.Size {
		return errors.New("invalid token hash")
	}
	seen := make(map[string]struct{}, len(client.Devices))
	for _, device := range client.Devices {
		if !gateway.ValidClientID(device.ID) {
			return fmt.Errorf("invalid device ID %q", device.ID)
		}
		if _, exists := seen[device.ID]; exists {
			return fmt.Errorf("duplicate device ID %q", device.ID)
		}
		seen[device.ID] = struct{}{}
		if device.ID == forwardproxy.DeviceID {
			if device.PublicKey != "" || device.Name != "Forward proxy" {
				return errors.New("invalid forward proxy device")
			}
		} else {
			if device.Name == "" || !gateway.ValidClientID(device.Name) {
				return fmt.Errorf("invalid device name %q", device.Name)
			}
			encodedKey, err := base64.RawURLEncoding.DecodeString(device.PublicKey)
			if err != nil || len(encodedKey) == 0 {
				return fmt.Errorf("invalid public key for device %q", device.ID)
			}
			if base64.RawURLEncoding.EncodeToString(encodedKey) != device.PublicKey {
				return fmt.Errorf("non-canonical public key for device %q", device.ID)
			}
			derivedID, err := deviceauth.DeviceIDFromEncoded(encodedKey)
			if err != nil {
				return fmt.Errorf("invalid public key for device %q: %w", device.ID, err)
			}
			if derivedID != device.ID {
				return fmt.Errorf("public key does not match device ID %q", device.ID)
			}
		}
	}
	if len(client.Devices) > client.MaxDevices {
		return errors.New("enrolled devices exceed device limit")
	}
	return nil
}

func validateClientInput(name string, maxDevices int) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return "", clientInputError("client name must contain 1 to 80 characters")
	}
	if maxDevices < 1 || maxDevices > 100 {
		return "", clientInputError("device limit must be between 1 and 100")
	}
	return name, nil
}

func summarizeClient(client clientRecord, devices []deviceRecord, snapshot usage.Snapshot) clientSummary {
	if devices == nil {
		devices = []deviceRecord{}
	}
	clientUsage := snapshot.Clients[client.ID]
	summary := clientSummary{
		ID:                client.ID,
		Name:              client.Name,
		MaxDevices:        client.MaxDevices,
		Enabled:           client.Enabled,
		CreatedAt:         client.CreatedAt,
		DeviceCount:       len(devices),
		ActiveSessions:    clientUsage.ActiveSessions,
		ConnectionsTotal:  clientUsage.ConnectionsTotal,
		BytesUploaded:     clientUsage.BytesUploaded,
		BytesDownloaded:   clientUsage.BytesDownloaded,
		PacketsUploaded:   clientUsage.PacketsUploaded,
		PacketsDownloaded: clientUsage.PacketsDownloaded,
		LastConnected:     clientUsage.LastConnected,
		LastDisconnected:  clientUsage.LastDisconnected,
		Devices:           make([]deviceSummary, 0, len(devices)),
	}
	for _, device := range devices {
		deviceUsage := usage.Device(snapshot, client.ID, device.ID)
		summary.Devices = append(summary.Devices, deviceSummary{
			ID:                device.ID,
			Name:              device.Name,
			FirstSeen:         device.FirstSeen,
			LastSeen:          device.LastSeen,
			ActiveSessions:    deviceUsage.ActiveSessions,
			ConnectionsTotal:  deviceUsage.ConnectionsTotal,
			BytesUploaded:     deviceUsage.BytesUploaded,
			BytesDownloaded:   deviceUsage.BytesDownloaded,
			PacketsUploaded:   deviceUsage.PacketsUploaded,
			PacketsDownloaded: deviceUsage.PacketsDownloaded,
			LastConnected:     deviceUsage.LastConnected,
			LastDisconnected:  deviceUsage.LastDisconnected,
			Transport:         deviceUsage.Transport,
			AssignedAddress:   deviceUsage.AssignedAddress,
			Target:            deviceUsage.Target,
		})
	}
	return summary
}

func registryIdentity(client clientRecord, deviceID string) gateway.ClientIdentity {
	sum := sha256.Sum256([]byte(client.ID + "\x00" + deviceID))
	return gateway.ClientIdentity{
		AccountID: client.ID,
		LeaseID:   "device-" + hex.EncodeToString(sum[:16]),
	}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate client token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate client ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}
