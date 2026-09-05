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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/usage"
)

const clientRegistryVersion = 1

var (
	errClientUnauthorized = errors.New("client token is invalid")
	errClientDisabled     = errors.New("client is disabled")
	errDeviceLimit        = errors.New("client device limit reached")
	errDeviceDraining     = errors.New("device sessions are being disconnected")
)

type clientRegistry struct {
	mu       sync.Mutex
	path     string
	clients  []clientRecord
	sessions map[registryDeviceKey]map[*activeClientSession]struct{}
	retiring map[registryDeviceKey]bool
}

type registryDeviceKey struct {
	accountID string
	deviceID  string
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
	registry := &clientRegistry{path: path}
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
	return registry, nil
}

func (r *clientRegistry) Authenticate(token, deviceID string) (gateway.ClientIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.authenticateLocked(token, deviceID)
}

// AuthenticateSession registers cancellation under the same lock as authentication.
// release must run after all packet/copy workers and usage accounting have drained.
func (r *clientRegistry) AuthenticateSession(parent context.Context, token, deviceID string) (gateway.ClientIdentity, context.Context, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := parent.Err(); err != nil {
		return gateway.ClientIdentity{}, nil, nil, err
	}
	identity, err := r.authenticateLocked(token, deviceID)
	if err != nil {
		return gateway.ClientIdentity{}, nil, nil, err
	}
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

func (r *clientRegistry) authenticateLocked(token, deviceID string) (gateway.ClientIdentity, error) {
	if !gateway.ValidClientID(deviceID) {
		return gateway.ClientIdentity{}, errClientUnauthorized
	}
	tokenHash := hashToken(token)
	for clientIndex := range r.clients {
		client := &r.clients[clientIndex]
		if subtle.ConstantTimeCompare([]byte(client.TokenHash), []byte(tokenHash)) != 1 {
			continue
		}
		if !client.Enabled {
			return gateway.ClientIdentity{}, errClientDisabled
		}
		if r.retiring[registryDeviceKey{client.ID, deviceID}] {
			return gateway.ClientIdentity{}, errDeviceDraining
		}
		now := time.Now().UTC()
		for deviceIndex := range client.Devices {
			device := &client.Devices[deviceIndex]
			if device.ID != deviceID {
				continue
			}
			if now.Sub(device.LastSeen) >= time.Minute {
				previous := device.LastSeen
				device.LastSeen = now
				if err := r.persistLocked(); err != nil {
					device.LastSeen = previous
					return gateway.ClientIdentity{}, err
				}
			}
			return registryIdentity(*client, deviceID), nil
		}
		if len(client.Devices) >= client.MaxDevices {
			return gateway.ClientIdentity{}, errDeviceLimit
		}
		client.Devices = append(client.Devices, deviceRecord{
			ID:        deviceID,
			FirstSeen: now,
			LastSeen:  now,
		})
		if err := r.persistLocked(); err != nil {
			client.Devices = client.Devices[:len(client.Devices)-1]
			return gateway.ClientIdentity{}, err
		}
		return registryIdentity(*client, deviceID), nil
	}
	return gateway.ClientIdentity{}, errClientUnauthorized
}

func (r *clientRegistry) AuthenticatePortal(token string) (clientPortalIdentity, error) {
	tokenHash := hashToken(token)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, client := range r.clients {
		if subtle.ConstantTimeCompare([]byte(client.TokenHash), []byte(tokenHash)) != 1 {
			continue
		}
		if !client.Enabled {
			return clientPortalIdentity{}, errClientDisabled
		}
		return clientPortalIdentity{ID: client.ID, Name: client.Name}, nil
	}
	return clientPortalIdentity{}, errClientUnauthorized
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
		return clientSummary{}, fmt.Errorf("device limit cannot be below the %d enrolled devices", len(client.Devices))
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
			delete(r.retiring, key)
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
		stopped = r.sessionsLocked(clientID, deviceID)
		if r.retiring == nil {
			r.retiring = make(map[registryDeviceKey]bool)
		}
		r.retiring[key] = true
		retired = true
		return nil
	}
	return os.ErrNotExist
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
	stopped := r.sessionsLocked(clientID, deviceID)
	r.mu.Unlock()
	drainClientSessions(stopped)
	return len(stopped), nil
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

func (r *clientRegistry) persistLocked() error {
	state := registryState{Version: clientRegistryVersion, Clients: r.clients}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode client registry: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("create client registry directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(r.path), ".clients-*")
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
	if runtimeDir, err := os.Open(filepath.Dir(r.path)); err == nil {
		_ = runtimeDir.Sync()
		_ = runtimeDir.Close()
	}
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
	}
	if len(client.Devices) > client.MaxDevices {
		return errors.New("enrolled devices exceed device limit")
	}
	return nil
}

func validateClientInput(name string, maxDevices int) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return "", errors.New("client name must contain 1 to 80 characters")
	}
	if maxDevices < 1 || maxDevices > 100 {
		return "", errors.New("device limit must be between 1 and 100")
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
