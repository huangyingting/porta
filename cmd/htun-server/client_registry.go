package main

import (
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

	"github.com/htun-project/htun/internal/gateway"
)

const clientRegistryVersion = 1

var (
	errClientUnauthorized = errors.New("client token is invalid")
	errClientDisabled     = errors.New("client is disabled")
	errDeviceLimit        = errors.New("client device limit reached")
)

type clientRegistry struct {
	mu      sync.Mutex
	path    string
	clients []clientRecord
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
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	MaxDevices  int            `json:"max_devices"`
	Enabled     bool           `json:"enabled"`
	CreatedAt   time.Time      `json:"created_at"`
	DeviceCount int            `json:"device_count"`
	Devices     []deviceRecord `json:"devices"`
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
	if !gateway.ValidClientID(deviceID) {
		return gateway.ClientIdentity{}, errClientUnauthorized
	}
	tokenHash := hashToken(token)
	r.mu.Lock()
	defer r.mu.Unlock()
	for clientIndex := range r.clients {
		client := &r.clients[clientIndex]
		if subtle.ConstantTimeCompare([]byte(client.TokenHash), []byte(tokenHash)) != 1 {
			continue
		}
		if !client.Enabled {
			return gateway.ClientIdentity{}, errClientDisabled
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

func (r *clientRegistry) List() []clientSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	summaries := make([]clientSummary, 0, len(r.clients))
	for _, client := range r.clients {
		devices := append([]deviceRecord(nil), client.Devices...)
		sort.Slice(devices, func(i, j int) bool { return devices[i].LastSeen.After(devices[j].LastSeen) })
		summaries = append(summaries, summarizeClient(client, devices))
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
	return summarizeClient(client, nil), token, nil
}

func (r *clientRegistry) Update(id, name string, maxDevices int, enabled bool) (clientSummary, error) {
	name, err := validateClientInput(name, maxDevices)
	if err != nil {
		return clientSummary{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
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
	return summarizeClient(*client, append([]deviceRecord(nil), client.Devices...)), nil
}

func (r *clientRegistry) RotateToken(id string) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
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
	return token, nil
}

func (r *clientRegistry) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
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
		return nil
	}
	return os.ErrNotExist
}

func (r *clientRegistry) DeleteDevice(clientID, deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
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
		return nil
	}
	return os.ErrNotExist
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

func summarizeClient(client clientRecord, devices []deviceRecord) clientSummary {
	if devices == nil {
		devices = []deviceRecord{}
	}
	return clientSummary{
		ID:          client.ID,
		Name:        client.Name,
		MaxDevices:  client.MaxDevices,
		Enabled:     client.Enabled,
		CreatedAt:   client.CreatedAt,
		DeviceCount: len(devices),
		Devices:     devices,
	}
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
