package usage

import (
	"context"
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
)

const stateVersion = 1

type DeviceSnapshot struct {
	AccountID         string     `json:"account_id"`
	DeviceID          string     `json:"device_id"`
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

type ClientSnapshot struct {
	ActiveSessions    int        `json:"active_sessions"`
	ConnectionsTotal  uint64     `json:"connections_total"`
	BytesUploaded     uint64     `json:"bytes_uploaded"`
	BytesDownloaded   uint64     `json:"bytes_downloaded"`
	PacketsUploaded   uint64     `json:"packets_uploaded"`
	PacketsDownloaded uint64     `json:"packets_downloaded"`
	LastConnected     *time.Time `json:"last_connected,omitempty"`
	LastDisconnected  *time.Time `json:"last_disconnected,omitempty"`
}

type Snapshot struct {
	Clients map[string]ClientSnapshot
	Devices map[string]DeviceSnapshot
}

type Store struct {
	mu        sync.RWMutex
	persistMu sync.Mutex
	path      string
	logger    *slog.Logger
	devices   map[string]DeviceSnapshot
	sessions  map[string]*sessionState
	nextID    atomic.Uint64
}

type Session struct {
	store *Store
	key   string
	state *sessionState
	once  sync.Once
}

type sessionState struct {
	mu              sync.Mutex
	accountID       string
	deviceID        string
	refs            int
	closed          bool
	transport       string
	assignedAddress string
	target          string
	connectedAt     time.Time
	uploaded        uint64
	downloaded      uint64
	packetsUp       uint64
	packetsDown     uint64
}

type persistentState struct {
	Version int              `json:"version"`
	Devices []DeviceSnapshot `json:"devices"`
}

func Open(path string, logger *slog.Logger) (*Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	store := &Store{
		path:     strings.TrimSpace(path),
		logger:   logger,
		devices:  make(map[string]DeviceSnapshot),
		sessions: make(map[string]*sessionState),
	}
	if store.path == "" {
		return store, nil
	}
	data, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read usage state: %w", err)
	}
	var state persistentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode usage state: %w", err)
	}
	if state.Version != stateVersion {
		return nil, fmt.Errorf("unsupported usage state version %d", state.Version)
	}
	for _, device := range state.Devices {
		if device.AccountID == "" || device.DeviceID == "" {
			return nil, errors.New("usage state contains an invalid device")
		}
		device.ActiveSessions = 0
		store.devices[deviceKey(device.AccountID, device.DeviceID)] = device
	}
	return store, nil
}

func (s *Store) Begin(sessionKey, accountID, deviceID, transport, assignedAddress, target string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sessionKey == "" {
		sessionKey = fmt.Sprintf("session-%d", s.nextID.Add(1))
	}
	state := s.sessions[sessionKey]
	if state == nil {
		state = &sessionState{
			accountID:       accountID,
			deviceID:        deviceID,
			refs:            1,
			transport:       transport,
			assignedAddress: assignedAddress,
			target:          target,
			connectedAt:     time.Now().UTC(),
		}
		s.sessions[sessionKey] = state
	} else {
		state.refs++
		state.mu.Lock()
		if transport != "" {
			state.transport = transport
		}
		if assignedAddress != "" {
			state.assignedAddress = assignedAddress
		}
		if target != "" {
			state.target = target
		}
		state.mu.Unlock()
	}
	return &Session{store: s, key: sessionKey, state: state}
}

func (s *Session) AddUploaded(bytes, packets uint64) {
	if s == nil || s.state == nil {
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if !s.state.closed {
		s.state.uploaded += bytes
		s.state.packetsUp += packets
	}
}

func (s *Session) AddDownloaded(bytes, packets uint64) {
	if s == nil || s.state == nil {
		return
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if !s.state.closed {
		s.state.downloaded += bytes
		s.state.packetsDown += packets
	}
}

func (s *Session) Close() {
	if s == nil || s.store == nil {
		return
	}
	s.once.Do(func() { s.store.finish(s.key) })
}

func (s *Store) finish(key string) {
	s.mu.Lock()
	state := s.sessions[key]
	if state == nil {
		s.mu.Unlock()
		return
	}
	state.refs--
	if state.refs > 0 {
		s.mu.Unlock()
		return
	}
	delete(s.sessions, key)
	state.mu.Lock()
	state.closed = true
	now := time.Now().UTC()
	deviceKey := deviceKey(state.accountID, state.deviceID)
	device := s.devices[deviceKey]
	device.AccountID = state.accountID
	device.DeviceID = state.deviceID
	device.ConnectionsTotal++
	device.BytesUploaded += state.uploaded
	device.BytesDownloaded += state.downloaded
	device.PacketsUploaded += state.packetsUp
	device.PacketsDownloaded += state.packetsDown
	device.LastConnected = timePointer(state.connectedAt)
	device.LastDisconnected = timePointer(now)
	device.Transport = state.transport
	device.AssignedAddress = state.assignedAddress
	device.Target = state.target
	s.devices[deviceKey] = device
	state.mu.Unlock()
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		s.logger.Error("persist usage state", "error", err)
	}
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := Snapshot{
		Clients: make(map[string]ClientSnapshot),
		Devices: make(map[string]DeviceSnapshot, len(s.devices)),
	}
	for key, device := range s.devices {
		result.Devices[key] = device
	}
	for _, session := range s.sessions {
		session.mu.Lock()
		key := deviceKey(session.accountID, session.deviceID)
		device := result.Devices[key]
		device.AccountID = session.accountID
		device.DeviceID = session.deviceID
		device.ActiveSessions++
		device.ConnectionsTotal++
		device.BytesUploaded += session.uploaded
		device.BytesDownloaded += session.downloaded
		device.PacketsUploaded += session.packetsUp
		device.PacketsDownloaded += session.packetsDown
		device.LastConnected = timePointer(session.connectedAt)
		device.Transport = session.transport
		device.AssignedAddress = session.assignedAddress
		device.Target = session.target
		result.Devices[key] = device
		session.mu.Unlock()
	}
	result.Clients = make(map[string]ClientSnapshot)
	for _, device := range result.Devices {
		addClientUsage(result.Clients, device)
	}
	return result
}

func (s *Store) Run(ctx context.Context, interval time.Duration) {
	if s.path == "" {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.persist(); err != nil {
				s.logger.Error("persist usage state during shutdown", "error", err)
			}
			return
		case <-ticker.C:
			if err := s.persist(); err != nil {
				s.logger.Error("persist usage state checkpoint", "error", err)
			}
		}
	}
}

func Device(snapshot Snapshot, accountID, deviceID string) DeviceSnapshot {
	return snapshot.Devices[deviceKey(accountID, deviceID)]
}

func (s *Store) DeleteClient(accountID string) {
	s.mu.Lock()
	for key, device := range s.devices {
		if device.AccountID == accountID {
			delete(s.devices, key)
		}
	}
	for key, session := range s.sessions {
		if session.accountID == accountID {
			session.mu.Lock()
			session.closed = true
			session.mu.Unlock()
			delete(s.sessions, key)
		}
	}
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		s.logger.Error("persist usage state", "error", err)
	}
}

func (s *Store) DeleteDevice(accountID, deviceID string) {
	s.mu.Lock()
	delete(s.devices, deviceKey(accountID, deviceID))
	for key, session := range s.sessions {
		if session.accountID == accountID && session.deviceID == deviceID {
			session.mu.Lock()
			session.closed = true
			session.mu.Unlock()
			delete(s.sessions, key)
		}
	}
	s.mu.Unlock()
	if err := s.persist(); err != nil {
		s.logger.Error("persist usage state", "error", err)
	}
}

func addClientUsage(clients map[string]ClientSnapshot, device DeviceSnapshot) {
	client := clients[device.AccountID]
	client.ActiveSessions += device.ActiveSessions
	client.ConnectionsTotal += device.ConnectionsTotal
	client.BytesUploaded += device.BytesUploaded
	client.BytesDownloaded += device.BytesDownloaded
	client.PacketsUploaded += device.PacketsUploaded
	client.PacketsDownloaded += device.PacketsDownloaded
	client.LastConnected = latestTime(client.LastConnected, device.LastConnected)
	client.LastDisconnected = latestTime(client.LastDisconnected, device.LastDisconnected)
	clients[device.AccountID] = client
}

func latestTime(current, candidate *time.Time) *time.Time {
	if candidate == nil || (current != nil && !candidate.After(*current)) {
		return current
	}
	return timePointer(*candidate)
}

func timePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}

func deviceKey(accountID, deviceID string) string {
	return accountID + "\x00" + deviceID
}

func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.RLock()
	checkpoint := make(map[string]DeviceSnapshot, len(s.devices)+len(s.sessions))
	for key, device := range s.devices {
		checkpoint[key] = device
	}
	for _, session := range s.sessions {
		session.mu.Lock()
		key := deviceKey(session.accountID, session.deviceID)
		device := checkpoint[key]
		device.AccountID = session.accountID
		device.DeviceID = session.deviceID
		device.ConnectionsTotal++
		device.BytesUploaded += session.uploaded
		device.BytesDownloaded += session.downloaded
		device.PacketsUploaded += session.packetsUp
		device.PacketsDownloaded += session.packetsDown
		device.LastConnected = timePointer(session.connectedAt)
		device.Transport = session.transport
		device.AssignedAddress = session.assignedAddress
		device.Target = session.target
		checkpoint[key] = device
		session.mu.Unlock()
	}
	s.mu.RUnlock()
	devices := make([]DeviceSnapshot, 0, len(checkpoint))
	for _, device := range checkpoint {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].AccountID == devices[j].AccountID {
			return devices[i].DeviceID < devices[j].DeviceID
		}
		return devices[i].AccountID < devices[j].AccountID
	})
	data, err := json.MarshalIndent(persistentState{Version: stateVersion, Devices: devices}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode usage state: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create usage state directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".usage-*")
	if err != nil {
		return fmt.Errorf("create usage state temporary file: %w", err)
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
	if err := os.Rename(tempName, s.path); err != nil {
		return fmt.Errorf("replace usage state: %w", err)
	}
	if directory, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}
