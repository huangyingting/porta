package usage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	stateVersion                   = 1
	defaultPersistenceDelay        = 100 * time.Millisecond
	sessionClosed           uint64 = 1 << 63
	sessionWritersMask             = sessionClosed - 1
)

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
	mu               sync.RWMutex
	persistMu        sync.Mutex
	path             string
	logger           *slog.Logger
	devices          map[string]DeviceSnapshot
	sessions         map[string]*sessionState
	nextID           atomic.Uint64
	changeVersion    atomic.Uint64
	persistedVersion atomic.Uint64
	persistRequested chan struct{}
	persistenceDelay time.Duration
	writeState       func(string, []byte) error
}

type Session struct {
	store       *Store
	key         string
	state       *sessionState
	once        sync.Once
	lifecycle   atomic.Uint64
	generation  atomic.Uint64
	uploaded    atomic.Uint64
	downloaded  atomic.Uint64
	packetsUp   atomic.Uint64
	packetsDown atomic.Uint64
}

type sessionState struct {
	accountID       string
	deviceID        string
	transport       string
	assignedAddress string
	target          string
	connectedAt     time.Time
	members         map[*Session]struct{}
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
		path:             strings.TrimSpace(path),
		logger:           logger,
		devices:          make(map[string]DeviceSnapshot),
		sessions:         make(map[string]*sessionState),
		persistRequested: make(chan struct{}, 1),
		persistenceDelay: defaultPersistenceDelay,
		writeState:       writeStateAtomically,
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
		for {
			sessionKey = fmt.Sprintf("session-%d", s.nextID.Add(1))
			if s.sessions[sessionKey] == nil {
				break
			}
		}
	}
	state := s.sessions[sessionKey]
	if state == nil {
		state = &sessionState{
			accountID:       accountID,
			deviceID:        deviceID,
			transport:       transport,
			assignedAddress: assignedAddress,
			target:          target,
			connectedAt:     time.Now().UTC(),
			members:         make(map[*Session]struct{}),
		}
		s.sessions[sessionKey] = state
	} else {
		if transport != "" {
			state.transport = transport
		}
		if assignedAddress != "" {
			state.assignedAddress = assignedAddress
		}
		if target != "" {
			state.target = target
		}
	}
	session := &Session{store: s, key: sessionKey, state: state}
	state.members[session] = struct{}{}
	return session
}

func (s *Session) AddUploaded(bytes, packets uint64) {
	if s == nil || s.state == nil {
		return
	}
	if !s.beginUpdate() {
		return
	}
	s.uploaded.Add(bytes)
	s.packetsUp.Add(packets)
	s.endUpdate()
}

func (s *Session) AddDownloaded(bytes, packets uint64) {
	if s == nil || s.state == nil {
		return
	}
	if !s.beginUpdate() {
		return
	}
	s.downloaded.Add(bytes)
	s.packetsDown.Add(packets)
	s.endUpdate()
}

func (s *Session) beginUpdate() bool {
	// The high bit permanently closes the connection while the low bits count
	// in-flight updates, allowing Close to wait without taking the store lock.
	for {
		state := s.lifecycle.Load()
		if state&sessionClosed != 0 || state&sessionWritersMask == sessionWritersMask {
			return false
		}
		if s.lifecycle.CompareAndSwap(state, state+1) {
			return true
		}
	}
}

func (s *Session) endUpdate() {
	s.generation.Add(1)
	s.lifecycle.Add(^uint64(0))
}

type counterSnapshot struct {
	uploaded    uint64
	downloaded  uint64
	packetsUp   uint64
	packetsDown uint64
}

func (s *Session) counters() counterSnapshot {
	// A generation change catches writers that start and finish between the
	// lifecycle checks, so byte/packet pairs come from one stable update set.
	for {
		generation := s.generation.Load()
		if s.lifecycle.Load()&sessionWritersMask != 0 {
			runtime.Gosched()
			continue
		}
		counters := counterSnapshot{
			uploaded:    s.uploaded.Load(),
			downloaded:  s.downloaded.Load(),
			packetsUp:   s.packetsUp.Load(),
			packetsDown: s.packetsDown.Load(),
		}
		if s.lifecycle.Load()&sessionWritersMask == 0 && s.generation.Load() == generation {
			return counters
		}
	}
}

func (s *Session) stopAndSnapshot() counterSnapshot {
	for {
		state := s.lifecycle.Load()
		if state&sessionClosed != 0 || s.lifecycle.CompareAndSwap(state, state|sessionClosed) {
			break
		}
	}
	for s.lifecycle.Load()&sessionWritersMask != 0 {
		runtime.Gosched()
	}
	return s.counters()
}

func (s *Session) Close() {
	if s == nil || s.store == nil {
		return
	}
	s.once.Do(func() {
		counters := s.stopAndSnapshot()
		s.store.finish(s.key, s.state, s, counters)
	})
}

func (s *Store) finish(key string, expected *sessionState, session *Session, counters counterSnapshot) {
	s.mu.Lock()
	state := s.sessions[key]
	if state == nil || state != expected {
		s.mu.Unlock()
		return
	}
	if _, ok := state.members[session]; !ok {
		s.mu.Unlock()
		return
	}
	delete(state.members, session)
	state.uploaded += counters.uploaded
	state.downloaded += counters.downloaded
	state.packetsUp += counters.packetsUp
	state.packetsDown += counters.packetsDown
	if len(state.members) > 0 {
		s.mu.Unlock()
		return
	}
	delete(s.sessions, key)
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
	setConnectionMetadata(&device, state)
	device.LastDisconnected = timePointer(now)
	s.devices[deviceKey] = device
	s.mu.Unlock()
	s.requestPersistence()
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := Snapshot{
		Clients: make(map[string]ClientSnapshot),
		Devices: make(map[string]DeviceSnapshot, len(s.devices)),
	}
	for key, device := range s.devices {
		device.LastConnected = latestTime(nil, device.LastConnected)
		device.LastDisconnected = latestTime(nil, device.LastDisconnected)
		result.Devices[key] = device
	}
	for _, session := range s.sessions {
		key := deviceKey(session.accountID, session.deviceID)
		device := result.Devices[key]
		device.AccountID = session.accountID
		device.DeviceID = session.deviceID
		device.ActiveSessions++
		device.ConnectionsTotal++
		addCounters(&device, session.counters())
		setConnectionMetadata(&device, session)
		result.Devices[key] = device
	}
	for _, device := range result.Devices {
		addClientUsage(result.Clients, device)
	}
	return result
}

func (s *Store) Run(ctx context.Context, interval time.Duration) error {
	if s.path == "" {
		return nil
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	resetTimer := func() {
		if timer == nil {
			timer = time.NewTimer(s.persistenceDelay)
		} else {
			stopTimer()
			timer.Reset(s.persistenceDelay)
		}
		timerC = timer.C
	}
	defer stopTimer()
	for {
		select {
		case <-ctx.Done():
			if err := s.flush(s.hasActiveSessions()); err != nil {
				return fmt.Errorf("persist usage state during shutdown: %w", err)
			}
			return nil
		case <-s.persistRequested:
			resetTimer()
		case <-timerC:
			timerC = nil
			if err := s.flush(false); err != nil {
				s.logger.Error("persist usage state", "error", err)
				resetTimer()
			}
		case <-ticker.C:
			if err := s.flush(true); err != nil {
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
			for member := range session.members {
				member.stopAndSnapshot()
			}
			delete(s.sessions, key)
		}
	}
	s.mu.Unlock()
	s.requestPersistence()
	if err := s.Flush(); err != nil {
		s.logger.Error("persist usage state", "error", err)
	}
}

func (s *Store) DeleteDevice(accountID, deviceID string) {
	s.mu.Lock()
	delete(s.devices, deviceKey(accountID, deviceID))
	for key, session := range s.sessions {
		if session.accountID == accountID && session.deviceID == deviceID {
			for member := range session.members {
				member.stopAndSnapshot()
			}
			delete(s.sessions, key)
		}
	}
	s.mu.Unlock()
	s.requestPersistence()
	if err := s.Flush(); err != nil {
		s.logger.Error("persist usage state", "error", err)
	}
}

func addCounters(device *DeviceSnapshot, counters counterSnapshot) {
	device.BytesUploaded += counters.uploaded
	device.BytesDownloaded += counters.downloaded
	device.PacketsUploaded += counters.packetsUp
	device.PacketsDownloaded += counters.packetsDown
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

func setConnectionMetadata(device *DeviceSnapshot, session *sessionState) {
	if device.LastConnected != nil && session.connectedAt.Before(*device.LastConnected) {
		return
	}
	device.LastConnected = timePointer(session.connectedAt)
	device.Transport = session.transport
	device.AssignedAddress = session.assignedAddress
	device.Target = session.target
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

func (s *sessionState) counters() counterSnapshot {
	counters := counterSnapshot{
		uploaded:    s.uploaded,
		downloaded:  s.downloaded,
		packetsUp:   s.packetsUp,
		packetsDown: s.packetsDown,
	}
	for member := range s.members {
		memberCounters := member.counters()
		counters.uploaded += memberCounters.uploaded
		counters.downloaded += memberCounters.downloaded
		counters.packetsUp += memberCounters.packetsUp
		counters.packetsDown += memberCounters.packetsDown
	}
	return counters
}

func (s *Store) requestPersistence() {
	if s.path == "" {
		return
	}
	s.changeVersion.Add(1)
	select {
	case s.persistRequested <- struct{}{}:
	default:
	}
}

func (s *Store) hasActiveSessions() bool {
	s.mu.RLock()
	active := len(s.sessions) > 0
	s.mu.RUnlock()
	return active
}

func (s *Store) Flush() error {
	return s.flush(true)
}

func (s *Store) flush(force bool) error {
	if s.path == "" {
		return nil
	}
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	version := s.changeVersion.Load()
	if !force && version <= s.persistedVersion.Load() {
		return nil
	}
	if err := s.persist(); err != nil {
		return err
	}
	for {
		persisted := s.persistedVersion.Load()
		if persisted >= version || s.persistedVersion.CompareAndSwap(persisted, version) {
			return nil
		}
	}
}

func (s *Store) persist() error {
	s.mu.RLock()
	checkpoint := make(map[string]DeviceSnapshot, len(s.devices)+len(s.sessions))
	for key, device := range s.devices {
		checkpoint[key] = device
	}
	for _, session := range s.sessions {
		counters := session.counters()
		key := deviceKey(session.accountID, session.deviceID)
		device := checkpoint[key]
		device.AccountID = session.accountID
		device.DeviceID = session.deviceID
		device.ConnectionsTotal++
		addCounters(&device, counters)
		setConnectionMetadata(&device, session)
		checkpoint[key] = device
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
	return s.writeState(s.path, data)
}

func writeStateAtomically(path string, data []byte) error {
	directoryPath := filepath.Dir(path)
	if err := os.MkdirAll(directoryPath, 0o700); err != nil {
		return fmt.Errorf("create usage state directory: %w", err)
	}
	temp, err := os.CreateTemp(directoryPath, ".usage-*")
	if err != nil {
		return fmt.Errorf("create usage state temporary file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure usage state temporary file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write usage state temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync usage state temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close usage state temporary file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace usage state: %w", err)
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open usage state directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync usage state directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close usage state directory: %w", err)
	}
	return nil
}
