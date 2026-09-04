package clientprofile

import (
	"crypto/rand"
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

	"github.com/huangyingting/porta/internal/tunnel"
)

const stateVersion = 1

type Profile struct {
	ID                string           `json:"id"`
	Name              string           `json:"name"`
	ServerURL         string           `json:"server_url"`
	ClientID          string           `json:"client_id"`
	Transport         tunnel.Transport `json:"transport"`
	CAPath            string           `json:"ca_path,omitempty"`
	Thumbprint        string           `json:"thumbprint,omitempty"`
	Reconnect         bool             `json:"reconnect"`
	ReconnectMaxDelay time.Duration    `json:"reconnect_max_delay"`
	CreatedAt         time.Time        `json:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at"`
}

type Protector interface {
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
}

type Store struct {
	mu        sync.Mutex
	path      string
	protector Protector
	state     state
}

type record struct {
	Profile
	ProtectedToken string `json:"protected_token"`
}

type state struct {
	Version  int      `json:"version"`
	Profiles []record `json:"profiles"`
}

func Open(path string, protector Protector) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("profile store path is required")
	}
	if protector == nil {
		return nil, errors.New("profile secret protector is required")
	}
	store := &Store{
		path:      path,
		protector: protector,
		state:     state{Version: stateVersion, Profiles: []record{}},
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read profile store: %w", err)
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode profile store: %w", err)
	}
	if store.state.Version != stateVersion {
		return nil, fmt.Errorf("unsupported profile store version %d", store.state.Version)
	}
	for index := range store.state.Profiles {
		if err := validate(store.state.Profiles[index].Profile); err != nil {
			return nil, fmt.Errorf("profile %d: %w", index+1, err)
		}
	}
	return store, nil
}

func (s *Store) List() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	profiles := make([]Profile, len(s.state.Profiles))
	for index, record := range s.state.Profiles {
		profiles[index] = record.Profile
	}
	sort.Slice(profiles, func(i, j int) bool {
		return strings.ToLower(profiles[i].Name) < strings.ToLower(profiles[j].Name)
	})
	return profiles
}

func (s *Store) Save(profile Profile, token string) (Profile, error) {
	now := time.Now().UTC()
	if profile.ID == "" {
		id, err := randomID()
		if err != nil {
			return Profile{}, err
		}
		profile.ID = id
		profile.CreatedAt = now
	}
	profile.UpdatedAt = now
	if profile.Transport == "" {
		profile.Transport = tunnel.TransportHTTP3
	}
	if profile.ReconnectMaxDelay <= 0 {
		profile.ReconnectMaxDelay = 30 * time.Second
	}
	profile.Name = strings.TrimSpace(profile.Name)
	profile.ServerURL = strings.TrimSpace(profile.ServerURL)
	profile.ClientID = strings.TrimSpace(profile.ClientID)
	if err := validate(profile); err != nil {
		return Profile{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.indexLocked(profile.ID)
	protectedToken := ""
	if index >= 0 {
		protectedToken = s.state.Profiles[index].ProtectedToken
		profile.CreatedAt = s.state.Profiles[index].CreatedAt
	}
	if token != "" {
		protected, err := s.protector.Protect([]byte(token))
		if err != nil {
			return Profile{}, fmt.Errorf("protect profile token: %w", err)
		}
		protectedToken = base64.RawStdEncoding.EncodeToString(protected)
	}
	if protectedToken == "" {
		return Profile{}, errors.New("profile token is required")
	}
	entry := record{Profile: profile, ProtectedToken: protectedToken}
	previous := append([]record(nil), s.state.Profiles...)
	if index >= 0 {
		s.state.Profiles[index] = entry
	} else {
		s.state.Profiles = append(s.state.Profiles, entry)
	}
	if err := s.persistLocked(); err != nil {
		s.state.Profiles = previous
		return Profile{}, err
	}
	return profile, nil
}

func (s *Store) Token(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.indexLocked(id)
	if index < 0 {
		return "", os.ErrNotExist
	}
	protected, err := base64.RawStdEncoding.DecodeString(s.state.Profiles[index].ProtectedToken)
	if err != nil {
		return "", errors.New("profile token is corrupt")
	}
	plain, err := s.protector.Unprotect(protected)
	if err != nil {
		return "", fmt.Errorf("unprotect profile token: %w", err)
	}
	return string(plain), nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.indexLocked(id)
	if index < 0 {
		return os.ErrNotExist
	}
	previous := append([]record(nil), s.state.Profiles...)
	s.state.Profiles = append(s.state.Profiles[:index], s.state.Profiles[index+1:]...)
	if err := s.persistLocked(); err != nil {
		s.state.Profiles = previous
		return err
	}
	return nil
}

func (s *Store) indexLocked(id string) int {
	for index := range s.state.Profiles {
		if s.state.Profiles[index].ID == id {
			return index
		}
	}
	return -1
}

func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode profile store: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".profiles-*")
	if err != nil {
		return fmt.Errorf("create profile temporary file: %w", err)
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
		return fmt.Errorf("replace profile store: %w", err)
	}
	return nil
}

func validate(profile Profile) error {
	if profile.ID == "" || len(profile.ID) > 64 {
		return errors.New("profile ID is invalid")
	}
	if profile.Name == "" || len(profile.Name) > 80 {
		return errors.New("profile name must contain 1 to 80 characters")
	}
	if profile.ServerURL == "" {
		return errors.New("server URL is required")
	}
	if profile.ClientID == "" || len(profile.ClientID) > 64 {
		return errors.New("client ID must contain 1 to 64 characters")
	}
	if profile.Transport != tunnel.TransportHTTP2 && profile.Transport != tunnel.TransportHTTP3 {
		return errors.New("transport must be h2 or h3")
	}
	return nil
}

func randomID() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate profile ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}
