package clientid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
)

const stateVersion = 1

var invalidNameCharacters = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type Identity struct {
	ID   string
	Name string
	key  crypto.Signer
}

type state struct {
	Version    int    `json:"version"`
	PrivateKey string `json:"private_key"`
}

func New(signer crypto.Signer, name string) (*Identity, error) {
	if signer == nil {
		return nil, errors.New("device signer is required")
	}
	name, err := fromName(name)
	if err != nil {
		return nil, err
	}
	id, err := deviceauth.DeviceID(signer.Public())
	if err != nil {
		return nil, err
	}
	return &Identity{ID: id, Name: name, key: signer}, nil
}

func (i *Identity) Proof(token, method, path string) (deviceauth.Proof, error) {
	if i == nil {
		return deviceauth.Proof{}, errors.New("device identity is unavailable")
	}
	return deviceauth.NewProof(i.key, i.Name, token, method, path, time.Now(), nil)
}

func fromHostname(hostname func() (string, error)) (string, error) {
	name, err := hostname()
	if err != nil {
		return "", fmt.Errorf("read machine name: %w", err)
	}
	return fromName(name)
}

func fromName(name string) (string, error) {
	name = strings.Trim(invalidNameCharacters.ReplaceAllString(name, "-"), "-._")
	if name == "" {
		return "", errors.New("machine name must contain an ASCII letter or digit; rename this machine in OS settings")
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name, nil
}

func loadOrCreate(path string, protect, unprotect func([]byte) ([]byte, error)) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("device identity path is required")
	}
	if err := prepareIdentityStorage(path); err != nil {
		return nil, err
	}
	var key *ecdsa.PrivateKey
	err := withFileLock(path+".lock", func() error {
		data, err := os.ReadFile(path)
		if err == nil {
			key, err = decodeState(data, unprotect)
			return err
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read device identity: %w", err)
		}
		key, err = deviceauth.GenerateKey()
		if err != nil {
			return err
		}
		return persist(path, key, protect)
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

func decodeState(data []byte, unprotect func([]byte) ([]byte, error)) (*ecdsa.PrivateKey, error) {
	var stored state
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("decode device identity: %w", err)
	}
	if stored.Version != stateVersion {
		return nil, fmt.Errorf("unsupported device identity version %d", stored.Version)
	}
	protected, err := base64.RawStdEncoding.DecodeString(stored.PrivateKey)
	if err != nil {
		return nil, errors.New("device identity key is corrupt")
	}
	encoded, err := unprotect(protected)
	if err != nil {
		return nil, fmt.Errorf("unprotect device identity key: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, errors.New("device identity key is corrupt")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, errors.New("device identity key must use ECDSA P-256")
	}
	return key, nil
}

func persist(path string, key *ecdsa.PrivateKey, protect func([]byte) ([]byte, error)) error {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode device identity key: %w", err)
	}
	protected, err := protect(encoded)
	if err != nil {
		return fmt.Errorf("protect device identity key: %w", err)
	}
	data, err := json.MarshalIndent(state{
		Version:    stateVersion,
		PrivateKey: base64.RawStdEncoding.EncodeToString(protected),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode device identity: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create device identity directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".device-identity-*")
	if err != nil {
		return fmt.Errorf("create device identity temporary file: %w", err)
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
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace device identity: %w", err)
	}
	if err := secureIdentityFile(path); err != nil {
		return fmt.Errorf("secure device identity: %w", err)
	}
	if directory, err := os.Open(filepath.Dir(path)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}
