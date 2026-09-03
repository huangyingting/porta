package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

type certificateReloader struct {
	certPath string
	keyPath  string

	mu          sync.Mutex
	certificate *tls.Certificate
	certModTime time.Time
	keyModTime  time.Time
	certSize    int64
	keySize     int64
}

func staticTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("both --tls-cert and --tls-key are required")
	}
	loader := &certificateReloader{certPath: certPath, keyPath: keyPath}
	if _, err := loader.load(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: loader.GetCertificate,
	}, nil
}

func (r *certificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.load()
}

func (r *certificateReloader) load() (*tls.Certificate, error) {
	certInfo, err := os.Stat(r.certPath)
	if err != nil {
		return nil, fmt.Errorf("stat TLS certificate: %w", err)
	}
	keyInfo, err := os.Stat(r.keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat TLS key: %w", err)
	}
	if r.certificate != nil &&
		certInfo.ModTime() == r.certModTime &&
		keyInfo.ModTime() == r.keyModTime &&
		certInfo.Size() == r.certSize &&
		keyInfo.Size() == r.keySize {
		return r.certificate, nil
	}
	certificate, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		if r.certificate != nil {
			return r.certificate, nil
		}
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	r.certificate = &certificate
	r.certModTime = certInfo.ModTime()
	r.keyModTime = keyInfo.ModTime()
	r.certSize = certInfo.Size()
	r.keySize = keyInfo.Size()
	return r.certificate, nil
}
