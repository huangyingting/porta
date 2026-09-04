package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

type certificateReloader struct {
	certPath string
	keyPath  string
	logger   *slog.Logger

	mu              sync.Mutex
	certificate     *tls.Certificate
	certInfo        os.FileInfo
	keyInfo         os.FileInfo
	lastReloadError string
}

func staticTLSConfig(certPath, keyPath string, logger *slog.Logger) (*tls.Config, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("both --tls-cert and --tls-key are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	loader := &certificateReloader{certPath: certPath, keyPath: keyPath, logger: logger}
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
	certificate, err := r.load()
	if err != nil && r.certificate != nil {
		if message := err.Error(); message != r.lastReloadError {
			r.logger.Warn("reload TLS certificate failed; keeping previous certificate", "error", err)
			r.lastReloadError = message
		}
		return r.certificate, nil
	}
	if err == nil && r.lastReloadError != "" {
		r.logger.Info("TLS certificate reload recovered")
		r.lastReloadError = ""
	}
	return certificate, err
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
		os.SameFile(certInfo, r.certInfo) && os.SameFile(keyInfo, r.keyInfo) &&
		certInfo.ModTime().Equal(r.certInfo.ModTime()) &&
		keyInfo.ModTime().Equal(r.keyInfo.ModTime()) &&
		certInfo.Size() == r.certInfo.Size() &&
		keyInfo.Size() == r.keyInfo.Size() {
		return r.certificate, nil
	}
	certificate, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	r.certificate = &certificate
	r.certInfo = certInfo
	r.keyInfo = keyInfo
	return r.certificate, nil
}
