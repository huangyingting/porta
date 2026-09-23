package portamobile

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// CertificateVerifier is implemented by Android's platform trust manager.
// Verify must verify the entire PEM certificate chain (leaf first), including
// signatures, trust anchors, constraints and server authentication usage.
// It returns an empty string only on success. Hostname and time checks are
// additionally enforced in Go; the platform must never accept untrusted chains.
type CertificateVerifier interface {
	Verify(hostname string, chainPEM []byte, unixTimeMillis int64) string
}

// VerifyCertificateChain exercises the same verification as a native TLS
// connection. It is used by Android platform probes without opening a tunnel.
// DialWithPlatform always uses the current time, not a caller-supplied clock.
func VerifyCertificateChain(hostname string, chainPEM []byte, unixTimeMillis int64, verifier CertificateVerifier) error {
	var chain []*x509.Certificate
	for len(bytes.TrimSpace(chainPEM)) > 0 {
		block, rest := pem.Decode(chainPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("invalid PEM certificate chain")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse peer certificate: %w", err)
		}
		chain = append(chain, certificate)
		chainPEM = rest
	}
	return verifyPlatformCertificates(hostname, chain, time.UnixMilli(unixTimeMillis), verifier)
}

func platformTLSConfig(hostname string, verifier CertificateVerifier) (*tls.Config, error) {
	if verifier == nil {
		return nil, errors.New("configuration: platform certificate verifier is required")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: hostname,
		// Android owns the trust store. The callback replaces, rather than
		// disables, certificate verification; Go still verifies TLS signatures.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if err := verifyPlatformCertificates(hostname, state.PeerCertificates, time.Now(), verifier); err != nil {
				return &tls.CertificateVerificationError{UnverifiedCertificates: state.PeerCertificates, Err: err}
			}
			return nil
		},
	}, nil
}

func verifyPlatformCertificates(hostname string, chain []*x509.Certificate, now time.Time, verifier CertificateVerifier) error {
	if verifier == nil || len(chain) == 0 {
		return errors.New("certificate verification requires a platform verifier and peer chain")
	}
	if hostname == "" {
		return errors.New("certificate verification requires a hostname")
	}
	if err := chain[0].VerifyHostname(hostname); err != nil {
		return err
	}
	var encoded bytes.Buffer
	for _, certificate := range chain {
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return x509.CertificateInvalidError{Cert: certificate, Reason: x509.Expired}
		}
		if err := pem.Encode(&encoded, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			return fmt.Errorf("encode peer certificate: %w", err)
		}
	}
	leaf := chain[0]
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
		}
		if !serverAuth {
			return x509.CertificateInvalidError{Cert: leaf, Reason: x509.IncompatibleUsage}
		}
	}
	for _, extension := range leaf.Extensions {
		if extension.Id.String() == "2.5.29.15" && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return errors.New("certificate does not permit TLS digital signatures")
		}
	}
	if failure := verifier.Verify(hostname, encoded.Bytes(), now.UnixMilli()); failure != "" {
		return fmt.Errorf("platform certificate verification: %s", failure)
	}
	return nil
}
