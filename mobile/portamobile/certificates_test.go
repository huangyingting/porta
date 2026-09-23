package portamobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

type certificateVerifierFunc func(string, []byte, int64) string

func (f certificateVerifierFunc) Verify(host string, chain []byte, now int64) string {
	return f(host, chain, now)
}

func certificateFixture(t *testing.T, modify func(*x509.Certificate)) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Android platform test root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"vpn.example.com"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute),
	}
	if modify != nil {
		modify(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: key, Leaf: leaf}, roots
}

func testPlatformVerifier(roots *x509.CertPool) CertificateVerifier {
	return certificateVerifierFunc(func(host string, chainPEM []byte, now int64) string {
		var chain []*x509.Certificate
		for len(chainPEM) > 0 {
			block, rest := pem.Decode(chainPEM)
			if block == nil || block.Type != "CERTIFICATE" {
				return "invalid platform PEM contract"
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err.Error()
			}
			chain = append(chain, cert)
			chainPEM = rest
		}
		intermediates := x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
		_, err := chain[0].Verify(x509.VerifyOptions{
			DNSName: host, Roots: roots, Intermediates: intermediates,
			CurrentTime: time.UnixMilli(now), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return err.Error()
		}
		return ""
	})
}

func TestPlatformCertificatesRequireIdentityValidityAndUsage(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		modify func(*x509.Certificate)
	}{
		{"hostname", "attacker.example.com", nil},
		{"missing hostname", "", nil},
		{"expired", "vpn.example.com", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }},
		{"future", "vpn.example.com", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Second) }},
		{"client-only EKU", "vpn.example.com", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"unknown EKU", "vpn.example.com", func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}},
		{"cannot sign", "vpn.example.com", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, _ := certificateFixture(t, test.modify)
			verifier := certificateVerifierFunc(func(string, []byte, int64) string {
				t.Fatal("invalid certificate reached platform trust callback")
				return ""
			})
			if err := verifyPlatformCertificates(test.host, []*x509.Certificate{fixture.Leaf}, time.Now(), verifier); err == nil {
				t.Fatal("invalid certificate accepted")
			}
		})
	}
	if _, err := platformTLSConfig("vpn.example.com", nil); err == nil {
		t.Fatal("missing platform verifier enabled unverified TLS")
	}
}

func TestPlatformTLSRequiresTrustedSignedChain(t *testing.T) {
	fixture, roots := certificateFixture(t, nil)
	for _, test := range []struct {
		name     string
		verifier CertificateVerifier
		accept   bool
	}{
		{"trusted platform root", testPlatformVerifier(roots), true},
		{"untrusted root", testPlatformVerifier(x509.NewCertPool()), false},
		{"platform policy", certificateVerifierFunc(func(string, []byte, int64) string {
			return "retryable: platform trust rejected"
		}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := platformTLSConfig("vpn.example.com", test.verifier)
			if err != nil {
				t.Fatal(err)
			}

			listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{fixture}, MinVersion: tls.VersionTLS13,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_ = conn.(*tls.Conn).Handshake()
				}
			}()
			conn, err := tls.Dial("tcp4", listener.Addr().String(), config)
			if conn != nil {
				conn.Close()
			}
			<-done
			if (err == nil) != test.accept {
				t.Fatalf("TLS result %v; accept=%v", err, test.accept)
			}
			if err != nil {
				classified := classifyDialError(err)
				if IsRetryable(classified.Error()) || IsTransportUnavailable(classified.Error()) {
					t.Fatalf("certificate rejection permitted fallback/retry: %v", classified)
				}
				var verification *tls.CertificateVerificationError
				if !errors.As(err, &verification) {
					t.Fatalf("certificate rejection lost its type: %v", err)
				}
			}
		})
	}
	mutated := append([]byte(nil), fixture.Leaf.Raw...)
	mutated[len(mutated)-1] ^= 1
	invalid, err := x509.ParseCertificate(mutated)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyPlatformCertificates("vpn.example.com", []*x509.Certificate{invalid}, time.Now(), testPlatformVerifier(roots))
	if err == nil || !strings.Contains(err.Error(), "platform certificate verification") {
		t.Fatalf("invalid certificate signature accepted: %v", err)
	}
}

func TestCertificateProbeUsesNativeIdentityAndTrustChecks(t *testing.T) {
	fixture, roots := certificateFixture(t, nil)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Leaf.Raw})
	if err := VerifyCertificateChain("vpn.example.com", chain, time.Now().UnixMilli(), testPlatformVerifier(roots)); err != nil {
		t.Fatalf("valid probe failed: %v", err)
	}
	for _, test := range []struct {
		host  string
		chain []byte
		time  time.Time
	}{
		{"other.example.com", chain, time.Now()},
		{"vpn.example.com", chain, fixture.Leaf.NotAfter.Add(time.Second)},
		{"vpn.example.com", []byte("not PEM"), time.Now()},
		{"vpn.example.com", nil, time.Now()},
	} {
		if err := VerifyCertificateChain(test.host, test.chain, test.time.UnixMilli(), testPlatformVerifier(roots)); err == nil {
			t.Fatal("invalid platform certificate probe succeeded")
		}
	}
}
