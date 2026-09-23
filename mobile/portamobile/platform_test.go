package portamobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/gateway"
	"github.com/quic-go/quic-go/http3"
)

type proofProviderFunc func(string, string) (string, error)

func (f proofProviderFunc) Proof(method, path string) (string, error) { return f(method, path) }

func proofJSON(t *testing.T, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(map[string]string{
		"publicKey": base64.RawURLEncoding.EncodeToString(der),
		"timestamp": "1234", "nonce": "test-nonce", "signature": "test-signature", "deviceName": name,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func TestPlatformProofIsFreshAndBoundToDeviceKey(t *testing.T) {
	value := proofJSON(t, "Android test")
	calls := 0
	provider := platformProof(proofProviderFunc(func(method, path string) (string, error) {
		calls++
		if method != "CONNECT" || path != gateway.MasquePath {
			t.Fatal("incorrect proof target")
		}
		return value, nil
	}))
	if _, err := provider("POST", gateway.MasquePath); err == nil || calls != 0 {
		t.Fatal("unexpected target reached Android signer")
	}
	first, err := provider("CONNECT", gateway.MasquePath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider("CONNECT", gateway.MasquePath)
	if err != nil || first.DeviceID != second.DeviceID || calls != 2 {
		t.Fatalf("proof was cached or identity changed: %v, calls %d", err, calls)
	}
	value = proofJSON(t, "another key")
	if _, err := provider("CONNECT", gateway.MasquePath); err == nil {
		t.Fatal("signer changed keys during a connection")
	}
	for _, invalid := range []string{"{", "{}", `{"publicKey":"invalid"}`} {
		provider := platformProof(proofProviderFunc(func(string, string) (string, error) { return invalid, nil }))
		if _, err := provider("CONNECT", gateway.MasquePath); err == nil {
			t.Fatalf("invalid Android proof accepted: %s", invalid)
		}
	}
}

func TestPlatformDialCompletesTLSBeforeRequestingProof(t *testing.T) {
	fixture, roots := certificateFixture(t, nil)
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{fixture}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}),
		EnableDatagrams: true,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	defer func() {
		server.Close()
		listener.Close()
		<-done
	}()
	_, port, err := net.SplitHostPort(listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, accept := range []bool{true, false} {
		t.Run(map[bool]string{true: "trusted", false: "untrusted"}[accept], func(t *testing.T) {
			var verified, proofRequested atomic.Bool
			platform := testPlatformVerifier(roots)
			verifier := certificateVerifierFunc(func(host string, chain []byte, now int64) string {
				if !accept {
					return "platform rejected certificate"
				}
				result := platform.Verify(host, chain, now)
				verified.Store(result == "")
				return result
			})
			provider := proofProviderFunc(func(method, path string) (string, error) {
				if !verified.Load() || method != "CONNECT" || path != gateway.MasquePath {
					return "", errors.New("proof requested before verified TLS or for incorrect target")
				}
				proofRequested.Store(true)
				return "", errors.New("intentional proof probe rejection")
			})
			dialer := NewDialer()
			defer dialer.Close()
			timer := time.AfterFunc(5*time.Second, dialer.Close)
			defer timer.Stop()
			_, err := dialer.DialWithPlatform(
				"https://vpn.example.com:"+port, "certificate-probe-no-account", "127.0.0.1",
				&recordingProtector{}, verifier, provider,
			)
			if err == nil || IsTransportUnavailable(err.Error()) || IsRetryable(err.Error()) {
				t.Fatalf("TLS/proof probe must fail permanently, not downgrade: %v", err)
			}
			if proofRequested.Load() != accept {
				t.Fatalf("proof requested=%v after verified TLS=%v: %v", proofRequested.Load(), accept, err)
			}
			if accept && !strings.Contains(err.Error(), "intentional proof probe rejection") {
				t.Fatalf("proof failure did not cross bridge: %v", err)
			}
		})
	}
}

func TestClosedPlatformDialDoesNotCallAndroid(t *testing.T) {
	dialer := NewDialer()
	dialer.Close()
	_, err := dialer.DialWithPlatform("", "", "", nil, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("closed platform dial = %v", err)
	}
}

func TestPlatformDialerCancelsPendingHandshake(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialer := NewDialer()
	defer dialer.Close()
	unexpected := &atomic.Bool{}
	done := make(chan error, 1)
	go func() {
		_, err := dialer.DialWithPlatform(
			"https://vpn.example.com:"+port, "pending-handshake-probe", "127.0.0.1",
			&recordingProtector{},
			certificateVerifierFunc(func(string, []byte, int64) string {
				unexpected.Store(true)
				return "unexpected verifier callback"
			}),
			proofProviderFunc(func(string, string) (string, error) {
				unexpected.Store(true)
				return "", errors.New("unexpected proof callback")
			}),
		)
		done <- err
	}()
	if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listener.ReadFrom(make([]byte, 2048)); err != nil {
		t.Fatalf("native dial never sent its initial handshake: %v", err)
	}
	dialer.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || IsTransportUnavailable(err.Error()) || IsRetryable(err.Error()) {
			t.Fatalf("canceled handshake was misclassified: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native dial did not cancel promptly")
	}
	if unexpected.Load() {
		t.Fatal("pending handshake requested proof or platform verification")
	}
}
