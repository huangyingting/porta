package deviceauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProofRoundTripAndHeaders(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	proof, err := NewProof(key, "Office-PC", "account-token", http.MethodConnect, "/tunnel", now, bytes.NewReader(make([]byte, 256)))
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodConnect, "https://gateway.example/tunnel", nil)
	Apply(request, proof)
	if got := FromRequest(request); got != proof {
		t.Fatalf("header proof = %#v, want %#v", got, proof)
	}
	encoded, signedAt, err := Verify(proof, "account-token", http.MethodConnect, "/tunnel", now)
	if err != nil || !signedAt.Equal(now) {
		t.Fatalf("verify = %v, %v", signedAt, err)
	}
	want, _ := x509.MarshalPKIXPublicKey(key.Public())
	if !bytes.Equal(encoded, want) {
		t.Fatal("verified public key changed")
	}
	if len(proof.DeviceID) != 24 || !strings.HasPrefix(proof.DeviceID, "d-") {
		t.Fatalf("device ID = %q", proof.DeviceID)
	}
}

func TestProofBindsEverySecurityField(t *testing.T) {
	key, _ := GenerateKey()
	now := time.Unix(1_800_000_000, 0)
	proof, _ := NewProof(key, "Office-PC", "account-token", http.MethodPost, "/v1/tunnel", now, rand.Reader)
	tests := []struct {
		name   string
		proof  Proof
		token  string
		method string
		path   string
	}{
		{"token", proof, "other-token", http.MethodPost, "/v1/tunnel"},
		{"method", proof, "account-token", http.MethodConnect, "/v1/tunnel"},
		{"path", proof, "account-token", http.MethodPost, "/other"},
		{"name", withProof(proof, func(value *Proof) { value.Name = "Home-PC" }), "account-token", http.MethodPost, "/v1/tunnel"},
		{"timestamp", withProof(proof, func(value *Proof) { value.Timestamp = "1800000001" }), "account-token", http.MethodPost, "/v1/tunnel"},
		{"nonce", withProof(proof, func(value *Proof) { value.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, 16)) }), "account-token", http.MethodPost, "/v1/tunnel"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := Verify(test.proof, test.token, test.method, test.path, now); err == nil {
				t.Fatal("modified proof verified")
			}
		})
	}
}

func TestProofRejectsWrongKeyAndStaleOrMalformedInput(t *testing.T) {
	key, _ := GenerateKey()
	now := time.Unix(1_800_000_000, 0)
	proof, _ := NewProof(key, "Office-PC", "account-token", http.MethodPost, "/v1/tunnel", now, rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := x509.MarshalPKIXPublicKey(other.Public())
	tests := []Proof{
		withProof(proof, func(value *Proof) { value.DeviceID = "d-AAAAAAAAAAAAAAAAAAAAAA" }),
		withProof(proof, func(value *Proof) { value.Name = "invalid name" }),
		withProof(proof, func(value *Proof) { value.PublicKey = base64.RawURLEncoding.EncodeToString(otherKey) }),
		withProof(proof, func(value *Proof) { value.Nonce = "bad" }),
		withProof(proof, func(value *Proof) { value.Signature = "bad" }),
	}
	for _, test := range tests {
		if _, _, err := Verify(test, "account-token", http.MethodPost, "/v1/tunnel", now); err == nil {
			t.Fatalf("malformed proof verified: %#v", test)
		}
	}
	for _, verificationTime := range []time.Time{
		now.Add(MaxClockSkew + time.Second),
		now.Add(-MaxClockSkew - time.Second),
	} {
		if _, _, err := Verify(proof, "account-token", http.MethodPost, "/v1/tunnel", verificationTime); err == nil {
			t.Fatalf("out-of-window proof verified at %v", verificationTime)
		}
	}
}

func withProof(proof Proof, change func(*Proof)) Proof {
	change(&proof)
	return proof
}
