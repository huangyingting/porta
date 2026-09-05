package deviceauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderPublicKey = "X-Porta-Device-Key"
	HeaderName      = "X-Porta-Device-Name"
	HeaderTimestamp = "X-Porta-Device-Time"
	HeaderNonce     = "X-Porta-Device-Nonce"
	HeaderSignature = "X-Porta-Device-Signature"

	MaxClockSkew = 5 * time.Minute
	domain       = "porta/device-auth/v1"
)

var (
	deviceIDPattern   = regexp.MustCompile(`^d-[A-Za-z0-9_-]{22}$`)
	deviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Proof struct {
	DeviceID  string
	Name      string
	PublicKey string
	Timestamp string
	Nonce     string
	Signature string
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	return key, nil
}

func DeviceID(publicKey crypto.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("encode device public key: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "d-" + base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

func DeviceIDFromEncoded(encoded []byte) (string, error) {
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return "", errors.New("device public key is invalid")
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return "", errors.New("device public key must use ECDSA P-256")
	}
	return DeviceID(publicKey)
}

func NewProof(signer crypto.Signer, name, token, method, path string, now time.Time, random io.Reader) (Proof, error) {
	if signer == nil {
		return Proof{}, errors.New("device signer is required")
	}
	if !deviceNamePattern.MatchString(name) {
		return Proof{}, errors.New("device name is invalid")
	}
	if random == nil {
		random = rand.Reader
	}
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(random, nonceBytes); err != nil {
		return Proof{}, fmt.Errorf("generate device proof nonce: %w", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return Proof{}, fmt.Errorf("encode device public key: %w", err)
	}
	deviceID, err := DeviceID(signer.Public())
	if err != nil {
		return Proof{}, err
	}
	proof := Proof{
		DeviceID:  deviceID,
		Name:      name,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Timestamp: strconv.FormatInt(now.UTC().Unix(), 10),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	digest := sha256.Sum256(Message(proof, token, method, path))
	signature, err := signer.Sign(random, digest[:], crypto.SHA256)
	if err != nil {
		return Proof{}, fmt.Errorf("sign device proof: %w", err)
	}
	proof.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return proof, nil
}

func Verify(proof Proof, token, method, path string, now time.Time) ([]byte, time.Time, error) {
	if !deviceIDPattern.MatchString(proof.DeviceID) {
		return nil, time.Time{}, errors.New("device ID is invalid")
	}
	if !deviceNamePattern.MatchString(proof.Name) {
		return nil, time.Time{}, errors.New("device name is invalid")
	}
	encodedKey, err := base64.RawURLEncoding.DecodeString(proof.PublicKey)
	if err != nil || len(encodedKey) == 0 || len(encodedKey) > 512 {
		return nil, time.Time{}, errors.New("device public key is invalid")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(encodedKey)
	if err != nil {
		return nil, time.Time{}, errors.New("device public key is invalid")
	}
	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, time.Time{}, errors.New("device public key must use ECDSA P-256")
	}
	derivedID, err := DeviceID(publicKey)
	if err != nil || derivedID != proof.DeviceID {
		return nil, time.Time{}, errors.New("device ID does not match its public key")
	}
	seconds, err := strconv.ParseInt(proof.Timestamp, 10, 64)
	if err != nil {
		return nil, time.Time{}, errors.New("device proof timestamp is invalid")
	}
	signedAt := time.Unix(seconds, 0).UTC()
	if signedAt.Before(now.Add(-MaxClockSkew)) || signedAt.After(now.Add(MaxClockSkew)) {
		return nil, time.Time{}, errors.New("device proof timestamp is outside the allowed window")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(proof.Nonce)
	if err != nil || len(nonce) != 16 {
		return nil, time.Time{}, errors.New("device proof nonce is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(proof.Signature)
	if err != nil || len(signature) == 0 || len(signature) > 128 {
		return nil, time.Time{}, errors.New("device proof signature is invalid")
	}
	digest := sha256.Sum256(Message(proof, token, method, path))
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return nil, time.Time{}, errors.New("device proof signature is invalid")
	}
	return encodedKey, signedAt, nil
}

func FromRequest(request *http.Request) Proof {
	return Proof{
		DeviceID:  request.Header.Get("X-Porta-Client-ID"),
		Name:      request.Header.Get(HeaderName),
		PublicKey: request.Header.Get(HeaderPublicKey),
		Timestamp: request.Header.Get(HeaderTimestamp),
		Nonce:     request.Header.Get(HeaderNonce),
		Signature: request.Header.Get(HeaderSignature),
	}
}

func Apply(request *http.Request, proof Proof) {
	request.Header.Set("X-Porta-Client-ID", proof.DeviceID)
	request.Header.Set(HeaderName, proof.Name)
	request.Header.Set(HeaderPublicKey, proof.PublicKey)
	request.Header.Set(HeaderTimestamp, proof.Timestamp)
	request.Header.Set(HeaderNonce, proof.Nonce)
	request.Header.Set(HeaderSignature, proof.Signature)
}

func Message(proof Proof, token, method, path string) []byte {
	tokenHash := sha256.Sum256([]byte(token))
	canonical := strings.Join([]string{
		domain,
		strings.ToUpper(method),
		path,
		proof.DeviceID,
		proof.Name,
		proof.Timestamp,
		proof.Nonce,
		base64.RawURLEncoding.EncodeToString(tokenHash[:]),
	}, "\n")
	return []byte(canonical)
}
