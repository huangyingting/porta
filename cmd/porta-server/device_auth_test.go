package main

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/gateway"
)

var registryTestDevices = struct {
	sync.Mutex
	keys map[string]*ecdsa.PrivateKey
}{keys: make(map[string]*ecdsa.PrivateKey)}

func testDeviceProof(name, token, method, path string) (deviceauth.Proof, error) {
	registryTestDevices.Lock()
	key := registryTestDevices.keys[name]
	if key == nil {
		var err error
		key, err = deviceauth.GenerateKey()
		if err != nil {
			registryTestDevices.Unlock()
			return deviceauth.Proof{}, err
		}
		registryTestDevices.keys[name] = key
	}
	registryTestDevices.Unlock()
	return deviceauth.NewProof(key, name, token, method, path, time.Now(), nil)
}

func testDeviceID(name string) string {
	registryTestDevices.Lock()
	defer registryTestDevices.Unlock()
	key := registryTestDevices.keys[name]
	if key == nil {
		return ""
	}
	id, _ := deviceauth.DeviceID(key.Public())
	return id
}

func authenticateTestDevice(r *clientRegistry, token, name string) (gateway.ClientIdentity, error) {
	proof, err := testDeviceProof(name, token, http.MethodPost, gateway.TunnelPath)
	if err != nil {
		return gateway.ClientIdentity{}, err
	}
	return authenticateDeviceProof(r, token, proof)
}

func authenticateDeviceProof(r *clientRegistry, token string, proof deviceauth.Proof) (gateway.ClientIdentity, error) {
	identity, _, release, err := r.AuthenticateDeviceSession(
		context.Background(),
		token,
		proof,
		http.MethodPost,
		gateway.TunnelPath,
	)
	if err != nil {
		return gateway.ClientIdentity{}, err
	}
	release()
	return identity, nil
}

func authenticateTestDeviceSession(r *clientRegistry, parent context.Context, token, name string) (gateway.ClientIdentity, context.Context, func(), error) {
	proof, err := testDeviceProof(name, token, http.MethodPost, gateway.TunnelPath)
	if err != nil {
		return gateway.ClientIdentity{}, nil, nil, err
	}
	return r.AuthenticateDeviceSession(parent, token, proof, http.MethodPost, gateway.TunnelPath)
}

func proofForRequest(t *testing.T, request *http.Request, name, token string) {
	t.Helper()
	proof, err := testDeviceProof(name, token, request.Method, request.URL.Path)
	if err != nil {
		t.Fatal(err)
	}
	deviceauth.Apply(request, proof)
}
