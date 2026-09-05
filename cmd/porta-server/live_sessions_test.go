package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/huangyingting/porta/internal/usage"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const sessionTestToken = "session-token-0123456789012345"

func TestRegistryRevocationsCancelAndDrainSessions(t *testing.T) {
	for _, action := range []string{"disable", "delete", "rotate", "forget", "disconnect"} {
		t.Run(action, func(t *testing.T) {
			registry := sessionTestRegistry(t)
			var identity gateway.ClientIdentity
			var contexts []context.Context
			var releases []func()
			for range 4 {
				id, ctx, release, err := authenticateTestDeviceSession(registry, context.Background(), sessionTestToken, "phone")
				if err != nil {
					t.Fatal(err)
				}
				identity = id
				contexts, releases = append(contexts, ctx), append(releases, release)
			}
			_, otherCtx, releaseOther, err := authenticateTestDeviceSession(registry, context.Background(), sessionTestToken, "laptop")
			if err != nil {
				t.Fatal(err)
			}
			defer releaseOther()
			drained := make(chan struct{})
			for index, ctx := range contexts {
				go func() {
					<-ctx.Done()
					<-drained
					// A registry read during draining must not deadlock.
					_ = registry.List()
					releases[index]()
				}()
			}
			if action != "forget" {
				go func() {
					<-otherCtx.Done()
					<-drained
					releaseOther()
				}()
			}
			mutated := make(chan error, 1)
			go func() { mutated <- revokeTestSession(registry, identity.AccountID, action) }()
			for _, ctx := range contexts {
				waitSessionDone(t, ctx.Done())
			}
			select {
			case err := <-mutated:
				t.Fatalf("mutation returned before usage/workers drained: %v", err)
			default:
			}
			if action == "forget" && otherCtx.Err() != nil {
				t.Fatal("forget canceled another device")
			}
			if action == "forget" {
				if _, err := authenticateTestDevice(registry, sessionTestToken, "phone"); !errors.Is(err, errDeviceDraining) {
					t.Fatalf("device re-enrolled before old usage drained: %v", err)
				}
			}
			close(drained)
			select {
			case err := <-mutated:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("revocation failed to drain")
			}
			_, err = authenticateTestDevice(registry, sessionTestToken, "phone")
			wantRejected := action == "disable" || action == "delete" || action == "rotate"
			if (err != nil) != wantRejected {
				t.Fatalf("subsequent authentication error = %v", err)
			}
		})
	}
}

func TestRegistryAuthenticationRevocationRace(t *testing.T) {
	for range 20 {
		registry := sessionTestRegistry(t)
		id, err := authenticateTestDevice(registry, sessionTestToken, "phone")
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var workers sync.WaitGroup
		for range 12 {
			workers.Go(func() {
				<-start
				_, ctx, release, err := authenticateTestDeviceSession(registry, context.Background(), sessionTestToken, "phone")
				if err != nil {
					return
				}
				defer release()
				select {
				case <-ctx.Done():
				case <-time.After(3 * time.Second):
					t.Error("session escaped concurrent token rotation")
				}
			})
		}
		close(start)
		if _, err := registry.RotateToken(id.AccountID); err != nil {
			t.Fatal(err)
		}
		workers.Wait()
	}
}

func TestFailedRegistryMutationDoesNotCancelSessions(t *testing.T) {
	registry := sessionTestRegistry(t)
	id, ctx, release, err := authenticateTestDeviceSession(registry, context.Background(), sessionTestToken, "phone")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	registry.path = filepath.Join(registry.path, "not-a-directory")
	if _, err := registry.Update(id.AccountID, "test", 5, false); err == nil {
		t.Fatal("persistence failure was accepted")
	}
	if ctx.Err() != nil {
		t.Fatal("failed mutation revoked a valid session")
	}
	if _, err := authenticateTestDevice(registry, sessionTestToken, "phone"); err != nil {
		t.Fatalf("failed mutation did not restore account: %v", err)
	}
}

func TestLiveVPNRevocation(t *testing.T) {
	for _, transport := range []string{"h2-stream", "h3-stream", "h2-masque", "h3-masque"} {
		for _, action := range []string{"disable", "delete", "rotate", "forget", "disconnect"} {
			t.Run(transport+"/"+action, func(t *testing.T) {
				if transport == "h2-masque" && !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
					t.Skip("HTTP/2 Extended CONNECT requires GODEBUG=http2xconnect=1")
				}
				registry := sessionTestRegistry(t)
				pool, err := gateway.NewPool("10.66.0.0/29")
				if err != nil {
					t.Fatal(err)
				}
				store, _ := usage.Open("", nil)
				handler, err := gateway.NewHandler(gateway.HandlerConfig{
					AuthorizeSession: registry.AuthenticateDeviceSession, Pool: pool,
					Router: gateway.NewRouter(sessionTestDevice{}, nil), MTU: 1100,
					Usage: store, EnableH3Datagrams: true,
					Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
				})
				if err != nil {
					t.Fatal(err)
				}
				serverURL, client := sessionTestServer(t, handler, strings.HasPrefix(transport, "h3"))
				id, err := authenticateTestDevice(registry, sessionTestToken, "phone")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var errorsFromReaders []<-chan error
				if strings.HasSuffix(transport, "stream") {
					for lane := range 4 {
						reader, writer := io.Pipe()
						defer writer.Close()
						request, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+gateway.TunnelPath, reader)
						if err != nil {
							t.Fatal(err)
						}
						request.Header.Set("Authorization", "Bearer "+sessionTestToken)
						request.Header.Set("Content-Type", protocol.ContentType)
						request.Header.Set(protocol.HeaderVersion, protocol.Version)
						request.Header.Set("X-Porta-Lane-Session", "test-session-12345678")
						request.Header.Set("X-Porta-Lane", fmt.Sprint(lane))
						request.Header.Set("X-Porta-Lanes", "4")
						proofForRequest(t, request, "phone", sessionTestToken)
						response, err := client.Do(request)
						if err != nil {
							t.Fatal(err)
						}
						defer response.Body.Close()
						if response.StatusCode != http.StatusOK {
							t.Fatalf("lane response = %d", response.StatusCode)
						}
						done := make(chan error, 1)
						go func() {
							_, err := io.Copy(io.Discard, response.Body)
							done <- err
						}()
						errorsFromReaders = append(errorsFromReaders, done)
					}
				} else {
					proto := tunnel.TransportHTTP2
					if strings.HasPrefix(transport, "h3") {
						proto = tunnel.TransportHTTP3
					}
					connection, err := tunnel.Dial(ctx, tunnel.Config{
						URL: serverURL, Token: sessionTestToken, Transport: proto,
						TLSConfig: &tls.Config{InsecureSkipVerify: true}, Timeout: time.Second,
						DeviceProof: func(method, path string) (deviceauth.Proof, error) {
							return testDeviceProof("phone", sessionTestToken, method, path)
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					defer connection.Close()
					done := make(chan error, 1)
					go func() {
						_, err := connection.Receive()
						done <- err
					}()
					errorsFromReaders = append(errorsFromReaders, done)
				}
				mutated := make(chan error, 1)
				go func() { mutated <- revokeTestSession(registry, id.AccountID, action) }()
				select {
				case err := <-mutated:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("live session revocation failed to interrupt transport")
				}
				for _, done := range errorsFromReaders {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("client did not observe revocation")
					}
				}
				if active := store.Snapshot().Clients[id.AccountID].ActiveSessions; active != 0 {
					t.Fatalf("usage still has %d active sessions after revocation", active)
				}
			})
		}
	}
}

func TestAdminDisconnectPreservesToken(t *testing.T) {
	registry := sessionTestRegistry(t)
	id, ctx, release, err := authenticateTestDeviceSession(registry, context.Background(), sessionTestToken, "phone")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	go func() { <-ctx.Done(); release() }()
	handler := adminHandler(http.NotFoundHandler(), registry, testAdminToken)
	response := adminRequest(t, handler, http.MethodPost, "/api/clients/"+id.AccountID+"/devices/"+testDeviceID("phone")+"/disconnect", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"disconnected_sessions":1`) {
		t.Fatalf("disconnect response = %d: %s", response.Code, response.Body.String())
	}
	if _, err := authenticateTestDevice(registry, sessionTestToken, "phone"); err != nil {
		t.Fatalf("disconnect revoked token: %v", err)
	}
}

func sessionTestRegistry(t *testing.T) *clientRegistry {
	t.Helper()
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), sessionTestToken)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func revokeTestSession(registry *clientRegistry, accountID, action string) error {
	switch action {
	case "disable":
		_, err := registry.Update(accountID, "test", 5, false)
		return err
	case "delete":
		return registry.Delete(accountID)
	case "rotate":
		_, err := registry.RotateToken(accountID)
		return err
	case "forget":
		return registry.DeleteDevice(accountID, testDeviceID("phone"))
	case "disconnect":
		_, err := registry.Disconnect(accountID, "")
		return err
	default:
		return errors.New("unknown test action")
	}
}

func waitSessionDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("session was not canceled")
	}
}

type sessionTestDevice struct{}

func (sessionTestDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (sessionTestDevice) WritePacket(ctx context.Context, _ []byte) error { return ctx.Err() }
func (sessionTestDevice) Name() string                                    { return "fake0" }
func (sessionTestDevice) Close() error                                    { return nil }

func sessionTestServer(t *testing.T, handler http.Handler, h3 bool) (string, *http.Client) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	if err := http2.ConfigureServer(server.Config, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	if !h3 {
		return server.URL, server.Client()
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	quicServer := &http3.Server{Handler: handler, TLSConfig: server.TLS, EnableDatagrams: true}
	go func() { _ = quicServer.Serve(packetConn) }()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, EnableDatagrams: true}
	t.Cleanup(func() { _ = transport.Close(); _ = quicServer.Close(); _ = packetConn.Close() })
	return "https://" + packetConn.LocalAddr().String(), &http.Client{Transport: transport}
}
