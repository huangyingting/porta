package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/usage"
)

func TestDrainWaitsForHijackedHandlerAccounting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.json")
	store, err := usage.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	handler := newDrainingHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		session := store.Begin("", "account", "phone", "", "", "")
		defer session.Close()
		close(started)
		<-r.Context().Done()
		<-release
		session.AddUploaded(42, 1)
	}))
	server := httptest.NewServer(handler)
	defer server.Close()
	defer handler.stop()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, _ := server.Client().Get(server.URL)
		if response != nil {
			_ = response.Body.Close()
		}
	}()
	<-started
	handler.stop()
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handler.wait(expired); err == nil {
		t.Error("drain completed before deferred accounting")
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.wait(ctx); err != nil {
		t.Fatal(err)
	}
	<-clientDone
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	reopened, err := usage.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := usage.Device(reopened.Snapshot(), "account", "phone")
	if got.ActiveSessions != 0 || got.BytesUploaded != 42 || got.ConnectionsTotal != 1 {
		t.Fatalf("final accounting = %#v", got)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("new request during shutdown = %d", response.Code)
	}
}

func TestShutdownServersStartsConcurrentlyAndForcesClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := &blockingShutdownServer{started: make(chan struct{})}
	second := &blockingShutdownServer{started: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		shutdownServers(ctx, first, second)
		close(done)
	}()
	for _, server := range []*blockingShutdownServer{first, second} {
		select {
		case <-server.started:
		case <-time.After(time.Second):
			t.Fatal("listeners were shut down serially")
		}
	}
	cancel()
	<-done
	if !first.closed.Load() || !second.closed.Load() {
		t.Fatal("expired shutdown did not force close active connections")
	}
}

type blockingShutdownServer struct {
	started chan struct{}
	closed  atomic.Bool
}

func (s *blockingShutdownServer) Shutdown(ctx context.Context) error {
	close(s.started)
	<-ctx.Done()
	return ctx.Err()
}

func (s *blockingShutdownServer) Close() error {
	s.closed.Store(true)
	return nil
}
