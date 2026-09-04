package main

import (
	"context"
	"net/http"
	"sync"
)

// HTTP/1 CONNECT and h2c connections are hijacked, so Server.Shutdown alone
// doesn't wait for their handlers (and deferred usage accounting) to finish.
type drainingHandler struct {
	next     http.Handler
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	stopping bool
	requests sync.WaitGroup
}

func newDrainingHandler(next http.Handler) *drainingHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &drainingHandler{next: next, ctx: ctx, cancel: cancel}
}

func (h *drainingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	h.requests.Add(1)
	h.mu.Unlock()
	defer h.requests.Done()

	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(h.ctx, cancel)
	defer stop()
	defer cancel()
	h.next.ServeHTTP(w, r.WithContext(ctx))
}

func (h *drainingHandler) stop() {
	h.mu.Lock()
	h.stopping = true
	h.mu.Unlock()
	h.cancel()
}

func (h *drainingHandler) wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		h.requests.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type shutdownServer interface {
	Shutdown(context.Context) error
	Close() error
}

func shutdownServers(ctx context.Context, servers ...shutdownServer) {
	var pending sync.WaitGroup
	for _, server := range servers {
		pending.Go(func() {
			if err := server.Shutdown(ctx); err != nil {
				_ = server.Close()
			}
		})
	}
	pending.Wait()
}
