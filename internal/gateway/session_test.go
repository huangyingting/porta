package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/protocol"
)

func TestSessionCancellationInterruptsBlockedStreamWrite(t *testing.T) {
	pool, err := NewPool("10.66.0.0/29")
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	handler, err := NewHandler(HandlerConfig{
		AuthorizeSession: func(parent context.Context, _ string, _ deviceauth.Proof, _, _ string) (ClientIdentity, context.Context, func(), error) {
			return ClientIdentity{AccountID: "account", LeaseID: "lease"}, parent, func() { close(released) }, nil
		},
		Pool: pool, Router: NewRouter(testPacketDevice{}, nil), MTU: 1100,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body, writer := io.Pipe()
	defer writer.Close()
	request := httptest.NewRequest(http.MethodPost, TunnelPath, body).WithContext(ctx)
	request.ProtoMajor = 2
	request.Header.Set("Authorization", "Bearer session-token-0123456789")
	request.Header.Set("Content-Type", protocol.ContentType)
	request.Header.Set(protocol.HeaderVersion, protocol.Version)
	request.Header.Set(laneSessionHeader, "session-test-12345678")
	request.Header.Set(laneIndexHeader, "0")
	request.Header.Set(laneCountHeader, "4")
	response := &blockedStreamWriter{
		header: make(http.Header), writing: make(chan struct{}), interrupted: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() { defer close(done); handler.ServeHTTP(response, request) }()
	select {
	case <-response.writing:
	case <-time.After(time.Second):
		t.Fatal("handler did not start writing")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock the response writer")
	}
	select {
	case <-released:
	default:
		t.Fatal("cancellation did not unregister the session")
	}
}

func TestSessionCancellationInterruptsInitialMasqueResponse(t *testing.T) {
	for _, test := range []struct {
		name   string
		proto  int
		header bool
	}{
		{"h2-header", 2, true},
		{"h3-header", 3, true},
		{"h2-flush", 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, err := NewPool("10.66.0.0/29")
			if err != nil {
				t.Fatal(err)
			}
			released := make(chan struct{})
			handler, err := NewHandler(HandlerConfig{
				AuthorizeSession: func(parent context.Context, _ string, _ deviceauth.Proof, _, _ string) (ClientIdentity, context.Context, func(), error) {
					return ClientIdentity{AccountID: "account", LeaseID: "lease"}, parent, func() { close(released) }, nil
				},
				Pool: pool, Router: NewRouter(testPacketDevice{}, nil), MTU: 1100,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body, writer := io.Pipe()
			defer writer.Close()
			request := httptest.NewRequest(http.MethodPost, MasquePath, body).WithContext(ctx)
			request.Method, request.ProtoMajor, request.Proto = http.MethodConnect, test.proto, connectIPProtocol
			request.Header.Set("Authorization", "Bearer session-token-0123456789")
			request.Header.Set(":protocol", connectIPProtocol)
			request.Header.Set("Capsule-Protocol", "?1")
			request.Header.Set(protocol.HeaderVersion, protocol.Version)
			blocked := &blockedStreamWriter{
				header: make(http.Header), writing: make(chan struct{}), interrupted: make(chan struct{}),
			}
			var response http.ResponseWriter = &blockedFlushWriter{blocked}
			if test.header {
				response = &blockedHeaderWriter{blocked}
			}
			done := make(chan struct{})
			go func() { defer close(done); handler.ServeHTTP(response, request) }()
			select {
			case <-blocked.writing:
			case <-time.After(time.Second):
				t.Fatal("MASQUE response did not start writing")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt initial MASQUE response I/O")
			}
			select {
			case <-released:
			default:
				t.Fatal("initial response cancellation did not unregister the session")
			}
		})
	}
}

type blockedHeaderWriter struct{ *blockedStreamWriter }

func (w *blockedHeaderWriter) WriteHeader(int) { _, _ = w.Write(nil) }

type blockedFlushWriter struct{ *blockedStreamWriter }

func (w *blockedFlushWriter) Flush() { _, _ = w.Write(nil) }

type blockedStreamWriter struct {
	header      http.Header
	writing     chan struct{}
	interrupted chan struct{}
	writeOnce   sync.Once
	closeOnce   sync.Once
}

func (w *blockedStreamWriter) Header() http.Header { return w.header }
func (*blockedStreamWriter) WriteHeader(int)       {}
func (w *blockedStreamWriter) Write([]byte) (int, error) {
	w.writeOnce.Do(func() { close(w.writing) })
	<-w.interrupted
	return 0, context.DeadlineExceeded
}
func (w *blockedStreamWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.After(time.Now()) {
		w.closeOnce.Do(func() { close(w.interrupted) })
	}
	return nil
}
