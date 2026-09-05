package forwardproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlushWriterBatchesUntilThreshold(t *testing.T) {
	response := &recordingResponseWriter{}
	writer := newFlushWriter(response, 8, time.Hour)
	defer writer.Close()
	if _, err := writer.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if response.size() != 0 {
		t.Fatal("small write flushed before threshold")
	}
	if _, err := writer.Write([]byte("5678")); err != nil {
		t.Fatal(err)
	}
	if got := response.string(); got != "12345678" {
		t.Fatalf("flushed body = %q", got)
	}
	if response.flushes.Load() != 1 {
		t.Fatalf("flushes = %d, want 1", response.flushes.Load())
	}
}

func TestFlushWriterFlushesInteractiveWriteOnTimer(t *testing.T) {
	response := &recordingResponseWriter{}
	writer := newFlushWriter(response, 128, time.Millisecond)
	defer writer.Close()
	if _, err := writer.Write([]byte("interactive")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for response.size() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := response.string(); got != "interactive" {
		t.Fatalf("timer-flushed body = %q", got)
	}
}

func TestCopyTunnelStreamFlushesFinalBufferedBytes(t *testing.T) {
	response := &recordingResponseWriter{}
	writer := newFlushWriter(response, 128, time.Hour)
	defer writer.Close()
	if err := copyTunnelStream(writer, bytes.NewBufferString("final")); err != nil {
		t.Fatal(err)
	}
	if got := response.string(); got != "final" {
		t.Fatalf("final body = %q", got)
	}
}

func TestFlushWriterTimerFailureTerminatesTunnel(t *testing.T) {
	upstream, peer := net.Pipe()
	defer peer.Close()
	body, bodyWriter := io.Pipe()
	defer bodyWriter.Close()
	response := &failingFlushResponseWriter{err: errors.New("flush failed")}
	writer := newFlushWriter(response, 128, time.Millisecond)
	failed := make(chan error, 1)
	writer.onFailure = func(err error) {
		failed <- err
		closeTunnelEndpoints(upstream, body, writer)
	}
	done := make(chan struct{})
	go func() {
		copyStreamTunnel(context.Background(), upstream, body, writer)
		close(done)
	}()
	if _, err := peer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failed:
		if !errors.Is(err, response.err) {
			t.Fatalf("flush error = %v, want %v", err, response.err)
		}
	case <-time.After(time.Second):
		t.Fatal("timer flush failure was not reported")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timer flush failure left the tunnel running")
	}
}

func BenchmarkFlushWriterBufferedWrites(b *testing.B) {
	response := &discardResponseWriter{}
	writer := newFlushWriter(response, responseBufferSize, 0)
	defer writer.Close()
	payload := make([]byte, 4096)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := writer.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := writer.Flush(); err != nil {
		b.Fatal(err)
	}
}

type recordingResponseWriter struct {
	mu      sync.Mutex
	header  http.Header
	body    bytes.Buffer
	flushes atomic.Int32
}

func (w *recordingResponseWriter) Header() http.Header {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *recordingResponseWriter) WriteHeader(int) {}

func (w *recordingResponseWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(data)
}

func (w *recordingResponseWriter) Flush() {
	w.flushes.Add(1)
}

func (w *recordingResponseWriter) SetWriteDeadline(time.Time) error { return nil }

func (w *recordingResponseWriter) size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Len()
}

func (w *recordingResponseWriter) string() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.String()
}

type discardResponseWriter struct{}

func (*discardResponseWriter) Header() http.Header              { return make(http.Header) }
func (*discardResponseWriter) WriteHeader(int)                  {}
func (*discardResponseWriter) Write(data []byte) (int, error)   { return len(data), nil }
func (*discardResponseWriter) Flush()                           {}
func (*discardResponseWriter) SetWriteDeadline(time.Time) error { return nil }

type failingFlushResponseWriter struct {
	err error
}

func (*failingFlushResponseWriter) Header() http.Header            { return make(http.Header) }
func (*failingFlushResponseWriter) WriteHeader(int)                {}
func (*failingFlushResponseWriter) Write(data []byte) (int, error) { return len(data), nil }
func (w *failingFlushResponseWriter) FlushError() error            { return w.err }
func (*failingFlushResponseWriter) SetWriteDeadline(time.Time) error {
	return nil
}
