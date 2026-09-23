package tunnel

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestMasqueTerminalErrorSurvivesFullQueuesAndEveryReceive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &masqueClient{
		ctx: ctx, cancel: cancel, errors: make(chan error, 1), packets: make(chan []byte, 1),
		lease: Lease{Address: netip.MustParsePrefix("10.66.0.2/32"), MTU: 1400},
	}
	client.errors <- io.EOF
	client.packets <- []byte{1}
	failure := PermanentError{Err: errors.New("terminal protocol failure")}
	client.report(failure)
	client.report(io.ErrClosedPipe)
	for range 3 {
		if _, err := client.receive(); !errors.Is(err, failure) {
			t.Fatalf("terminal error lost behind packets/cancellation: %v", err)
		}
	}
	if err := client.send(nil); !errors.Is(err, failure) {
		t.Fatalf("send ignored terminal failure: %v", err)
	}
}

func TestHTTP2TerminalErrorWinsOverQueuedPackets(t *testing.T) {
	group := newHTTP2RoutingTestGroup()
	for _, lane := range group.lanes {
		lane.downstream <- []byte{1}
	}
	failure := PermanentError{Err: errors.New("terminal lane failure")}
	group.fail(failure)
	if _, err := group.receive(); !errors.Is(err, failure) {
		t.Fatalf("terminal lane failure hidden by queued data: %v", err)
	}
	_ = group.close()
}

func TestEveryMasqueCloseWaitsForReadersAndReturnsSameFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &masqueClient{ctx: ctx, cancel: cancel, closeTransport: func() error { return io.ErrClosedPipe }}
	release := make(chan struct{})
	client.workers.Go(func() { <-release })
	var callers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		callers.Go(func() { results <- client.close() })
	}
	select {
	case <-results:
		t.Fatal("Close returned before readers drained")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	callers.Wait()
	for range 2 {
		if err := <-results; !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Close result lost: %v", err)
		}
	}
}
