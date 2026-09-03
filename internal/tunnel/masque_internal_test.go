package tunnel

import (
	"context"
	"testing"
	"time"
)

func TestMasqueDeliveryBackpressuresInsteadOfDisconnecting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &masqueClient{
		ctx:     ctx,
		packets: make(chan []byte, 1),
		errors:  make(chan error, 1),
	}
	client.deliver([]byte{1})

	delivered := make(chan struct{})
	go func() {
		client.deliver([]byte{2})
		close(delivered)
	}()

	select {
	case <-delivered:
		t.Fatal("delivery did not apply backpressure when the queue was full")
	case err := <-client.errors:
		t.Fatalf("full receive queue reported a fatal error: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	<-client.packets
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("delivery did not resume after receive capacity became available")
	}
}
