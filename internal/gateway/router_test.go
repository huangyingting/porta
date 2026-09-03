package gateway

import (
	"testing"
)

func TestSessionQueueDropsOldestPacketWithoutClosing(t *testing.T) {
	queue := make(chan []byte, 2)
	session := &Session{Outgoing: queue, outgoing: queue}
	session.enqueue([]byte{1})
	session.enqueue([]byte{2})
	session.enqueue([]byte{3})

	first := <-queue
	second := <-queue
	if first[0] != 2 || second[0] != 3 {
		t.Fatalf("queued packets = %v, %v; want newest packets 2 and 3", first, second)
	}
}
