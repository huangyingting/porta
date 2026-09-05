package gateway

import (
	"testing"
	"time"
)

func BenchmarkPacketQueue(b *testing.B) {
	queue := newPacketQueue(defaultPacketQueueConfig, nil, 0)
	packet := testIPv4TCPData(1)
	now := time.Now()
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		if !queue.enqueue(packet, now) {
			b.Fatal("packet rejected")
		}
		if _, ok := queue.dequeue(now); !ok {
			b.Fatal("packet unavailable")
		}
	}
}
