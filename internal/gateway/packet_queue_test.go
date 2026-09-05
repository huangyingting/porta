package gateway

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestPacketQueueEvictsOldestDatagramAtomically(t *testing.T) {
	metrics := &Metrics{}
	config := defaultPacketQueueConfig
	config.maxPackets = 2
	config.maxBytes = 4096
	queue := newPacketQueue(config, metrics, 0)
	now := time.Now()
	for marker := byte(1); marker <= 3; marker++ {
		packet := testIPv4UDP()
		packet[4] = marker
		if !queue.enqueue(packet, now) {
			t.Fatalf("packet %d rejected", marker)
		}
	}
	first, _ := queue.dequeue(now)
	second, _ := queue.dequeue(now)
	if first[4] != 2 || second[4] != 3 {
		t.Fatalf("queue retained markers %d and %d", first[4], second[4])
	}
	if metrics.queueOldestDrops.Load() != 1 {
		t.Fatalf("oldest drops = %d", metrics.queueOldestDrops.Load())
	}
}

func TestPacketQueueTailDropsTCPToPreserveQueuedPrefix(t *testing.T) {
	metrics := &Metrics{}
	config := defaultPacketQueueConfig
	config.maxPackets = 2
	config.maxBytes = 4096
	queue := newPacketQueue(config, metrics, 0)
	now := time.Now()
	for marker := byte(1); marker <= 2; marker++ {
		packet := testIPv4TCPData(marker)
		if !queue.enqueue(packet, now) {
			t.Fatalf("packet %d rejected", marker)
		}
	}
	if queue.enqueue(testIPv4TCPData(3), now) {
		t.Fatal("new TCP packet was accepted into a full queue")
	}
	first, _ := queue.dequeue(now)
	second, _ := queue.dequeue(now)
	if first[4] != 1 || second[4] != 2 {
		t.Fatalf("TCP prefix changed to markers %d and %d", first[4], second[4])
	}
	if metrics.queueTailDrops.Load() != 1 {
		t.Fatalf("tail drops = %d", metrics.queueTailDrops.Load())
	}
}

func TestPacketQueueDoesNotEvictControlForTCP(t *testing.T) {
	metrics := &Metrics{}
	config := defaultPacketQueueConfig
	config.maxPackets = 1
	queue := newPacketQueue(config, metrics, 0)
	now := time.Now()
	control := testIPv4UDP()
	if !queue.enqueue(control, now) {
		t.Fatal("control packet rejected")
	}
	if queue.enqueue(testIPv4TCPData(1), now) {
		t.Fatal("TCP packet unexpectedly displaced queued control traffic")
	}
	got, ok := queue.dequeue(now)
	if !ok || !bytes.Equal(got, control) {
		t.Fatal("queued control packet was not preserved")
	}
	if metrics.queueTailDrops.Load() != 1 {
		t.Fatalf("tail drops = %d, want 1", metrics.queueTailDrops.Load())
	}
}

func TestPacketQueueEvictsDatagramForTCP(t *testing.T) {
	metrics := &Metrics{}
	config := defaultPacketQueueConfig
	config.maxPackets = 1
	queue := newPacketQueue(config, metrics, 0)
	now := time.Now()
	datagram := append(testIPv4UDP(), make([]byte, 300)...)
	binary.BigEndian.PutUint16(datagram[2:4], uint16(len(datagram)))
	if !queue.enqueue(datagram, now) {
		t.Fatal("datagram rejected")
	}
	tcp := testIPv4TCPData(1)
	if !queue.enqueue(tcp, now) {
		t.Fatal("TCP packet did not displace queued datagram")
	}
	got, ok := queue.dequeue(now)
	if !ok || !bytes.Equal(got, tcp) {
		t.Fatal("TCP packet was not retained")
	}
	if metrics.queueOldestDrops.Load() != 1 {
		t.Fatalf("oldest drops = %d, want 1", metrics.queueOldestDrops.Load())
	}
}

func TestPacketQueueDropsExpiredPacketsByClass(t *testing.T) {
	metrics := &Metrics{}
	config := defaultPacketQueueConfig
	config.udpMaxAge = 10 * time.Millisecond
	config.controlAge = 10 * time.Millisecond
	queue := newPacketQueue(config, metrics, 0)
	now := time.Now()
	if !queue.enqueue(testIPv4UDP(), now) {
		t.Fatal("packet rejected")
	}
	if packet, ok := queue.dequeue(now.Add(11 * time.Millisecond)); ok || packet != nil {
		t.Fatal("expired packet was delivered")
	}
	if metrics.queueExpiredDrops.Load() != 1 {
		t.Fatalf("expired drops = %d", metrics.queueExpiredDrops.Load())
	}
}

func TestPacketQueueTracksByteHighWater(t *testing.T) {
	metrics := &Metrics{}
	queue := newPacketQueue(defaultPacketQueueConfig, metrics, 0)
	now := time.Now()
	packet := testIPv4TCPData(1)
	queue.enqueue(packet, now)
	queue.enqueue(packet, now)
	if got := metrics.queueBytesHighWater[0].Load(); got != uint64(2*len(packet)) {
		t.Fatalf("byte high water = %d", got)
	}
}

func TestPacketQueueTracksCurrentBytesPerLaneAndClose(t *testing.T) {
	metrics := &Metrics{}
	first := newPacketQueue(defaultPacketQueueConfig, metrics, 1)
	second := newPacketQueue(defaultPacketQueueConfig, metrics, 1)
	packet := testIPv4TCPData(1)
	now := time.Now()

	if !first.enqueue(packet, now) || !second.enqueue(packet, now) {
		t.Fatal("enqueue failed")
	}
	if got := metrics.queueBytesCurrent[1].Load(); got != int64(2*len(packet)) {
		t.Fatalf("current lane bytes = %d, want %d", got, 2*len(packet))
	}
	first.close()
	if got := metrics.queueBytesCurrent[1].Load(); got != int64(len(packet)) {
		t.Fatalf("current lane bytes after first close = %d, want %d", got, len(packet))
	}
	second.close()
	if got := metrics.queueBytesCurrent[1].Load(); got != 0 {
		t.Fatalf("current lane bytes after both closes = %d, want 0", got)
	}
}

func TestMasquePacketQueuePreservesDropOldestWithoutExpiry(t *testing.T) {
	metrics := &Metrics{}
	config := masquePacketQueueConfig
	config.maxPackets = 2
	queue := newPacketQueue(config, metrics, -1)
	now := time.Now()
	for marker := byte(1); marker <= 3; marker++ {
		packet := testIPv4TCPData(marker)
		if !queue.enqueue(packet, now) {
			t.Fatalf("packet %d rejected", marker)
		}
	}
	first, _ := queue.dequeue(now.Add(time.Hour))
	second, _ := queue.dequeue(now.Add(time.Hour))
	if first[4] != 2 || second[4] != 3 {
		t.Fatalf("MASQUE queue retained markers %d and %d", first[4], second[4])
	}
	if metrics.queueOldestDrops.Load() != 1 {
		t.Fatalf("oldest drops = %d, want 1", metrics.queueOldestDrops.Load())
	}
	for lane := range metrics.queueBytesCurrent {
		if got := metrics.queueBytesCurrent[lane].Load(); got != 0 {
			t.Fatalf("MASQUE traffic polluted lane %d metric with %d bytes", lane, got)
		}
	}
}

func testIPv4TCPData(marker byte) []byte {
	packet := make([]byte, 80)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[4] = marker
	packet[9] = 6
	copy(packet[12:16], []byte{10, 66, 0, 2})
	copy(packet[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 443)
	packet[32] = 5 << 4
	packet[33] = 0x18
	return packet
}
