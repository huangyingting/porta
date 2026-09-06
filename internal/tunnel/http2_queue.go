package tunnel

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
)

const (
	defaultHTTP2QueuePackets = 96
	defaultHTTP2QueueBytes   = 128 << 10
)

type http2QueueConfig struct {
	maxPackets int
	maxBytes   int
	tcpMaxAge  time.Duration
	udpMaxAge  time.Duration
	controlAge time.Duration
}

var defaultHTTP2QueueConfig = http2QueueConfig{
	maxPackets: defaultHTTP2QueuePackets,
	maxBytes:   defaultHTTP2QueueBytes,
	tcpMaxAge:  500 * time.Millisecond,
	udpMaxAge:  150 * time.Millisecond,
	controlAge: 250 * time.Millisecond,
}

type http2QueueStats struct {
	oldestDrops  atomic.Uint64
	fullDrops    atomic.Uint64
	tailDrops    atomic.Uint64
	expiredDrops atomic.Uint64
	currentBytes atomic.Int64
	highWater    atomic.Uint64
}

type http2QueuedPacket struct {
	data     []byte
	class    protocol.PacketClass
	enqueued time.Time
}

type http2UploadQueue struct {
	mu     sync.Mutex
	items  []http2QueuedPacket
	head   int
	bytes  int
	ready  chan struct{}
	config http2QueueConfig
	stats  http2QueueStats
	closed bool
	active bool
}

func newHTTP2UploadQueue(config http2QueueConfig) *http2UploadQueue {
	return &http2UploadQueue{
		items:  make([]http2QueuedPacket, 0, config.maxPackets),
		ready:  make(chan struct{}, 1),
		config: config,
		active: true,
	}
}

func (q *http2UploadQueue) activate() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.active = true
	}
}

func (q *http2UploadQueue) deactivateAndClear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.active = false
	q.clearLocked()
}

func (q *http2UploadQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	q.active = false
	q.clearLocked()
	q.signalLocked()
}

func (q *http2UploadQueue) enqueue(packet []byte, metadata protocol.PacketMetadata, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || !q.active {
		return false
	}
	q.dropExpiredLocked(now)
	if len(packet) > q.config.maxBytes || q.config.maxPackets <= 0 {
		q.recordRejectedLocked(metadata.Class)
		return false
	}
	if q.fitsLocked(len(packet)) {
		q.appendLocked(http2QueuedPacket{
			data:     append([]byte(nil), packet...),
			class:    metadata.Class,
			enqueued: now,
		})
		return true
	}
	for !q.fitsLocked(len(packet)) {
		victim := q.oldestReplaceableLocked(metadata.Class)
		if victim < 0 {
			q.recordRejectedLocked(metadata.Class)
			return false
		}
		q.removeLocked(victim)
		q.stats.oldestDrops.Add(1)
	}
	q.appendLocked(http2QueuedPacket{
		data:     append([]byte(nil), packet...),
		class:    metadata.Class,
		enqueued: now,
	})
	return true
}

func (q *http2UploadQueue) recordRejectedLocked(class protocol.PacketClass) {
	if class == protocol.PacketClassTCP {
		q.stats.tailDrops.Add(1)
	} else {
		q.stats.fullDrops.Add(1)
	}
}

func (q *http2UploadQueue) takeBatch(
	ctx context.Context,
	now func() time.Time,
	maxPackets int,
	maxBytes int,
) ([][]byte, bool) {
	for {
		q.mu.Lock()
		q.dropExpiredLocked(now())
		if q.head < len(q.items) {
			batch := q.takeBatchLocked(maxPackets, maxBytes)
			q.mu.Unlock()
			return batch, true
		}
		if q.closed {
			q.mu.Unlock()
			return nil, false
		}
		ready := q.ready
		q.mu.Unlock()

		select {
		case <-ready:
		case <-ctx.Done():
			return nil, false
		}
	}
}

func (q *http2UploadQueue) dequeue(now time.Time) ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.dropExpiredLocked(now)
	if q.head >= len(q.items) {
		q.resetLocked()
		return nil, false
	}
	packet := q.items[q.head].data
	q.items[q.head] = http2QueuedPacket{}
	q.head++
	q.adjustBytesLocked(-len(packet))
	q.compactLocked()
	q.signalLocked()
	return packet, true
}

func (q *http2UploadQueue) queuedBytes() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bytes
}

func (q *http2UploadQueue) queuedBytesAt(now time.Time) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.dropExpiredLocked(now)
	return q.bytes
}

func (q *http2UploadQueue) queuedPackets() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) - q.head
}

func (q *http2UploadQueue) takeBatchLocked(maxPackets, maxBytes int) [][]byte {
	available := len(q.items) - q.head
	count := min(available, maxPackets)
	if count <= 0 {
		return nil
	}
	batchBytes := 0
	for offset := 0; offset < count; offset++ {
		size := len(q.items[q.head+offset].data)
		if offset > 0 && batchBytes+size > maxBytes {
			count = offset
			break
		}
		batchBytes += size
	}
	batch := make([][]byte, count)
	for offset := range count {
		batch[offset] = q.items[q.head+offset].data
		q.items[q.head+offset] = http2QueuedPacket{}
	}
	q.head += count
	q.adjustBytesLocked(-batchBytes)
	q.compactLocked()
	q.signalLocked()
	return batch
}

func (q *http2UploadQueue) fitsLocked(packetBytes int) bool {
	return packetBytes <= q.config.maxBytes &&
		len(q.items)-q.head < q.config.maxPackets &&
		q.bytes+packetBytes <= q.config.maxBytes
}

func (q *http2UploadQueue) appendLocked(packet http2QueuedPacket) {
	wasEmpty := q.head >= len(q.items)
	q.items = append(q.items, packet)
	q.adjustBytesLocked(len(packet.data))
	if wasEmpty {
		q.signalLocked()
	}
}

func (q *http2UploadQueue) signalLocked() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

func (q *http2UploadQueue) dropExpiredLocked(now time.Time) {
	for index := q.head; index < len(q.items); {
		item := q.items[index]
		if now.Sub(item.enqueued) < q.maxAge(item.class) {
			index++
			continue
		}
		q.removeLocked(index)
		q.stats.expiredDrops.Add(1)
	}
}

func (q *http2UploadQueue) maxAge(class protocol.PacketClass) time.Duration {
	switch class {
	case protocol.PacketClassTCP:
		return q.config.tcpMaxAge
	case protocol.PacketClassControl:
		return q.config.controlAge
	default:
		return q.config.udpMaxAge
	}
}

func (q *http2UploadQueue) oldestReplaceableLocked(incoming protocol.PacketClass) int {
	for index := q.head; index < len(q.items); index++ {
		if q.items[index].class == protocol.PacketClassDatagram {
			return index
		}
	}
	if incoming == protocol.PacketClassControl {
		for index := q.head; index < len(q.items); index++ {
			if q.items[index].class == protocol.PacketClassControl {
				return index
			}
		}
	}
	return -1
}

func (q *http2UploadQueue) removeLocked(index int) {
	q.adjustBytesLocked(-len(q.items[index].data))
	copy(q.items[index:], q.items[index+1:])
	q.items[len(q.items)-1] = http2QueuedPacket{}
	q.items = q.items[:len(q.items)-1]
	if q.head >= len(q.items) {
		q.resetLocked()
	}
}

func (q *http2UploadQueue) adjustBytesLocked(delta int) {
	q.bytes += delta
	current := q.stats.currentBytes.Add(int64(delta))
	if current < 0 {
		q.stats.currentBytes.Store(0)
		current = 0
	}
	for {
		previous := q.stats.highWater.Load()
		if uint64(current) <= previous || q.stats.highWater.CompareAndSwap(previous, uint64(current)) {
			return
		}
	}
}

func (q *http2UploadQueue) compactLocked() {
	if q.head == 0 {
		return
	}
	if q.head < 64 && q.head*2 < len(q.items) {
		return
	}
	remaining := copy(q.items, q.items[q.head:])
	clear(q.items[remaining:])
	q.items = q.items[:remaining]
	q.head = 0
}

func (q *http2UploadQueue) resetLocked() {
	q.items = q.items[:0]
	q.head = 0
	q.bytes = 0
	q.stats.currentBytes.Store(0)
	select {
	case <-q.ready:
	default:
	}
}

func (q *http2UploadQueue) clearLocked() {
	for index := q.head; index < len(q.items); index++ {
		q.items[index] = http2QueuedPacket{}
	}
	q.items = nil
	q.head = 0
	q.bytes = 0
	q.stats.currentBytes.Store(0)
	select {
	case <-q.ready:
	default:
	}
}
