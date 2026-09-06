package gateway

import (
	"sync"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
)

const (
	defaultQueuePackets = 96
	defaultQueueBytes   = 128 << 10
)

type packetQueueConfig struct {
	maxPackets int
	maxBytes   int
	tcpMaxAge  time.Duration
	udpMaxAge  time.Duration
	controlAge time.Duration
	policy     packetQueuePolicy
}

type packetQueuePolicy uint8

const (
	packetQueueClassAware packetQueuePolicy = iota
	packetQueueDropOldest
)

func (q *packetQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	if q.metrics != nil && q.bytes != 0 {
		q.metrics.adjustQueueBytes(q.lane, -int64(q.bytes))
	}
	q.resetLocked()
}

var defaultPacketQueueConfig = packetQueueConfig{
	maxPackets: defaultQueuePackets,
	maxBytes:   defaultQueueBytes,
	tcpMaxAge:  500 * time.Millisecond,
	udpMaxAge:  150 * time.Millisecond,
	controlAge: 250 * time.Millisecond,
}

var masquePacketQueueConfig = packetQueueConfig{
	maxPackets: 256,
	maxBytes:   256 * 9000,
	policy:     packetQueueDropOldest,
}

type queuedPacket struct {
	data     []byte
	class    protocol.PacketClass
	enqueued time.Time
}

type packetQueue struct {
	mu      sync.Mutex
	items   []queuedPacket
	head    int
	bytes   int
	ready   chan struct{}
	config  packetQueueConfig
	metrics *Metrics
	lane    int
	closed  bool
}

func newPacketQueue(config packetQueueConfig, metrics *Metrics, lane int) *packetQueue {
	return &packetQueue{
		items:   make([]queuedPacket, 0, config.maxPackets),
		ready:   make(chan struct{}, 1),
		config:  config,
		metrics: metrics,
		lane:    lane,
	}
}

func (q *packetQueue) enqueue(packet []byte, now time.Time) bool {
	metadata := protocol.ClassifyIPv4(packet)
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	q.dropExpiredLocked(now)
	if q.fitsLocked(len(packet)) {
		q.appendLocked(queuedPacket{data: packet, class: metadata.Class, enqueued: now})
		return true
	}
	for !q.fitsLocked(len(packet)) {
		victim := -1
		if q.config.policy == packetQueueDropOldest {
			if q.head < len(q.items) {
				victim = q.head
			}
		} else {
			victim = q.oldestReplaceableLocked(metadata.Class)
		}
		if victim < 0 {
			if q.metrics != nil {
				if metadata.Class == protocol.PacketClassTCP {
					q.metrics.queueTailDrops.Add(1)
				} else {
					q.metrics.queueFullDrops.Add(1)
				}
			}
			return false
		}
		q.removeLocked(victim)
		if q.metrics != nil {
			q.metrics.queueOldestDrops.Add(1)
		}
	}
	q.appendLocked(queuedPacket{data: packet, class: metadata.Class, enqueued: now})
	return true
}

func (q *packetQueue) dequeue(now time.Time) ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil, false
	}
	q.dropExpiredLocked(now)
	if q.head >= len(q.items) {
		q.resetLocked()
		return nil, false
	}
	item := q.items[q.head]
	q.items[q.head] = queuedPacket{}
	q.head++
	q.bytes -= len(item.data)
	if q.metrics != nil {
		q.metrics.adjustQueueBytes(q.lane, -int64(len(item.data)))
	}
	q.compactLocked()
	q.signalLocked()
	return item.data, true
}

func (q *packetQueue) readySignal() <-chan struct{} {
	return q.ready
}

func (q *packetQueue) queuedBytes() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bytes
}

func (q *packetQueue) queuedPackets() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) - q.head
}

func (q *packetQueue) fitsLocked(packetBytes int) bool {
	return len(q.items)-q.head < q.config.maxPackets && q.bytes+packetBytes <= q.config.maxBytes
}

func (q *packetQueue) appendLocked(packet queuedPacket) {
	wasEmpty := q.head >= len(q.items)
	q.items = append(q.items, packet)
	q.bytes += len(packet.data)
	if q.metrics != nil {
		q.metrics.adjustQueueBytes(q.lane, int64(len(packet.data)))
	}
	if wasEmpty {
		q.signalLocked()
	}
}

func (q *packetQueue) signalLocked() {
	if q.head >= len(q.items) {
		return
	}
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

func (q *packetQueue) dropExpiredLocked(now time.Time) {
	for index := q.head; index < len(q.items); {
		item := q.items[index]
		maxAge := q.maxAge(item.class)
		if maxAge <= 0 || now.Sub(item.enqueued) < maxAge {
			index++
			continue
		}
		q.removeLocked(index)
		if q.metrics != nil {
			q.metrics.queueExpiredDrops.Add(1)
		}
	}
}

func (q *packetQueue) maxAge(class protocol.PacketClass) time.Duration {
	switch class {
	case protocol.PacketClassTCP:
		return q.config.tcpMaxAge
	case protocol.PacketClassControl:
		return q.config.controlAge
	default:
		return q.config.udpMaxAge
	}
}

func (q *packetQueue) oldestReplaceableLocked(incoming protocol.PacketClass) int {
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

func (q *packetQueue) removeLocked(index int) {
	q.bytes -= len(q.items[index].data)
	if q.metrics != nil {
		q.metrics.adjustQueueBytes(q.lane, -int64(len(q.items[index].data)))
	}
	copy(q.items[index:], q.items[index+1:])
	q.items[len(q.items)-1] = queuedPacket{}
	q.items = q.items[:len(q.items)-1]
	if q.head >= len(q.items) {
		q.resetLocked()
	}
}

func (q *packetQueue) compactLocked() {
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

func (q *packetQueue) resetLocked() {
	clear(q.items)
	q.items = q.items[:0]
	q.head = 0
	q.bytes = 0
	select {
	case <-q.ready:
	default:
	}
}
