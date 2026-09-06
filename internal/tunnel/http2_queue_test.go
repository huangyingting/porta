package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
)

func TestHTTP2UploadQueueOverflowPreservesTCPPrefix(t *testing.T) {
	config := defaultHTTP2QueueConfig
	config.maxPackets = 2
	config.maxBytes = 256
	queue := newHTTP2UploadQueue(config)
	now := time.Unix(100, 0)
	tcp := protocol.PacketMetadata{Class: protocol.PacketClassTCP}

	first := []byte{1, 1, 1}
	second := []byte{2, 2, 2}
	if !queue.enqueue(first, tcp, now) || !queue.enqueue(second, tcp, now) {
		t.Fatal("initial TCP packets were rejected")
	}
	first[0] = 9
	if queue.enqueue([]byte{3, 3, 3}, tcp, now) {
		t.Fatal("new TCP packet displaced a queued TCP prefix")
	}
	gotFirst, _ := queue.dequeue(now)
	gotSecond, _ := queue.dequeue(now)
	if !bytes.Equal(gotFirst, []byte{1, 1, 1}) || !bytes.Equal(gotSecond, second) {
		t.Fatalf("queued TCP prefix changed: %v, %v", gotFirst, gotSecond)
	}
	if queue.stats.tailDrops.Load() != 1 {
		t.Fatalf("TCP tail drops = %d, want 1", queue.stats.tailDrops.Load())
	}
}

func TestHTTP2UploadQueueEvictsDatagramForTCP(t *testing.T) {
	config := defaultHTTP2QueueConfig
	config.maxPackets = 1
	config.maxBytes = 256
	queue := newHTTP2UploadQueue(config)
	now := time.Unix(150, 0)
	datagram := protocol.PacketMetadata{Class: protocol.PacketClassDatagram}
	tcp := protocol.PacketMetadata{Class: protocol.PacketClassTCP}
	if !queue.enqueue([]byte{1}, datagram, now) {
		t.Fatal("datagram rejected")
	}
	if !queue.enqueue([]byte{2}, tcp, now) {
		t.Fatal("TCP packet did not displace queued datagram")
	}
	packet, ok := queue.dequeue(now)
	if !ok || !bytes.Equal(packet, []byte{2}) {
		t.Fatalf("retained packet = %v, want TCP packet", packet)
	}
	if queue.stats.oldestDrops.Load() != 1 {
		t.Fatalf("oldest drops = %d, want 1", queue.stats.oldestDrops.Load())
	}
}

func TestHTTP2UploadQueueRejectsAndDiscardsWhileLaneIsInactive(t *testing.T) {
	queue := newHTTP2UploadQueue(defaultHTTP2QueueConfig)
	now := time.Unix(175, 0)
	tcp := protocol.PacketMetadata{Class: protocol.PacketClassTCP}
	if !queue.enqueue([]byte{1}, tcp, now) {
		t.Fatal("active queue rejected packet")
	}

	queue.deactivateAndClear()

	if queue.enqueue([]byte{2}, tcp, now) {
		t.Fatal("inactive lane accepted packet")
	}
	if queue.queuedPackets() != 0 {
		t.Fatal("inactive lane retained stale packets")
	}
	queue.activate()
	if !queue.enqueue([]byte{3}, tcp, now) {
		t.Fatal("reactivated lane rejected packet")
	}
}

func TestHTTP2UploadQueueEvictsAndExpiresByClass(t *testing.T) {
	config := defaultHTTP2QueueConfig
	config.maxPackets = 2
	config.maxBytes = 256
	config.udpMaxAge = 10 * time.Millisecond
	config.controlAge = 20 * time.Millisecond
	queue := newHTTP2UploadQueue(config)
	now := time.Unix(200, 0)
	datagram := protocol.PacketMetadata{Class: protocol.PacketClassDatagram}
	control := protocol.PacketMetadata{Class: protocol.PacketClassControl}

	if !queue.enqueue([]byte{1}, datagram, now) ||
		!queue.enqueue([]byte{2}, control, now) ||
		!queue.enqueue([]byte{3}, control, now) {
		t.Fatal("class-aware queue replacement rejected a control packet")
	}
	first, _ := queue.dequeue(now)
	second, _ := queue.dequeue(now)
	if first[0] != 2 || second[0] != 3 {
		t.Fatalf("queue retained packets %v and %v", first, second)
	}
	if queue.stats.oldestDrops.Load() != 1 {
		t.Fatalf("oldest drops = %d, want 1", queue.stats.oldestDrops.Load())
	}

	if !queue.enqueue(make([]byte, 40), datagram, now) ||
		!queue.enqueue(make([]byte, 30), control, now) {
		t.Fatal("packets for expiry were rejected")
	}
	if queue.stats.highWater.Load() != 70 || queue.stats.currentBytes.Load() != 70 {
		t.Fatalf(
			"queue bytes current=%d high-water=%d, want 70",
			queue.stats.currentBytes.Load(),
			queue.stats.highWater.Load(),
		)
	}
	if packet, ok := queue.dequeue(now.Add(25 * time.Millisecond)); ok || packet != nil {
		t.Fatal("expired datagram or control packet was delivered")
	}
	if queue.stats.expiredDrops.Load() != 2 || queue.stats.currentBytes.Load() != 0 {
		t.Fatalf(
			"expiry drops=%d current bytes=%d",
			queue.stats.expiredDrops.Load(),
			queue.stats.currentBytes.Load(),
		)
	}
}

func TestHTTP2UploadQueueRejectsOversizedPacketAtomically(t *testing.T) {
	config := defaultHTTP2QueueConfig
	config.maxPackets = 2
	config.maxBytes = 4
	queue := newHTTP2UploadQueue(config)
	now := time.Unix(250, 0)
	datagram := protocol.PacketMetadata{Class: protocol.PacketClassDatagram}
	if !queue.enqueue([]byte{1, 2}, datagram, now) {
		t.Fatal("initial datagram rejected")
	}
	if queue.enqueue(make([]byte, 5), datagram, now) {
		t.Fatal("oversized datagram accepted")
	}
	packet, ok := queue.dequeue(now)
	if !ok || !bytes.Equal(packet, []byte{1, 2}) {
		t.Fatalf("oversized enqueue changed existing queue: %v", packet)
	}
	if queue.stats.fullDrops.Load() != 1 || queue.stats.oldestDrops.Load() != 0 {
		t.Fatalf(
			"oversized counters full=%d oldest=%d",
			queue.stats.fullDrops.Load(),
			queue.stats.oldestDrops.Load(),
		)
	}
}

func TestHTTP2UploadBatchIsPromptAndBounded(t *testing.T) {
	config := defaultHTTP2QueueConfig
	config.maxPackets = 8
	config.maxBytes = 1024
	queue := newHTTP2UploadQueue(config)
	now := time.Unix(300, 0)
	metadata := protocol.PacketMetadata{Class: protocol.PacketClassTCP}
	for marker := byte(1); marker <= 3; marker++ {
		if !queue.enqueue(bytes.Repeat([]byte{marker}, 60), metadata, now) {
			t.Fatalf("packet %d rejected", marker)
		}
	}
	batch, ok := queue.takeBatch(context.Background(), func() time.Time { return now }, 2, 100)
	if !ok || len(batch) != 1 || batch[0][0] != 1 {
		t.Fatalf("first bounded batch = %v", batch)
	}
	batch, ok = queue.takeBatch(context.Background(), func() time.Time { return now }, 2, 120)
	if !ok || len(batch) != 2 || batch[0][0] != 2 || batch[1][0] != 3 {
		t.Fatalf("second bounded batch = %v", batch)
	}
}

func TestHTTP2UploadQueueReleasesPacketStorage(t *testing.T) {
	for _, batch := range []bool{false, true} {
		queue := newHTTP2UploadQueue(defaultHTTP2QueueConfig)
		now := time.Now()
		metadata := protocol.PacketMetadata{Class: protocol.PacketClassTCP}
		queue.enqueue(make([]byte, 80), metadata, now)
		queue.enqueue(make([]byte, 80), metadata, now)
		for range 2 {
			if batch {
				queue.takeBatch(context.Background(), func() time.Time { return now }, 1, 100)
			} else {
				queue.dequeue(now)
			}
		}
		retained := 0
		for _, item := range queue.items[:cap(queue.items)] {
			retained += len(item.data)
		}
		if retained != 0 {
			t.Errorf("drained queue (batch=%t) retains %d packet bytes in backing storage", batch, retained)
		}
	}
}

func TestHTTP2FlowPinningUsesLeastLoadedHealthyLane(t *testing.T) {
	group := newHTTP2RoutingTestGroup()
	now := time.Unix(400, 0)
	group.now = func() time.Time { return now }
	for index := 1; index < http2LaneCount; index++ {
		group.lanes[index].active.Store(true)
	}
	load := protocol.PacketMetadata{Class: protocol.PacketClassTCP}
	group.lanes[1].upload.enqueue(make([]byte, 100), load, now)
	group.lanes[2].upload.enqueue(make([]byte, 50), load, now)

	packet := http2TestUDP([4]byte{10, 66, 0, 2}, [4]byte{1, 1, 1, 1}, 40000, 443, 300)
	metadata := protocol.ClassifyIPv4(packet)
	if lane := group.dataLane(metadata, now); lane.index != 3 {
		t.Fatalf("new flow selected lane %d, want least-loaded lane 3", lane.index)
	}
	group.lanes[3].upload.enqueue(make([]byte, 200), load, now)
	if lane := group.dataLane(metadata, now); lane.index != 3 {
		t.Fatalf("pinned flow moved to lane %d", lane.index)
	}

	group.lanes[3].active.Store(false)
	if lane := group.dataLane(metadata, now); lane.index != 2 {
		t.Fatalf("flow did not route around failed lane: got %d, want 2", lane.index)
	}
	group.flowMu.Lock()
	group.flows[metadata.Flow] = http2FlowAssignment{lane: 2, lastSeen: now.Add(-http2FlowIdle)}
	group.flowMu.Unlock()
	group.lanes[2].upload.enqueue(make([]byte, 100), load, now)
	group.lanes[3].active.Store(true)
	if lane := group.dataLane(metadata, now); lane.index != 1 {
		t.Fatalf("idle flow assignment did not expire: got lane %d, want least-loaded lane 1", lane.index)
	}
}

func TestHTTP2FragmentsStayOnOneLane(t *testing.T) {
	group := newHTTP2RoutingTestGroup()
	now := time.Unix(500, 0)
	for index := 1; index < http2LaneCount; index++ {
		group.lanes[index].active.Store(true)
	}
	first := http2TestUDP([4]byte{10, 66, 0, 2}, [4]byte{1, 1, 1, 1}, 40000, 53, 80)
	binary.BigEndian.PutUint16(first[4:6], 0x1234)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	second := append([]byte(nil), first...)
	binary.BigEndian.PutUint16(second[6:8], 1)
	for index := 20; index < len(second); index++ {
		second[index] ^= 0xff
	}
	firstMetadata := protocol.ClassifyIPv4(first)
	secondMetadata := protocol.ClassifyIPv4(second)
	if firstMetadata.Flow != secondMetadata.Flow {
		t.Fatal("fragment flow keys differ")
	}
	firstLane := group.dataLane(firstMetadata, now)
	secondLane := group.dataLane(secondMetadata, now)
	if firstLane == nil || secondLane == nil || firstLane.index != secondLane.index {
		t.Fatalf("fragments selected lanes %v and %v", firstLane, secondLane)
	}
}

func TestHTTP2ControlClassificationRoutesToLaneZero(t *testing.T) {
	group := newHTTP2RoutingTestGroup()
	group.lanes[0].active.Store(true)
	group.lanes[1].active.Store(true)
	packet := http2TestIPv4([4]byte{10, 66, 0, 2}, [4]byte{1, 1, 1, 1}, 1, 28)
	if protocol.ClassifyIPv4(packet).Class != protocol.PacketClassControl {
		t.Fatal("test packet was not classified as control traffic")
	}
	if err := group.send(packet); err != nil {
		t.Fatal(err)
	}
	if group.lanes[0].upload.queuedPackets() != 1 {
		t.Fatal("control packet was not queued on lane zero")
	}
	for index := 1; index < http2LaneCount; index++ {
		if group.lanes[index].upload.queuedPackets() != 0 {
			t.Fatalf("control packet leaked to data lane %d", index)
		}
	}
}

func TestHTTP2TemporaryDataLaneLossKeepsConnUsable(t *testing.T) {
	group := newHTTP2RoutingTestGroup()
	group.lanes[0].active.Store(true)
	packet := http2TestUDP([4]byte{10, 66, 0, 2}, [4]byte{1, 1, 1, 1}, 40000, 443, 300)
	if err := group.send(packet); err != nil {
		t.Fatalf("temporary data-lane loss failed Conn early: %v", err)
	}
	if group.lanes[0].upload.queuedPackets() != 1 {
		t.Fatal("ordinary traffic did not use the healthy control lane during recovery")
	}
	metadata := protocol.ClassifyIPv4(packet)
	if _, pinned := group.flows[metadata.Flow]; pinned {
		t.Fatal("degraded control-lane fallback pinned an ordinary flow")
	}
	group.lanes[2].active.Store(true)
	if lane := group.dataLane(metadata, time.Now()); lane == nil || lane.index != 2 {
		t.Fatalf("recovered flow did not return to a data lane: %v", lane)
	}
}

func TestHTTP2LeaseChangeAfterFullOutageRequiresFreshGroup(t *testing.T) {
	group := newHTTP2RoutingTestGroup()
	group.established.Store(true)
	changed := group.lease
	changed.Address = netip.MustParsePrefix("10.66.0.3/29")

	err := group.acceptLease(changed)
	if err == nil || isPermanent(err) || !IsRetryable(err) {
		t.Fatalf("full-outage lease change error = %v, want retryable", err)
	}

	group.lanes[0].active.Store(true)
	if err := group.acceptLease(changed); err == nil || !isPermanent(err) {
		t.Fatalf("concurrent-lane lease mismatch error = %v, want permanent", err)
	}
}

func TestHTTP2DownstreamMergePrioritizesControlAndBoundsDataStarvation(t *testing.T) {
	group := newHTTP2RoutingTestGroup()
	for marker := byte(1); marker <= 5; marker++ {
		group.lanes[0].downstream <- []byte{marker}
	}
	group.lanes[1].downstream <- []byte{99}
	for want := byte(1); want <= 4; want++ {
		packet, err := group.receive()
		if err != nil || packet[0] != want {
			t.Fatalf("control receive %d = %v, %v", want, packet, err)
		}
	}
	packet, err := group.receive()
	if err != nil || packet[0] != 99 {
		t.Fatalf("data lane starved behind control lane: %v, %v", packet, err)
	}
}

func newHTTP2RoutingTestGroup() *http2Group {
	ctx, cancel := context.WithCancel(context.Background())
	group := &http2Group{
		ctx:           ctx,
		cancel:        cancel,
		now:           time.Now,
		lease:         Lease{Address: netip.MustParsePrefix("10.66.0.2/29"), Gateway: netip.MustParseAddr("10.66.0.1"), MTU: 1300},
		leaseSet:      true,
		flows:         make(map[protocol.FlowKey]http2FlowAssignment),
		nextDataLane:  1,
		controlBudget: http2ControlBurst,
		downloadReady: make(chan struct{}, 1),
		stateChanged:  make(chan struct{}, 1),
		failureSignal: make(chan struct{}),
	}
	for index := range http2LaneCount {
		group.lanes[index] = &http2Lane{
			index:      index,
			upload:     newHTTP2UploadQueue(defaultHTTP2QueueConfig),
			downstream: make(chan []byte, http2DownstreamPackets),
		}
	}
	return group
}

func http2TestUDP(source, destination [4]byte, sourcePort, destinationPort uint16, size int) []byte {
	packet := http2TestIPv4(source, destination, 17, size)
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	return packet
}

func http2TestIPv4(source, destination [4]byte, transport uint8, size int) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	packet[8] = 64
	packet[9] = transport
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	return packet
}
