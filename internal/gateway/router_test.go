package gateway

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
)

func TestSessionQueueDropsOldestPacketWithoutClosing(t *testing.T) {
	metrics := &Metrics{}
	config := defaultPacketQueueConfig
	config.maxPackets = 2
	config.maxBytes = 100
	session := &Session{metrics: metrics, queue: newPacketQueue(config, metrics, 0)}
	session.enqueue([]byte{1})
	session.enqueue([]byte{2})
	session.enqueue([]byte{3})

	first, _ := session.dequeue()
	second, _ := session.dequeue()
	if first[0] != 2 || second[0] != 3 {
		t.Fatalf("queued packets = %v, %v; want newest packets 2 and 3", first, second)
	}
	if got := metrics.queueOldestDrops.Load(); got != 1 {
		t.Fatalf("oldest packet drop count = %d", got)
	}
}

func TestCanceledSessionDoesNotQueuePackets(t *testing.T) {
	metrics := &Metrics{}
	session, ctx := newSession(
		context.Background(),
		netip.MustParseAddr("10.66.0.2"),
		metrics,
		0,
		defaultPacketQueueConfig,
	)
	session.Close()
	<-ctx.Done()
	session.enqueue([]byte{1})
	if session.queue.queuedPackets() != 0 || metrics.closedSessionDrops.Load() != 1 {
		t.Fatal("canceled session queued traffic or did not count the drop")
	}
}

func TestRouterGroupedLanesDoNotReplaceSiblings(t *testing.T) {
	router := NewRouter(testPacketDevice{}, nil)
	address := netip.MustParseAddr("10.66.0.2")
	first, firstContext, _, err := router.RegisterGroup(context.Background(), address, "session-12345678", 0, 4, "peer:1")
	if err != nil {
		t.Fatal(err)
	}
	second, secondContext, _, err := router.RegisterGroup(context.Background(), address, "session-12345678", 1, 4, "peer:2")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstContext.Done():
		t.Fatal("registering a sibling lane closed the first lane")
	default:
	}

	replacement, _, _, err := router.RegisterGroup(context.Background(), address, "session-12345678", 0, 4, "peer:3")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstContext.Done():
	default:
		t.Fatal("replacing a lane did not close its previous connection")
	}
	select {
	case <-secondContext.Done():
		t.Fatal("replacing lane zero closed lane one")
	default:
	}
	second.Close()
	replacement.Close()
	first.Close()
}

func TestRouterDetectsCollapsedBackendConnections(t *testing.T) {
	router := NewRouter(testPacketDevice{}, nil)
	address := netip.MustParseAddr("10.66.0.2")
	first, _, collapsed, err := router.RegisterGroup(
		context.Background(), address, "session-12345678", 0, 4, "proxy:443",
	)
	if err != nil || collapsed {
		t.Fatalf("first lane = collapsed %t, error %v", collapsed, err)
	}
	second, _, collapsed, err := router.RegisterGroup(
		context.Background(), address, "session-12345678", 1, 4, "proxy:443",
	)
	if err != nil || !collapsed {
		t.Fatalf("second lane = collapsed %t, error %v", collapsed, err)
	}
	if router.metrics.Load().laneCollapsedGroups.Load() != 1 {
		t.Fatal("collapsed lane group was not counted")
	}
	first.Close()
	second.Close()
}

func TestRouterPinsNewFlowsToLeastLoadedDataLane(t *testing.T) {
	group := &sessionGroup{
		laneCount: 4,
		lanes:     make(map[int]*Session),
		flows:     make(map[protocol.FlowKey]flowLane),
	}
	for lane := 1; lane < 4; lane++ {
		group.lanes[lane] = &Session{queue: newPacketQueue(defaultPacketQueueConfig, nil, lane)}
	}
	group.lanes[1].queue.enqueue(make([]byte, 100), time.Now())
	group.lanes[2].queue.enqueue(make([]byte, 50), time.Now())
	packet := testIPv4UDP()
	packet = append(packet, make([]byte, 300-len(packet))...)
	packet[2], packet[3] = byte(len(packet)>>8), byte(len(packet))
	metadata := protocol.ClassifyIPv4(packet)
	if lane := selectDataLane(group, metadata); lane != 3 {
		t.Fatalf("selected lane = %d, want least-loaded lane 3", lane)
	}
	group.lanes[3].queue.enqueue(make([]byte, 200), time.Now())
	if lane := selectDataLane(group, metadata); lane != 3 {
		t.Fatalf("pinned flow moved to lane %d", lane)
	}
}

func TestPacketLaneReservesLaneZeroForDNS(t *testing.T) {
	packet := testIPv4UDP()
	packet[22] = 0
	packet[23] = 53
	if lane := packetLane(packet, 4); lane != 0 {
		t.Fatalf("DNS lane = %d, want 0", lane)
	}
	packet = append(packet, make([]byte, 300-len(packet))...)
	packet[2] = byte(len(packet) >> 8)
	packet[3] = byte(len(packet))
	packet[22] = 1
	packet[23] = 187
	first := packetLane(packet, 4)
	packet[4] = 0x12
	packet[5] = 0x34
	packet[10] = 0x56
	packet[11] = 0x78
	second := packetLane(packet, 4)
	if first < 1 || first > 3 || second != first {
		t.Fatalf("data lanes = %d, %d; want stable lane in 1..3", first, second)
	}
}

func testIPv4UDP() []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[2] = byte(len(packet) >> 8)
	packet[3] = byte(len(packet))
	packet[9] = 17
	copy(packet[12:16], []byte{10, 66, 0, 2})
	copy(packet[16:20], []byte{1, 1, 1, 1})
	packet[20] = 0x9c
	packet[21] = 0x40
	packet[22] = 0x01
	packet[23] = 0xbb
	return packet
}

func TestPacketLaneKeepsFragmentsTogether(t *testing.T) {
	packet := testIPv4UDP()
	packet[6] = 0x20
	packet[22], packet[23] = 0, 53
	first := packetLane(packet, 4)
	if first == 0 {
		t.Fatal("fragmented traffic must not depend on transport ports")
	}
	for _, flags := range [][2]byte{{0x20, 1}, {0, 2}} {
		packet[6], packet[7] = flags[0], flags[1]
		for value := 0; value < 256; value++ {
			packet[20], packet[22] = byte(value), byte(255-value)
			if lane := packetLane(packet, 4); lane != first {
				t.Fatalf("fragment payload changed lane from %d to %d", first, lane)
			}
		}
	}
	packet[6], packet[7] = 0x40, 0
	packet[22], packet[23] = 0, 53
	if lane := packetLane(packet, 4); lane != 0 {
		t.Fatal("Don't Fragment flag prevented DNS prioritization")
	}
}
