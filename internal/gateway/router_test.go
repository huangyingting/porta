package gateway

import (
	"context"
	"net/netip"
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

func TestRouterGroupedLanesDoNotReplaceSiblings(t *testing.T) {
	router := NewRouter(testPacketDevice{}, nil)
	address := netip.MustParseAddr("10.66.0.2")
	first, firstContext, err := router.RegisterGroup(context.Background(), address, "session-12345678", 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	second, secondContext, err := router.RegisterGroup(context.Background(), address, "session-12345678", 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstContext.Done():
		t.Fatal("registering a sibling lane closed the first lane")
	default:
	}

	replacement, _, err := router.RegisterGroup(context.Background(), address, "session-12345678", 0, 4)
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

func TestPacketLaneReservesLaneZeroForDNS(t *testing.T) {
	packet := testIPv4UDP()
	packet[22] = 0
	packet[23] = 53
	if lane := packetLane(packet, 4); lane != 0 {
		t.Fatalf("DNS lane = %d, want 0", lane)
	}
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
