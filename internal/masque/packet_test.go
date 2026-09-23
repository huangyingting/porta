package masque

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

func adaptivePacket(size int, df bool) []byte {
	packet := make([]byte, size)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	copy(packet[12:20], []byte{10, 66, 0, 2, 8, 8, 8, 8})
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	if df {
		packet[6] = 0x40
	}
	for i := 20; i < size; i++ {
		packet[i] = byte(i)
	}
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	return packet
}

func TestFeedbackConvergenceKeepsNegotiatedCeiling(t *testing.T) {
	now := time.Unix(100, 0)
	packet := adaptivePacket(1380, true)
	for _, ceiling := range []int{1100, 1400} {
		var policy FeedbackPolicy
		for i := range 3 {
			if got := policy.Oversized(packet, 1000, ceiling, now.Add(time.Duration(i)*100*time.Millisecond), 0); !got.SendICMP || got.UseCapsule {
				t.Fatalf("prior feedback %d not granted: %+v", i, got)
			}
		}
		if got := policy.Oversized(packet, 1000, ceiling, now.Add(250*time.Millisecond), 0); got.SendICMP || got.UseCapsule {
			t.Fatal("feedback was not globally rate limited")
		}
		_ = policy.Oversized(adaptivePacket(68, false), 1000, ceiling, now.Add(time.Second), 0)
		got := policy.Oversized(packet, 1000, ceiling, now.Add(2*time.Second), 0)
		if got.UseCapsule != (ceiling >= len(packet)) || got.SendICMP == got.UseCapsule {
			t.Fatalf("ceiling %d violated by decision %+v", ceiling, got)
		}
		got = policy.Oversized(packet, 900, ceiling, now.Add(3*time.Second), 0)
		if got.UseCapsule || !got.SendICMP {
			t.Fatal("budget reduction did not reset convergence")
		}
	}
}

func TestFeedbackBoundedIdleAndRTT(t *testing.T) {
	now := time.Unix(100, 0)
	var policy FeedbackPolicy
	for i := 0; i < 129; i++ {
		packet := adaptivePacket(1300, true)
		packet[20] = byte(i)
		policy.Oversized(packet, 1100, 1400, now.Add(time.Duration(i)*time.Second), time.Second)
	}
	if len(policy.flows) > 60 {
		t.Fatal("idle flows did not expire")
	}
	policy = FeedbackPolicy{}
	for i := 0; i < 129; i++ {
		packet := adaptivePacket(1300, true)
		packet[20] = byte(i)
		policy.Oversized(packet, 1100, 1400, now, time.Second)
	}
	if len(policy.flows) != 128 || policy.flows[0].key.SourcePort == protocol.ClassifyIPv4(adaptivePacket(1300, true)).Flow.SourcePort {
		t.Fatal("feedback table exceeded bound or did not evict the oldest flow")
	}
	for _, rtt := range []time.Duration{time.Second, 20 * time.Second, time.Duration(1<<63 - 1)} {
		policy = FeedbackPolicy{}
		packet := adaptivePacket(1300, true)
		for i := range 3 {
			policy.Oversized(packet, 1100, 1400, now.Add(time.Duration(i)*time.Second), rtt)
		}
		grace := min(4*min(rtt, 2500*time.Millisecond), 10*time.Second)
		if policy.Oversized(packet, 1100, 1400, now.Add(grace-time.Millisecond), rtt).UseCapsule {
			t.Fatal("RTT grace was shortened")
		}
		if !policy.Oversized(packet, 1100, 1400, now.Add(grace), rtt).UseCapsule {
			t.Fatal("RTT grace failed to permit a compatible packet")
		}
	}
}

func TestPacketWriterRetriesOnlyUnsentFragments(t *testing.T) {
	packet := adaptivePacket(1400, false)
	original := bytes.Clone(packet)
	var submitted [][]byte
	limit, calls := 1100, 0
	writer := PacketWriter{Ceiling: 1400, StreamID: 1024}
	writer.Datagram = func(value []byte) error {
		calls++
		if calls == 3 {
			limit = 200
		}
		if len(value)-1 > limit {
			return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(limit + 3)}
		}
		submitted = append(submitted, bytes.Clone(value[1:]))
		return nil
	}
	writer.Capsule = func([]byte) error { t.Fatal("fragmentable packet used capsules"); return nil }
	if err := writer.Send(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if writer.Limit() != 200 || writer.Ceiling != 1400 || writer.Stats.Reductions != 2 || !bytes.Equal(packet, original) {
		t.Fatalf("invalid budget/packet state: %+v", writer)
	}
	offset := 0
	for i, fragment := range submitted {
		if int(binary.BigEndian.Uint16(fragment[6:8])&0x1fff)*8 != offset {
			t.Fatal("already-submitted fragment replayed")
		}
		if i > 0 && len(fragment) > 200 {
			t.Fatal("unsent fragment was not refragmented")
		}
		if _, err := protocol.FragmentIPv4(fragment, len(fragment)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fragment[20:], original[20+offset:20+offset+len(fragment)-20]) {
			t.Fatal("refragmentation corrupted payload")
		}
		offset += len(fragment) - 20
	}
	if offset != len(packet)-20 {
		t.Fatal("fragment lost")
	}
	limit = 1400
	if err := writer.Send(context.Background(), adaptivePacket(300, false)); err != nil || writer.Limit() != 200 {
		t.Fatal("budget grew before reconnect")
	}
}

func TestPacketWriterDFPolicyAndUnusableCapacity(t *testing.T) {
	packet := adaptivePacket(1300, true)
	now := time.Unix(100, 0)
	for _, gateway := range []netip.Addr{netip.MustParseAddr("10.66.0.1"), {}} {
		icmp, capsules := 0, 0
		writer := PacketWriter{
			Ceiling: 1400, Gateway: gateway,
			Datagram: func([]byte) error { return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1102} },
			Capsule:  func([]byte) error { capsules++; return nil },
			ICMP: func(reply []byte) error {
				icmp++
				if reply[20] != 3 || reply[21] != 4 || binary.BigEndian.Uint16(reply[26:28]) != 1100 {
					t.Fatal("incorrect MTU feedback")
				}
				return nil
			},
		}
		for _, offset := range []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond, 2 * time.Second} {
			if err := writer.sendAt(context.Background(), packet, now.Add(offset)); err != nil {
				t.Fatal(err)
			}
		}
		if gateway.IsValid() && (icmp != 3 || capsules != 1) || !gateway.IsValid() && (icmp != 0 || capsules != 4) {
			t.Fatalf("gateway %s: feedback %d, capsules %d", gateway, icmp, capsules)
		}
	}
	for _, capacity := range []int64{0, 2, 69} {
		writer := PacketWriter{Ceiling: 1400,
			Datagram: func([]byte) error { return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: capacity} },
			Capsule:  func([]byte) error { t.Fatal("unusable present capacity fell back"); return nil },
		}
		if err := writer.Send(context.Background(), packet); !errors.Is(err, protocol.ErrInvalidMTU) {
			t.Fatalf("unusable capacity %d: %v", capacity, err)
		}
	}
}

func TestPacketWriterMissingGatewayPreservesCapsuleErrors(t *testing.T) {
	writer := PacketWriter{Ceiling: 1400,
		Datagram: func([]byte) error { return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1102} },
		Capsule:  func([]byte) error { return io.ErrClosedPipe },
	}
	if err := writer.Send(context.Background(), adaptivePacket(1300, true)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestIPDatagramCapacityStreamOverhead(t *testing.T) {
	for _, test := range []struct {
		id   uint64
		want int
	}{{0, 1198}, {252, 1198}, {256, 1197}, {65536, 1195}, {1 << 32, 1191}} {
		if got := IPDatagramCapacity(1200, test.id); got != test.want {
			t.Fatalf("stream %d: %d, want %d", test.id, got, test.want)
		}
	}
}

func TestCapsuleLimitRejectsBeforeReadingValue(t *testing.T) {
	header := quicvarint.Append(nil, CapsuleAddressAssign)
	header = quicvarint.Append(header, 16<<10+1)
	if _, err := NewBoundedDecoder(bytes.NewReader(header), 16<<10).Read(); !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("oversized capsule tried to read/allocate its value: %v", err)
	}
}

func BenchmarkPacketBudgetFits(b *testing.B) {
	writer := PacketWriter{Ceiling: 1400}
	for b.Loop() {
		if writer.Limit() < 1100 {
			b.Fatal("unexpected limit")
		}
	}
}
