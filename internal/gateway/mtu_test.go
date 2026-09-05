package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/usage"
)

type mtuPacketDevice struct {
	testPacketDevice
	writes [][]byte
	err    error
}

func (d *mtuPacketDevice) WritePacket(_ context.Context, packet []byte) error {
	if d.err != nil {
		return d.err
	}
	d.writes = append(d.writes, bytes.Clone(packet))
	return nil
}

func newMTUTestSession(t *testing.T, mtu int) (*masqueSession, Lease, *mtuPacketDevice, *usage.Session) {
	t.Helper()
	responder, err := masque.NewMTUResponder(1400)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := masque.ParseMTUToken(responder.Offer())
	if mtu > masque.SafeMTU {
		data, err := masque.EncodeMTUProbe(masque.MTUProbe{Token: token, Sequence: 1, Size: mtu})
		if err != nil {
			t.Fatal(err)
		}
		if err := responder.Echo(data, func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := responder.Commit(masque.EncodeMTUSelection(token, mtu)); err != nil {
		t.Fatal(err)
	}
	dev := &mtuPacketDevice{}
	store, err := usage.Open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	session := store.Begin("", "account", "device", "masque-h3", "", "")
	t.Cleanup(session.Close)
	return &masqueSession{
		HandlerConfig: HandlerConfig{
			MTU: 1400, Metrics: &Metrics{}, Router: NewRouter(dev, nil),
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		mtuDiscovery: responder,
	}, Lease{Address: netip.MustParseAddr("10.66.0.2"), Gateway: netip.MustParseAddr("10.66.0.1"), PrefixBits: 24}, dev, session
}

func mtuIPv4Packet(size int, df bool) []byte {
	packet := make([]byte, size)
	copy(packet, testIPv4UDP())
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	packet[8] = 64
	if df {
		packet[6] = 0x40
	}
	for i := 28; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	mtuSetChecksum(packet)
	return packet
}

func mtuSetChecksum(packet []byte) {
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], mtuChecksum(packet[:20]))
}

func mtuChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i]) << 8
		if i+1 < len(data) {
			sum += uint32(data[i+1])
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestPerSessionMTULimitsDoNotChangeSharedCeiling(t *testing.T) {
	small, lease, sharedDev, smallUsage := newMTUTestSession(t, 1100)
	large, largeLease, _, largeUsage := newMTUTestSession(t, 1280)
	large.Router = small.Router
	largeLease.Address = lease.Address.Next()
	for _, test := range []struct {
		session *masqueSession
		usage   *usage.Session
		lease   Lease
		wantMTU int
	}{
		{small, smallUsage, lease, 1100}, {large, largeUsage, largeLease, 1280},
	} {
		packet := mtuIPv4Packet(1400, false)
		copy(packet[12:16], []byte{8, 8, 8, 8})
		destination := test.lease.Address.As4()
		copy(packet[16:20], destination[:])
		mtuSetChecksum(packet)
		before := bytes.Clone(packet)
		var reassembled []byte
		count := 0
		err := test.session.sendDownlink(context.Background(), test.lease, packet, func(fragment []byte) error {
			count++
			if len(fragment) > test.wantMTU || mtuChecksum(fragment[:20]) != 0 {
				t.Fatalf("fragment size/checksum: %d", len(fragment))
			}
			if offset := int(binary.BigEndian.Uint16(fragment[6:8])&0x1fff) * 8; offset != len(reassembled) {
				t.Fatalf("fragment offset %d, want %d", offset, len(reassembled))
			}
			reassembled = append(reassembled, fragment[20:]...)
			return nil
		}, test.usage)
		if err != nil || count != 2 || !bytes.Equal(reassembled, before[20:]) || !bytes.Equal(packet, before) {
			t.Fatalf("fragmented delivery: count=%d error=%v", count, err)
		}
		if test.session.MTU != 1400 || test.session.packetMTU() != test.wantMTU {
			t.Fatal("per-client selection modified the shared MTU")
		}
	}
	packet := mtuIPv4Packet(1200, false)
	if err := small.injectMasquePacket(context.Background(), lease.Address, packet); !errors.Is(err, errInvalidClientPacket) {
		t.Fatalf("oversized upload accepted by smaller session: %v", err)
	}
	if len(sharedDev.writes) != 0 {
		t.Fatal("oversized packet reached the shared TUN")
	}
	source := largeLease.Address.As4()
	copy(packet[12:16], source[:])
	mtuSetChecksum(packet)
	if err := large.injectMasquePacket(context.Background(), largeLease.Address, packet); err != nil {
		t.Fatalf("larger session inherited smaller MTU: %v", err)
	}
	if len(sharedDev.writes) != 1 {
		t.Fatal("per-session ingress limits were not enforced")
	}
}

func TestDownlinkDFGeneratesRateLimitedICMPWithoutDisconnect(t *testing.T) {
	session, lease, dev, usageSession := newMTUTestSession(t, 1100)
	packet := mtuIPv4Packet(1300, true)
	copy(packet[12:16], []byte{8, 8, 8, 8})
	destination := lease.Address.As4()
	copy(packet[16:20], destination[:])
	mtuSetChecksum(packet)
	send := func([]byte) error { t.Error("oversized DF packet sent to client"); return nil }
	if err := session.sendDownlink(context.Background(), lease, packet, send, usageSession); err != nil {
		t.Fatal(err)
	}
	if len(dev.writes) != 1 {
		t.Fatal("no fragmentation-needed response injected into gateway TUN")
	}
	reply := dev.writes[0]
	info, err := protocol.ParseIPv4(reply)
	if err != nil || info.Source != lease.Gateway || info.Destination.String() != "8.8.8.8" ||
		reply[20] != 3 || reply[21] != 4 || binary.BigEndian.Uint16(reply[26:28]) != 1100 ||
		mtuChecksum(reply[:20]) != 0 || mtuChecksum(reply[20:]) != 0 || !bytes.Equal(reply[28:], packet[:28]) {
		t.Fatalf("invalid ICMP response: %x, %v", reply, err)
	}
	session.icmpAfter = time.Now().Add(time.Hour)
	if err := session.sendDownlink(context.Background(), lease, packet, send, usageSession); err != nil {
		t.Fatal(err)
	}
	packet[9], packet[20] = 1, 3
	mtuSetChecksum(packet)
	if err := session.sendDownlink(context.Background(), lease, packet, send, usageSession); err != nil {
		t.Fatal(err)
	}
	if len(dev.writes) != 1 || session.Metrics.mtuICMPSent.Load() != 1 ||
		session.Metrics.mtuICMPRateLimited.Load() != 1 || session.Metrics.mtuICMPSuppressed.Load() != 1 {
		t.Fatal("ICMP rate limiting or error-response suppression failed")
	}
	fits := mtuIPv4Packet(100, false)
	if err := session.sendDownlink(context.Background(), lease, fits, func(got []byte) error {
		if &got[0] != &fits[0] {
			t.Fatal("ordinary packet was copied")
		}
		return nil
	}, usageSession); err != nil {
		t.Fatalf("tunnel did not remain usable: %v", err)
	}
}

func TestDownlinkRejectsInvalidHeadersAndPropagatesIOErrors(t *testing.T) {
	session, lease, dev, usageSession := newMTUTestSession(t, 1100)
	bad := mtuIPv4Packet(1300, false)
	bad[10]++
	if err := session.sendDownlink(context.Background(), lease, bad, func([]byte) error {
		t.Error("invalid packet transmitted")
		return nil
	}, usageSession); err != nil || session.Metrics.invalidTUNDrops.Load() != 1 {
		t.Fatalf("invalid input handling: %v", err)
	}
	for _, size := range []int{100, 1300} {
		if err := session.sendDownlink(context.Background(), lease, mtuIPv4Packet(size, false),
			func([]byte) error { return io.ErrClosedPipe }, usageSession); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("send error hidden: %v", err)
		}
	}
	dev.err = io.ErrClosedPipe
	if err := session.sendDownlink(context.Background(), lease, mtuIPv4Packet(1300, true),
		func([]byte) error { return nil }, usageSession); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("TUN error hidden: %v", err)
	}
}

func TestMTUAgreementPrecedesAddressAssignment(t *testing.T) {
	responder, err := masque.NewMTUResponder(1400)
	if err != nil {
		t.Fatal(err)
	}
	session := &masqueSession{mtuDiscovery: responder, addressReady: make(chan struct{}, 1)}
	lease := Lease{Address: netip.MustParseAddr("10.66.0.2")}
	request, _ := masque.EncodeAddressRequest([]masque.Address{{RequestID: 1, Prefix: netip.MustParsePrefix("0.0.0.0/32")}})
	var assigned atomic.Bool
	var output bytes.Buffer
	encoder := masque.NewEncoder(&output)
	if err := session.answerAddressRequest(encoder, lease, &assigned, request); !errors.Is(err, masque.ErrMTUMessage) || assigned.Load() || output.Len() != 0 {
		t.Fatalf("address assigned before MTU agreement: %v", err)
	}
	token, _ := masque.ParseMTUToken(responder.Offer())
	if _, err := responder.Commit(masque.EncodeMTUSelection(token, 1100)); err != nil {
		t.Fatal(err)
	}
	if err := session.answerAddressRequest(encoder, lease, &assigned, request); err != nil || !assigned.Load() {
		t.Fatalf("address not assigned after agreement: %v", err)
	}
	select {
	case <-session.addressReady:
	default:
		t.Fatal("downlink was not enabled after assignment")
	}
}
