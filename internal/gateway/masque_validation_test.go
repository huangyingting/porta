package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/usage"
	"github.com/quic-go/quic-go"
)

func TestMasqueOversizeCountsFallbackWithoutDroppingPacket(t *testing.T) {
	metrics := &Metrics{}
	config := HandlerConfig{Metrics: metrics}
	var wire bytes.Buffer
	packet := testIPv4UDP()
	err := config.sendMasqueIPPacket(packet, func([]byte) error {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 20}
	}, masque.NewEncoder(&wire))
	if err != nil {
		t.Fatal(err)
	}
	capsule, err := masque.NewDecoder(&wire).Read()
	if err != nil || !bytes.Equal(capsule.Value, masque.EncodeIPPacket(packet)) {
		t.Fatalf("fallback changed the packet: %+v, %v", capsule, err)
	}
	for _, sendErr := range []error{nil, io.ErrClosedPipe} {
		err := config.sendMasqueIPPacket(packet, func([]byte) error { return sendErr }, masque.NewEncoder(&wire))
		if err != sendErr {
			t.Fatalf("send error = %v, want %v", err, sendErr)
		}
	}
	if metrics.datagramOversize.Load() != 1 || metrics.droppedPacketsFromClient.Load() != 0 {
		t.Fatal("oversize fallback was counted as a packet drop or unrelated sends incremented the counter")
	}
}

func TestMasqueDropsInvalidPacketsWithoutEndingSessionOrCountingUsage(t *testing.T) {
	var wire bytes.Buffer
	encoder := masque.NewEncoder(&wire)
	for _, packet := range [][]byte{
		nil,
		{0x60, 0, 0},
		make([]byte, 1200),
		testIPv4UDP(),
	} {
		if err := encoder.WriteIPPacket(packet); err != nil {
			t.Fatal(err)
		}
	}
	valid := testIPv4UDP()
	// testIPv4UDP has the assigned source; also send a source-spoofed packet.
	valid[12] = 192
	if err := encoder.WriteIPPacket(valid); err != nil {
		t.Fatal(err)
	}
	metrics := &Metrics{}
	config := HandlerConfig{Router: NewRouter(testPacketDevice{}, nil), MTU: 1100, Metrics: metrics}
	store, _ := usage.Open("", nil)
	session := store.Begin("", "account", "phone", "masque-h2", "", "")
	var assigned atomic.Bool
	assigned.Store(true)
	done := make(chan error, 1)
	(&masqueSession{HandlerConfig: config}).readMasqueCapsules(context.Background(), &wire, masque.NewEncoder(io.Discard),
		Lease{Address: netip.MustParseAddr("10.66.0.2")}, &assigned, session, done)
	if err := <-done; !errors.Is(err, io.EOF) {
		t.Fatalf("invalid packet terminated the capsule stream: %v", err)
	}
	session.Close()
	device := usage.Device(store.Snapshot(), "account", "phone")
	if metrics.droppedPacketsFromClient.Load() != 4 || metrics.packetsFromClient.Load() != 1 ||
		device.BytesUploaded != 28 || device.PacketsUploaded != 1 {
		t.Fatalf("invalid packets counted as accepted: dropped=%d accepted=%d usage=%+v",
			metrics.droppedPacketsFromClient.Load(), metrics.packetsFromClient.Load(), device)
	}
}
