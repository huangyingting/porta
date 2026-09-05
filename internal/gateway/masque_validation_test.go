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

func TestAddressAssignmentEnablesUplinkBeforePublishingControlBytes(t *testing.T) {
	for _, test := range []struct {
		name      string
		previous  bool
		ipv4      bool
		wantReady bool
	}{
		{"initial IPv4", false, true, true},
		{"initial IPv6 only", false, false, false},
		{"existing IPv4", true, true, true},
		{"preserve existing IPv4", true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &masqueSession{addressReady: make(chan struct{}, 1)}
			var assigned atomic.Bool
			assigned.Store(test.previous)
			prefix := netip.MustParsePrefix("::/128")
			if test.ipv4 {
				prefix = netip.MustParsePrefix("0.0.0.0/32")
			}
			request, err := masque.EncodeAddressRequest([]masque.Address{{RequestID: 1, Prefix: prefix}})
			if err != nil {
				t.Fatal(err)
			}
			writer := &assignmentObserverWriter{
				write: func(value []byte) (int, error) {
					if assigned.Load() != test.wantReady {
						t.Error("ADDRESS_ASSIGN can reach the peer before uplink readiness is published")
					}
					select {
					case <-session.addressReady:
						t.Error("downlink enabled before control response was flushed")
					default:
					}
					return len(value), nil
				},
			}
			err = session.answerAddressRequest(masque.NewEncoder(writer),
				Lease{Address: netip.MustParseAddr("10.66.0.2")}, &assigned, request)
			if err != nil || !writer.flushed || assigned.Load() != test.wantReady {
				t.Fatalf("assignment readiness/flush failed: %v", err)
			}
			if got := len(session.addressReady) != 0; got != test.wantReady {
				t.Fatalf("downlink ready = %t, want %t", got, test.wantReady)
			}
		})
	}
}

func TestAddressAssignmentWriteFailureRestoresUplinkState(t *testing.T) {
	request, err := masque.EncodeAddressRequest([]masque.Address{{
		RequestID: 1, Prefix: netip.MustParsePrefix("0.0.0.0/32"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, previous := range []bool{false, true} {
		for failAt := 1; failAt <= 4; failAt++ {
			session := &masqueSession{addressReady: make(chan struct{}, 1)}
			var assigned atomic.Bool
			assigned.Store(previous)
			writes := 0
			writer := &assignmentObserverWriter{
				write: func(value []byte) (int, error) {
					writes++
					if writes == failAt {
						return 0, io.ErrClosedPipe
					}
					return len(value), nil
				},
			}
			err := session.answerAddressRequest(masque.NewEncoder(writer),
				Lease{Address: netip.MustParseAddr("10.66.0.2")}, &assigned, request)
			if !errors.Is(err, io.ErrClosedPipe) || assigned.Load() != previous ||
				len(session.addressReady) != 0 || writer.flushed {
				t.Fatalf("write %d failure with previous=%t changed readiness: %v", failAt, previous, err)
			}
		}
	}
}

type assignmentObserverWriter struct {
	write   func([]byte) (int, error)
	flushed bool
}

func (w *assignmentObserverWriter) Write(value []byte) (int, error) { return w.write(value) }
func (w *assignmentObserverWriter) Flush()                          { w.flushed = true }
