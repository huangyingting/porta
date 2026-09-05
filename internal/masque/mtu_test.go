package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestMTUProbeEncoding(t *testing.T) {
	want := MTUProbe{Token: MTUToken{1, 2, 3}, Sequence: 7, Size: 1280}
	data, err := EncodeMTUProbe(want)
	if err != nil || len(data) != len(EncodeIPPacket(make([]byte, want.Size))) {
		t.Fatalf("probe length does not match IP datagram: %d, %v", len(data), err)
	}
	got, err := DecodeMTUProbe(data)
	if err != nil || got != want {
		t.Fatalf("probe round trip = %+v, %v", got, err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:20] },
		func(b []byte) []byte { b[0] = 0; return b },
		func(b []byte) []byte { b[17], b[18] = 0, 0; return b },
		func(b []byte) []byte { b[20]++; return b },
		func(b []byte) []byte { b[len(b)-1] = 1; return b },
		func(b []byte) []byte { return append(b, 0) },
	} {
		if _, err := DecodeMTUProbe(mutate(bytes.Clone(data))); !errors.Is(err, ErrMTUMessage) {
			t.Fatal("malformed probe accepted")
		}
	}
	for _, probe := range []MTUProbe{{Size: -1}, {Size: 1100}, {Size: 9000, Sequence: 1}} {
		if _, err := EncodeMTUProbe(probe); !errors.Is(err, ErrMTUMessage) {
			t.Fatal("invalid probe encoded")
		}
	}
}

func TestMTUDiscoveryRequiresBidirectionalDatagramDelivery(t *testing.T) {
	for _, tt := range []struct {
		name      string
		maximum   int
		forward   int
		reverse   int
		lossAt    int
		staleOnly bool
		retryOnce bool
		want      int
	}{
		{name: "full", maximum: 1400, forward: 1400, reverse: 1400, want: 1400},
		{name: "ceiling", maximum: 1170, forward: 1400, reverse: 1400, want: 1170},
		{name: "bounded-jumbo", maximum: 9000, forward: 9000, reverse: 9000, want: 1400},
		{name: "local-limit", maximum: 1400, forward: 1180, reverse: 1400, want: 1152},
		{name: "reverse-limit", maximum: 1400, forward: 1400, reverse: 1180, want: 1152},
		{name: "loss", maximum: 1400, forward: 1400, reverse: 1400, lossAt: 1200, want: 1152},
		{name: "all-lost", maximum: 1400, forward: 1400, reverse: 1400, lossAt: 1100, want: 1100},
		{name: "baseline-too-large", maximum: 1400, forward: 1000, reverse: 1400, want: 1100},
		{name: "stale", maximum: 1400, forward: 1400, reverse: 1400, staleOnly: true, want: 1100},
		{name: "retry", maximum: 1400, forward: 1400, reverse: 1400, retryOnce: true, want: 1400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewMTUResponder(tt.maximum)
			if err != nil {
				t.Fatal(err)
			}
			token, err := ParseMTUToken(server.Offer())
			if err != nil {
				t.Fatal(err)
			}
			echoes := make(chan MTUProbe, 16)
			attempts := make(map[int]int)
			send := func(data []byte) error {
				probe, err := DecodeMTUProbe(data)
				if err != nil {
					return err
				}
				attempts[probe.Size]++
				if probe.Size > tt.forward {
					return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(tt.forward)}
				}
				if (tt.lossAt != 0 && probe.Size >= tt.lossAt) || (tt.retryOnce && probe.Size == 1200 && attempts[probe.Size] == 1) {
					return nil
				}
				return server.Echo(data, func(reply []byte) error {
					if probe.Size > tt.reverse {
						return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(tt.reverse)}
					}
					if !bytes.Equal(reply, data) {
						t.Fatal("echo changed probe")
					}
					if tt.staleOnly {
						wrong := probe
						wrong.Token[0]++
						echoes <- wrong
						probe.Sequence++
					}
					echoes <- probe
					return nil
				})
			}
			got, err := discoverMTU(context.Background(), tt.maximum, token, send, echoes, nil, time.Second, 5*time.Millisecond)
			if err != nil || got != tt.want {
				t.Fatalf("MTU = %d, %v; want %d", got, err, tt.want)
			}
			selected, err := server.Commit(EncodeMTUSelection(token, got))
			if err != nil {
				t.Fatal(err)
			}
			if selectedMTU, err := DecodeMTUSelection(selected, token); err != nil || selectedMTU != got || server.MTU() != got {
				t.Fatalf("selection agreement = %d, %v; server MTU %d", selectedMTU, err, server.MTU())
			}
		})
	}
}

func TestMTUDiscoveryBudgetCancellationAndErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sent := false
	send := func([]byte) error { sent = true; return nil }
	if _, err := DiscoverMTU(ctx, 1400, MTUToken{}, send, nil, nil); !errors.Is(err, context.Canceled) || sent {
		t.Fatalf("canceled discovery sent a packet: %v", err)
	}
	start := time.Now()
	mtu, err := discoverMTU(context.Background(), 1400, MTUToken{}, send, nil, nil, 10*time.Millisecond, time.Second)
	if err != nil || mtu != SafeMTU || time.Since(start) > time.Second {
		t.Fatalf("budget fallback = %d, %v", mtu, err)
	}
	if _, err := DiscoverMTU(context.Background(), 1400, MTUToken{}, func([]byte) error { return io.ErrClosedPipe }, nil, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("send failure hidden: %v", err)
	}
	failures := make(chan error, 1)
	failures <- io.EOF
	if _, err := DiscoverMTU(context.Background(), 1400, MTUToken{}, send, nil, failures); !errors.Is(err, io.EOF) {
		t.Fatalf("receive failure hidden: %v", err)
	}
	echoes := make(chan MTUProbe)
	close(echoes)
	if _, err := DiscoverMTU(context.Background(), 1400, MTUToken{}, send, echoes, nil); !errors.Is(err, ErrMTUMessage) {
		t.Fatalf("closed discovery receiver accepted: %v", err)
	}
}

func TestMTUResponderRejectsUnprovenOrLateChanges(t *testing.T) {
	server, err := NewMTUResponder(1400)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := ParseMTUToken(server.Offer())
	if _, err := server.Commit(EncodeMTUSelection(token, 1200)); !errors.Is(err, ErrMTUMessage) {
		t.Fatal("unproven MTU selected")
	}
	wrong := token
	wrong[0]++
	for _, data := range [][]byte{nil, EncodeMTUSelection(wrong, 1100), EncodeMTUSelection(token, 1000), EncodeMTUSelection(token, 1500)} {
		if _, err := server.Commit(data); !errors.Is(err, ErrMTUMessage) {
			t.Fatal("invalid selection accepted")
		}
	}
	data, _ := EncodeMTUProbe(MTUProbe{Token: token, Sequence: 1, Size: 1200})
	if err := server.Echo(data, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Commit(EncodeMTUSelection(token, 1200)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Commit(EncodeMTUSelection(token, 1100)); !errors.Is(err, ErrMTUMessage) {
		t.Fatal("live MTU change accepted")
	}
	if err := server.Echo(data, func([]byte) error { t.Fatal("late probe echoed"); return nil }); !errors.Is(err, ErrMTUMessage) {
		t.Fatal("late probe accepted")
	}
}

func TestMTUResponderBoundsWork(t *testing.T) {
	for _, expired := range []bool{false, true} {
		server, err := NewMTUResponder(1400)
		if err != nil {
			t.Fatal(err)
		}
		if expired {
			server.expires = time.Now().Add(-time.Second)
		}
		data, _ := EncodeMTUProbe(MTUProbe{Token: server.token, Sequence: 1, Size: 1100})
		sends := 0
		for range maxMTUProbes + 2 {
			_ = server.Echo(data, func([]byte) error { sends++; return nil })
		}
		if (!expired && sends != maxMTUProbes) || (expired && sends != 0) {
			t.Fatalf("probe quota/expiry not enforced: sends %d, expired %v", sends, expired)
		}
		if _, err := server.Commit(EncodeMTUSelection(server.token, 1100)); err != nil {
			t.Fatalf("inconclusive discovery prevented baseline selection: %v", err)
		}
	}
}
