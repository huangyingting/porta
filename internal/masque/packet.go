package masque

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

type FeedbackDecision struct {
	SendICMP   bool
	UseCapsule bool
}

type feedbackFlow struct {
	key      protocol.FlowKey
	mtu      int
	lastSeen time.Time
	first    time.Time
	attempts int
}

type FeedbackPolicy struct {
	flows []feedbackFlow
	last  time.Time
}

// Oversized only accepts validated DF packets for which ICMP is permitted.
// Small packets must not reset a flow's convergence state.
func (p *FeedbackPolicy) Oversized(packet []byte, mtu, ceiling int, now time.Time, rtt time.Duration) FeedbackDecision {
	if len(packet) <= mtu || mtu < 68 {
		return FeedbackDecision{}
	}
	retained := p.flows[:0]
	for _, flow := range p.flows {
		if now.Sub(flow.lastSeen) < time.Minute {
			retained = append(retained, flow)
		}
	}
	p.flows = retained
	key := protocol.ClassifyIPv4(packet).Flow
	index := -1
	for i := range p.flows {
		if p.flows[i].key == key {
			index = i
			break
		}
	}
	if index < 0 {
		if len(p.flows) == 128 {
			oldest := 0
			for i := 1; i < len(p.flows); i++ {
				if p.flows[i].lastSeen.Before(p.flows[oldest].lastSeen) {
					oldest = i
				}
			}
			p.flows = append(p.flows[:oldest], p.flows[oldest+1:]...)
		}
		p.flows = append(p.flows, feedbackFlow{key: key, mtu: mtu})
		index = len(p.flows) - 1
	}
	flow := &p.flows[index]
	if mtu < flow.mtu {
		*flow = feedbackFlow{key: key, mtu: mtu}
	}
	flow.lastSeen = now
	// Clamp before multiplying to avoid overflowing a duration.
	grace := max(2*time.Second, min(rtt, 2500*time.Millisecond)*4)
	if len(packet) <= ceiling && flow.attempts >= 3 && now.Sub(flow.first) >= grace {
		return FeedbackDecision{UseCapsule: true}
	}
	if !p.last.IsZero() && now.Sub(p.last) < 100*time.Millisecond {
		return FeedbackDecision{}
	}
	p.last = now
	if flow.attempts == 0 {
		flow.first = now
	}
	flow.attempts = min(flow.attempts+1, 3)
	return FeedbackDecision{SendICMP: true}
}

// IPDatagramCapacity accepts quic-go's raw QUIC payload limit. Its HTTP/3
// wrapper returns that limit unchanged, including the quarter-stream-ID.
func IPDatagramCapacity(capacity int64, streamID uint64) int {
	overhead := int64(quicvarint.Len(streamID/4) + 1)
	if capacity <= overhead {
		return 0
	}
	return int(min(capacity-overhead, int64(protocol.MaxPacket)))
}

type PacketStats struct {
	DatagramPackets, DatagramBytes uint64
	CapsulePackets, CapsuleBytes   uint64
	Reductions, Retries, Fallbacks uint64
}

// PacketWriter is owned by one sending worker. The interface ceiling never
// changes; a TooLarge rejection lowers the separate budget before retrying.
type PacketWriter struct {
	Ceiling      int
	StreamID     uint64
	Gateway      netip.Addr
	Subnet       netip.Prefix
	Datagram     func([]byte) error
	Capsule      func([]byte) error
	ICMP         func([]byte) error
	RTT          func() time.Duration
	Action       func(string)
	Reduced      func(int, int)
	Fallback     func(string)
	Stats        PacketStats
	limit        int
	feedback     FeedbackPolicy
	fallbackSeen map[string]bool
}

func (w *PacketWriter) Limit() int {
	if w.limit == 0 {
		return w.Ceiling
	}
	return w.limit
}

func (w *PacketWriter) action(action string) {
	if w.Action != nil {
		w.Action(action)
	}
}

func (w *PacketWriter) capsule(packet []byte, reason string) error {
	if len(packet) > w.Ceiling {
		return fmt.Errorf("capsule packet exceeds negotiated MTU %d", w.Ceiling)
	}
	if err := w.Capsule(packet); err != nil {
		return err
	}
	w.Stats.CapsulePackets++
	w.Stats.CapsuleBytes += uint64(len(packet))
	if reason != "" {
		w.Stats.Fallbacks++
		if w.fallbackSeen == nil {
			w.fallbackSeen = make(map[string]bool)
		}
		if !w.fallbackSeen[reason] {
			w.fallbackSeen[reason] = true
			if w.Fallback != nil {
				w.Fallback(reason)
			}
		}
		if reason == "nonconverging_df" {
			w.action("compatibility")
		}
	}
	return nil
}

func (w *PacketWriter) Send(ctx context.Context, packet []byte) error {
	return w.sendAt(ctx, packet, time.Now())
}

func (w *PacketWriter) sendAt(ctx context.Context, packet []byte, now time.Time) error {
	if w.Ceiling < 68 || w.Ceiling > protocol.MaxPacket {
		return protocol.ErrInvalidMTU
	}
	var pending [][]byte
	retries := 0
	for packet != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		limit := w.Ceiling
		if w.Datagram != nil {
			limit = w.Limit()
		}
		if len(packet) > limit {
			fragments, err := protocol.FragmentIPv4(packet, limit)
			switch {
			case err == nil:
				w.action("fragmented")
				pending = append(fragments[1:], pending...)
				packet = fragments[0]
				continue
			case errors.Is(err, protocol.ErrFragmentationNeeded):
				if !w.Gateway.IsValid() && len(packet) <= w.Ceiling && w.Datagram != nil {
					if err := w.capsule(packet, "missing_gateway"); err != nil {
						return err
					}
					break
				}
				reply, err := protocol.ICMPFragmentationNeeded(packet, w.Gateway, limit, w.Subnet)
				if errors.Is(err, protocol.ErrICMPSuppressed) {
					w.action("icmp_suppressed")
					break
				}
				if err != nil {
					return err
				}
				var rtt time.Duration
				if w.RTT != nil {
					rtt = w.RTT()
				}
				decision := w.feedback.Oversized(packet, limit, w.Ceiling, now, rtt)
				if decision.SendICMP {
					if err := w.ICMP(reply); err != nil {
						return err
					}
					w.action("icmp_sent")
				} else if decision.UseCapsule && w.Datagram != nil {
					if err := w.capsule(packet, "nonconverging_df"); err != nil {
						return err
					}
				} else {
					w.action("icmp_rate_limited")
				}
			default:
				return err
			}
		} else if w.Datagram == nil {
			if err := w.capsule(packet, ""); err != nil {
				return err
			}
		} else {
			err := w.Datagram(EncodeIPPacket(packet))
			var tooLarge *quic.DatagramTooLargeError
			switch {
			case err == nil:
				w.Stats.DatagramPackets++
				w.Stats.DatagramBytes += uint64(len(packet))
				w.action("datagram_queued")
			case errors.As(err, &tooLarge):
				capacity := IPDatagramCapacity(tooLarge.MaxDatagramPayloadSize, w.StreamID)
				if capacity < 68 {
					return fmt.Errorf("unusable HTTP/3 IP capacity %d: %w", capacity, protocol.ErrInvalidMTU)
				}
				if retries >= 4 || capacity >= w.Limit() {
					return fmt.Errorf("HTTP/3 datagram capacity did not converge: %w", err)
				}
				previous := w.Limit()
				w.limit = capacity
				w.Stats.Reductions++
				w.Stats.Retries++
				retries++
				if w.Reduced != nil {
					w.Reduced(previous, capacity)
				}
				continue
			case err.Error() == "datagram support disabled":
				// quic-go exposes no sentinel for this specific availability error.
				w.Datagram = nil
				if err := w.capsule(packet, "not_available"); err != nil {
					return err
				}
			default:
				return err
			}
		}
		if len(pending) == 0 {
			break
		}
		packet, pending = pending[0], pending[1:]
	}
	return nil
}
