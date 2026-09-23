package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/usage"
	"github.com/quic-go/quic-go"
)

func (c *masqueSession) newPacketWriter(ctx context.Context, lease Lease, usageSession *usage.Session, connection *quic.Conn) *masque.PacketWriter {
	account := func(size int) {
		c.Metrics.sentToClient()
		usageSession.AddDownloaded(uint64(size), 1)
	}
	packets := &masque.PacketWriter{
		Ceiling: c.packetMTU(), Gateway: lease.Gateway, Subnet: lease.Prefix().Masked(),
		Capsule: func(packet []byte) error {
			size := len(packet)
			return c.reliable.Packet(packet, func() { account(size) })
		},
		ICMP: func(reply []byte) error { return c.Router.injectValidated(ctx, reply) },
		Action: func(action string) {
			switch action {
			case "fragmented":
				c.Metrics.mtuFragmented.Add(1)
			case "icmp_sent":
				c.Metrics.mtuICMPSent.Add(1)
			case "icmp_suppressed":
				c.Metrics.mtuICMPSuppressed.Add(1)
			case "icmp_rate_limited":
				c.Metrics.mtuICMPRateLimited.Add(1)
			case "compatibility":
				c.Metrics.mtuCompatibility.Add(1)
			}
		},
		Reduced: func(previous, current int) {
			c.Metrics.mtuLiveReductions.Add(1)
			c.Logger.Warn("HTTP/3 live packet budget reduced", "previous", previous, "packet_budget", current, "mtu", c.packetMTU())
		},
		Fallback: func(reason string) { c.Logger.Warn("HTTP/3 compatibility capsules enabled", "reason", reason) },
	}
	if connection != nil {
		packets.RTT = func() time.Duration { return connection.ConnectionStats().SmoothedRTT }
	}
	if c.sendDatagram != nil {
		packets.Datagram = func(value []byte) error {
			err := c.sendDatagram(value)
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				c.Metrics.DatagramOversize()
			}
			if err == nil {
				account(len(value) - 1)
			}
			return err
		}
	}
	return packets
}

func (c *masqueSession) sendDownlink(ctx context.Context, lease Lease, packet []byte, send func([]byte) error, usageSession *usage.Session) error {
	sendPacket := func(packet []byte) error {
		if err := send(packet); err != nil {
			return err
		}
		c.Metrics.sentToClient()
		usageSession.AddDownloaded(uint64(len(packet)), 1)
		return nil
	}
	mtu := c.packetMTU()
	if len(packet) <= mtu {
		return sendPacket(packet)
	}
	fragments, err := protocol.FragmentIPv4(packet, mtu)
	if errors.Is(err, protocol.ErrInvalidIPv4Packet) {
		c.Metrics.invalidTUNDrops.Add(1)
		c.Logger.Warn("dropping invalid oversized packet from gateway TUN", "error", err)
		return nil
	}
	if errors.Is(err, protocol.ErrFragmentationNeeded) {
		reply, err := protocol.ICMPFragmentationNeeded(packet, lease.Gateway, mtu, lease.Prefix().Masked())
		if errors.Is(err, protocol.ErrICMPSuppressed) {
			c.Metrics.mtuICMPSuppressed.Add(1)
			return nil
		}
		if err != nil {
			return fmt.Errorf("construct fragmentation-needed response: %w", err)
		}
		now := time.Now()
		if now.Before(c.icmpAfter) {
			c.Metrics.mtuICMPRateLimited.Add(1)
			return nil
		}
		c.icmpAfter = now.Add(100 * time.Millisecond)
		if err := c.Router.injectValidated(ctx, reply); err != nil {
			return fmt.Errorf("write fragmentation-needed response: %w", err)
		}
		c.Metrics.mtuICMPSent.Add(1)
		return nil
	}
	if err != nil {
		return fmt.Errorf("fragment downlink packet: %w", err)
	}
	c.Metrics.mtuFragmented.Add(1)
	for _, fragment := range fragments {
		if err := sendPacket(fragment); err != nil {
			return err
		}
	}
	return nil
}
