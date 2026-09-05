package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/usage"
)

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
