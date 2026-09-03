package device

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

type PacketDevice interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
	Name() string
	Close() error
}

type Native struct {
	device tun.Device
	name   string
	mtu    int
	write  sync.Mutex
}

func OpenNative(name string, mtu int) (*Native, error) {
	if name == "" {
		return nil, errors.New("TUN interface name is required")
	}
	if mtu < 576 || mtu > 9000 {
		return nil, fmt.Errorf("MTU %d is outside 576..9000", mtu)
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w", name, err)
	}
	actualName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("read TUN name: %w", err)
	}
	return &Native{device: dev, name: actualName, mtu: mtu}, nil
}

func (n *Native) Name() string { return n.name }

func (n *Native) ReadPacket(ctx context.Context) ([]byte, error) {
	buffer := make([]byte, n.mtu+256)
	packets := [][]byte{buffer}
	sizes := make([]int, 1)
	type result struct {
		count int
		err   error
	}
	completed := make(chan result, 1)
	go func() {
		count, err := n.device.Read(packets, sizes, 0)
		completed <- result{count: count, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got := <-completed:
		if got.err != nil {
			return nil, got.err
		}
		if got.count < 1 || sizes[0] < 1 || sizes[0] > len(buffer) {
			return nil, fmt.Errorf("TUN returned invalid packet count=%d size=%d", got.count, sizes[0])
		}
		packet := make([]byte, sizes[0])
		copy(packet, buffer[:sizes[0]])
		return packet, nil
	}
}

func (n *Native) WritePacket(ctx context.Context, packet []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	n.write.Lock()
	defer n.write.Unlock()
	count, err := n.device.Write([][]byte{packet}, 0)
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("TUN wrote %d packets, want 1", count)
	}
	return nil
}

func (n *Native) Close() error { return n.device.Close() }
