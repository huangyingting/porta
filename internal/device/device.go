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
	device  tun.Device
	name    string
	mtu     int
	read    sync.Mutex
	pending [][]byte
	buffers [][]byte
	sizes   []int
	write   sync.Mutex
}

const packetOffset = 16

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
	n.read.Lock()
	defer n.read.Unlock()
	if len(n.pending) > 0 {
		packet := n.pending[0]
		n.pending = n.pending[1:]
		return packet, nil
	}

	batchSize := n.device.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	if len(n.buffers) != batchSize {
		n.buffers = make([][]byte, batchSize)
		n.sizes = make([]int, batchSize)
		for index := range n.buffers {
			n.buffers[index] = make([]byte, packetOffset+n.mtu+256)
		}
	}
	type result struct {
		count int
		err   error
	}
	completed := make(chan result, 1)
	go func() {
		count, err := n.device.Read(n.buffers, n.sizes, packetOffset)
		completed <- result{count: count, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got := <-completed:
		if got.err != nil {
			return nil, got.err
		}
		if got.count < 1 || got.count > len(n.buffers) {
			return nil, fmt.Errorf("TUN returned invalid packet count=%d", got.count)
		}
		for index := 0; index < got.count; index++ {
			if n.sizes[index] < 1 || n.sizes[index] > len(n.buffers[index])-packetOffset {
				return nil, fmt.Errorf("TUN returned invalid packet size=%d at index=%d", n.sizes[index], index)
			}
			packet := make([]byte, n.sizes[index])
			copy(packet, n.buffers[index][packetOffset:packetOffset+n.sizes[index]])
			n.pending = append(n.pending, packet)
		}
		packet := n.pending[0]
		n.pending = n.pending[1:]
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
	buffer := make([]byte, packetOffset+len(packet))
	copy(buffer[packetOffset:], packet)
	count, err := n.device.Write([][]byte{buffer}, packetOffset)
	if err != nil {
		return err
	}
	if count <= 0 {
		return errors.New("TUN wrote no packets")
	}
	return nil
}

func (n *Native) Close() error { return n.device.Close() }
