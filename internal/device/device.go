package device

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

type PacketDevice interface {
	// ReadPacket transfers ownership of the returned packet to the caller.
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
	Name() string
	Close() error
}

type readResult struct {
	packets [][]byte
	err     error
}

type Native struct {
	device       tun.Device
	name         string
	mtu          int
	read         sync.Mutex
	pending      [][]byte
	readErr      error
	readResults  chan readResult
	readDone     chan struct{}
	done         chan struct{}
	write        sync.Mutex
	writeBuffer  []byte
	writeBuffers [1][]byte
	closeOnce    sync.Once
	closeErr     error
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
	return newNative(dev, actualName, mtu), nil
}

func (n *Native) Name() string { return n.name }

func newNative(dev tun.Device, name string, mtu int) *Native {
	n := &Native{
		device:      dev,
		name:        name,
		mtu:         mtu,
		readResults: make(chan readResult),
		readDone:    make(chan struct{}),
		done:        make(chan struct{}),
		writeBuffer: make([]byte, packetOffset+mtu+256),
	}
	go n.readLoop()
	return n
}

func (n *Native) readLoop() {
	defer close(n.readDone)
	batchSize := n.device.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	buffers := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for index := range buffers {
		buffers[index] = make([]byte, packetOffset+n.mtu+256)
	}
	for {
		select {
		case <-n.done:
			return
		default:
		}
		count, err := n.device.Read(buffers, sizes, packetOffset)
		result := readResult{err: err}
		if err == nil {
			if count < 1 || count > len(buffers) {
				result.err = fmt.Errorf("TUN returned invalid packet count=%d", count)
			} else {
				result.packets = make([][]byte, count)
				for index := 0; index < count; index++ {
					if sizes[index] < 1 || sizes[index] > len(buffers[index])-packetOffset {
						result.err = fmt.Errorf("TUN returned invalid packet size=%d at index=%d", sizes[index], index)
						break
					}
					result.packets[index] = append(
						[]byte(nil),
						buffers[index][packetOffset:packetOffset+sizes[index]]...,
					)
				}
			}
		}
		select {
		case n.readResults <- result:
		case <-n.done:
			return
		}
		if result.err != nil {
			return
		}
	}
}

func (n *Native) ReadPacket(ctx context.Context) ([]byte, error) {
	n.read.Lock()
	defer n.read.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.done:
		return nil, os.ErrClosed
	default:
	}
	if n.readErr != nil {
		return nil, n.readErr
	}
	if len(n.pending) > 0 {
		packet := n.pending[0]
		n.pending[0] = nil
		n.pending = n.pending[1:]
		return packet, nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.done:
		return nil, os.ErrClosed
	case got := <-n.readResults:
		if got.err != nil {
			n.readErr = got.err
			return nil, got.err
		}
		n.pending = got.packets
		packet := n.pending[0]
		n.pending[0] = nil
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
	if len(packet) == 0 {
		return errors.New("cannot write an empty TUN packet")
	}
	if len(packet) > n.mtu {
		return fmt.Errorf("packet length %d exceeds TUN MTU %d", len(packet), n.mtu)
	}
	n.write.Lock()
	defer n.write.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.done:
		return os.ErrClosed
	default:
	}
	buffer := n.writeBuffer[:packetOffset+len(packet)]
	copy(buffer[packetOffset:], packet)
	n.writeBuffers[0] = buffer
	count, err := n.device.Write(n.writeBuffers[:], packetOffset)
	if err != nil {
		return err
	}
	if count <= 0 {
		return errors.New("TUN wrote no packets")
	}
	return nil
}

func (n *Native) Close() error {
	n.closeOnce.Do(func() {
		close(n.done)
		n.closeErr = n.device.Close()
		<-n.readDone
	})
	return n.closeErr
}
