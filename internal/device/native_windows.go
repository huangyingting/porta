package device

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/tun"
)

type wintunSession interface {
	ReceivePacket() ([]byte, error)
	ReleaseReceivePacket([]byte)
	AllocateSendPacket(int) ([]byte, error)
	SendPacket([]byte)
	ReadWaitEvent() windows.Handle
	End()
}

// Use the session API because wireguard/tun reports full-ring drops as writes.
type windowsTUN struct {
	session   wintunSession
	adapter   io.Closer
	name      string
	mtu       int
	stop      windows.Handle
	events    chan tun.Event
	running   sync.RWMutex
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func createNativeTUN(name string, mtu int) (tun.Device, error) {
	adapter, err := wintun.CreateAdapter(name, tun.WintunTunnelType, tun.WintunStaticRequestedGUID)
	if err != nil {
		return nil, err
	}
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		return nil, errors.Join(err, adapter.Close())
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		session.End()
		return nil, errors.Join(err, adapter.Close())
	}
	return &windowsTUN{
		session: session, adapter: adapter, name: name, mtu: mtu,
		stop: stop, events: make(chan tun.Event),
	}, nil
}

func (t *windowsTUN) File() *os.File           { return nil }
func (t *windowsTUN) Name() (string, error)    { return t.name, nil }
func (t *windowsTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *windowsTUN) Events() <-chan tun.Event { return t.events }
func (t *windowsTUN) BatchSize() int           { return 1 }

func (t *windowsTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	t.running.RLock()
	defer t.running.RUnlock()
	if len(buffers) == 0 || len(sizes) == 0 || offset < 0 || offset > len(buffers[0]) {
		return 0, io.ErrShortBuffer
	}
	for {
		if t.closed.Load() {
			return 0, os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch {
		case err == nil:
			size := len(packet)
			if size <= len(buffers[0])-offset {
				copy(buffers[0][offset:], packet)
			}
			t.session.ReleaseReceivePacket(packet)
			if size > len(buffers[0])-offset {
				return 0, io.ErrShortBuffer
			}
			sizes[0] = size
			return 1, nil
		case errors.Is(err, windows.ERROR_NO_MORE_ITEMS):
			// The finite wait also bounds shutdown if signaling the stop event fails.
			_, err = windows.WaitForMultipleObjects([]windows.Handle{t.stop, t.session.ReadWaitEvent()}, false, 1000)
			if err != nil {
				return 0, fmt.Errorf("wait for Wintun packet: %w", err)
			}
		case errors.Is(err, windows.ERROR_HANDLE_EOF):
			return 0, os.ErrClosed
		default:
			return 0, fmt.Errorf("read Wintun packet: %w", err)
		}
	}
}

func (t *windowsTUN) Write(buffers [][]byte, offset int) (int, error) {
	t.running.RLock()
	defer t.running.RUnlock()
	if t.closed.Load() {
		return 0, os.ErrClosed
	}
	for index, buffer := range buffers {
		if offset < 0 || offset >= len(buffer) {
			return index, io.ErrShortBuffer
		}
		packet, err := t.session.AllocateSendPacket(len(buffer) - offset)
		switch {
		case err == nil:
			copy(packet, buffer[offset:])
			t.session.SendPacket(packet)
		case errors.Is(err, windows.ERROR_BUFFER_OVERFLOW):
			return index, ErrPacketDropped
		case errors.Is(err, windows.ERROR_HANDLE_EOF):
			return index, os.ErrClosed
		default:
			return index, fmt.Errorf("write Wintun packet: %w", err)
		}
	}
	return len(buffers), nil
}

func (t *windowsTUN) Close() error {
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		t.closeErr = windows.SetEvent(t.stop)
		t.running.Lock()
		defer t.running.Unlock()
		t.session.End()
		t.closeErr = errors.Join(t.closeErr, t.adapter.Close(), windows.CloseHandle(t.stop))
		close(t.events)
	})
	return t.closeErr
}
