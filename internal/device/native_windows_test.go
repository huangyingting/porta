package device

import (
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

type testWintunSession struct {
	wait      windows.Handle
	allocate  error
	packet    []byte
	read      chan struct{}
	ended     atomic.Int32
	released  atomic.Int32
	submitted atomic.Int32
}

func (s *testWintunSession) ReceivePacket() ([]byte, error) {
	select {
	case s.read <- struct{}{}:
	default:
	}
	if s.packet != nil {
		return s.packet, nil
	}
	return nil, windows.ERROR_NO_MORE_ITEMS
}
func (s *testWintunSession) ReleaseReceivePacket([]byte) { s.released.Add(1) }
func (s *testWintunSession) AllocateSendPacket(size int) ([]byte, error) {
	if s.allocate != nil {
		return nil, s.allocate
	}
	return make([]byte, size), nil
}
func (s *testWintunSession) SendPacket([]byte)             { s.submitted.Add(1) }
func (s *testWintunSession) ReadWaitEvent() windows.Handle { return s.wait }
func (s *testWintunSession) End()                          { s.ended.Add(1) }

type testWintunAdapter struct{ closed atomic.Int32 }

func (a *testWintunAdapter) Close() error { a.closed.Add(1); return nil }

func newTestWindowsTUN(t *testing.T) (*windowsTUN, *testWintunSession, *testWintunAdapter) {
	t.Helper()
	wait, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(wait) })
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	session := &testWintunSession{wait: wait, read: make(chan struct{}, 1)}
	adapter := &testWintunAdapter{}
	dev := &windowsTUN{session: session, adapter: adapter, name: "test", mtu: 1280, stop: stop, events: make(chan tun.Event)}
	t.Cleanup(func() {
		if err := dev.Close(); err != nil {
			t.Error(err)
		}
	})
	return dev, session, adapter
}

func TestWindowsTUNReportsRingDropWithoutSubmission(t *testing.T) {
	dev, session, _ := newTestWindowsTUN(t)
	session.allocate = windows.ERROR_BUFFER_OVERFLOW
	if count, err := dev.Write([][]byte{{1, 2}}, 0); count != 0 || !errors.Is(err, ErrPacketDropped) {
		t.Fatalf("full ring write = %d, %v", count, err)
	}
	if session.submitted.Load() != 0 {
		t.Fatal("full-ring packet was submitted")
	}
	session.allocate = nil
	if count, err := dev.Write([][]byte{{1, 2}}, 0); count != 1 || err != nil {
		t.Fatalf("recovered ring write = %d, %v", count, err)
	}
	if session.submitted.Load() != 1 {
		t.Fatal("accepted packet was not submitted")
	}
}

func TestWindowsTUNCloseWakesAndDrainsReader(t *testing.T) {
	dev, session, adapter := newTestWindowsTUN(t)
	read := make(chan error, 1)
	go func() {
		_, err := dev.Read([][]byte{make([]byte, 1280)}, make([]int, 1), 0)
		read <- err
	}()
	select {
	case <-session.read:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not start")
	}
	for range 2 {
		if err := dev.Close(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-read:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("closed read = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not wake reader")
	}
	if session.ended.Load() != 1 || adapter.closed.Load() != 1 {
		t.Fatal("native resources were not closed exactly once")
	}
	if _, err := dev.Write([][]byte{{1}}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after session destruction = %v", err)
	}
}

func TestWindowsTUNRejectsTruncationAndReleasesPacket(t *testing.T) {
	dev, session, _ := newTestWindowsTUN(t)
	session.packet = make([]byte, 64)
	if _, err := dev.Read([][]byte{make([]byte, 20)}, make([]int, 1), 0); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("oversized packet = %v", err)
	}
	if session.released.Load() != 1 {
		t.Fatal("oversized receive packet was not released")
	}
}
