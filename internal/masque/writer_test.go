package masque

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestReliableWriterDeadlineIncludesQueueAndClosesBlockedWrite(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	writer := NewReliableWriter(context.Background(), NewEncoder(left), left.SetWriteDeadline, func() { _ = left.Close() }, 100*time.Millisecond)
	started := time.Now()
	for i := range 10 {
		if err := writer.Packet(make([]byte, 9000), nil); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	select {
	case <-writer.Done():
		if !errors.Is(writer.Err(), ErrWriterTimeout) {
			t.Fatal(writer.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write did not terminate")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("deadline was applied separately for each queued command")
	}
	_ = writer.Close()
	if writer.controlUsed != 0 || writer.dataUsed != 0 {
		t.Fatal("closed writer retained pending bytes")
	}
}

func TestReliableWriterIncludesInflightBytesAndReservesControlQueue(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	writer := NewReliableWriter(ctx, NewEncoder(left), left.SetWriteDeadline, func() { _ = left.Close() }, time.Second)
	defer writer.Close()
	defer cancel()
	for range 4 {
		if err := writer.Packet(make([]byte, 60<<10), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Packet(make([]byte, 30<<10), nil); !errors.Is(err, ErrWriterOverloaded) {
		t.Fatalf("in-flight bytes excluded from data budget: %v", err)
	}
	if err := writer.Control(CapsuleMTUSelected, []byte{1}, nil); err != nil {
		t.Fatalf("data saturation prevented control enqueue: %v", err)
	}
	cancel()
	select {
	case <-writer.Done():
	case <-time.After(time.Second):
		t.Fatal("cancel did not drain writer")
	}
}

func TestReliableWriterPreservesControlOrderAndBarrier(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	writer := NewReliableWriter(context.Background(), NewEncoder(left), left.SetWriteDeadline, func() { _ = left.Close() }, time.Second)
	defer writer.Close()
	ready := make(chan struct{})
	for _, kind := range []uint64{CapsuleMTUSelected, CapsuleAddressAssign, CapsuleRouteAdvertisement} {
		var done func()
		if kind == CapsuleRouteAdvertisement {
			done = func() { close(ready) }
		}
		if err := writer.Control(kind, []byte{1}, done); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ready:
		t.Fatal("assignment barrier passed before write")
	default:
	}
	decoder := NewDecoder(right)
	for _, kind := range []uint64{CapsuleMTUSelected, CapsuleAddressAssign, CapsuleRouteAdvertisement} {
		capsule, err := decoder.Read()
		if err != nil || capsule.Type != kind {
			t.Fatalf("control order: %+v %v", capsule, err)
		}
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("barrier did not pass after control writes")
	}
}

func TestBoundedDatagramSendAbortsConnectionAndJoinsDeadline(t *testing.T) {
	released := make(chan struct{})
	var once sync.Once
	send := BoundedDatagramSend(context.Background(), func([]byte) error { <-released; return net.ErrClosed },
		func() { once.Do(func() { close(released) }) }, 20*time.Millisecond)
	if err := send(nil); !errors.Is(err, ErrDatagramTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked datagram error: %v", err)
	}
}

func TestBoundedDatagramCancellationOnlyAbortsAnActiveSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started, released := make(chan struct{}), make(chan struct{})
	var once sync.Once
	send := BoundedDatagramSend(ctx, func([]byte) error {
		close(started)
		<-released
		return net.ErrClosed
	}, func() { once.Do(func() { close(released) }) }, time.Hour)
	done := make(chan error, 1)
	go func() { done <- send(nil) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("session cancellation did not unblock datagram queue")
	}
	idle, stop := context.WithCancel(context.Background())
	send = BoundedDatagramSend(idle, func([]byte) error { return nil }, func() { t.Error("idle sibling streams were closed") }, time.Second)
	if err := send(nil); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := send(nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled sender accepted work")
	}
}
