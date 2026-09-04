package clientapp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/device"
	"github.com/huangyingting/porta/internal/tunnel"
)

type testDevice struct {
	readStarted chan struct{}
	readExited  atomic.Bool
	closed      atomic.Bool
	read        func(context.Context) ([]byte, error)
}

func (d *testDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	close(d.readStarted)
	defer d.readExited.Store(true)
	if d.read != nil {
		return d.read(ctx)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*testDevice) WritePacket(ctx context.Context, packet []byte) error { return ctx.Err() }
func (*testDevice) Name() string                                         { return "actual-device" }
func (d *testDevice) Close() error                                       { d.closed.Store(true); return nil }

type testConnection struct {
	closed    chan struct{}
	closeOnce sync.Once
	receive   func() ([]byte, error)
	send      func([]byte) error
}

func (c *testConnection) Send(packet []byte) error {
	if c.send != nil {
		return c.send(packet)
	}
	return nil
}
func (c *testConnection) Receive() ([]byte, error) {
	if c.receive != nil {
		return c.receive()
	}
	<-c.closed
	return nil, io.EOF
}
func (c *testConnection) Close() error { c.closeOnce.Do(func() { close(c.closed) }); return nil }

type testNetwork struct {
	up   func(context.Context, string) error
	down func(context.Context) error
}

func (n testNetwork) Up(ctx context.Context, name string, _ net.Addr, _ tunnel.Lease) error {
	return n.up(ctx, name)
}
func (n testNetwork) Down(ctx context.Context) error { return n.down(ctx) }

func runTestClient(ctx context.Context, config Config, observer Observer, connection *testConnection, tunDevice *testDevice) error {
	config.ServerURL = "https://gateway.example"
	config.Token = "token"
	return run(ctx, config, observer,
		func(context.Context, tunnel.Config) (*clientConnection, error) {
			return &clientConnection{packetConnection: connection, lease: tunnel.Lease{MTU: 1280}}, nil
		},
		func(string, int) (device.PacketDevice, error) { return tunDevice, nil })
}

func TestRunCleansUpFailedNetworkSetup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanupFailure := errors.New("cleanup failed")
	downCalled := false
	config := Config{Network: testNetwork{
		up: func(ctx context.Context, name string) error {
			if name != "actual-device" {
				t.Errorf("configured %q instead of actual device name", name)
			}
			cancel()
			return context.Canceled
		},
		down: func(ctx context.Context) error {
			downCalled = true
			if ctx.Err() != nil {
				t.Error("cleanup inherited canceled context")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("cleanup has no deadline")
			}
			return cleanupFailure
		},
	}}
	connection := &testConnection{closed: make(chan struct{})}
	tunDevice := &testDevice{readStarted: make(chan struct{})}
	var events []State
	err := runTestClient(ctx, config, func(event Event) { events = append(events, event.State) }, connection, tunDevice)
	if !downCalled || !errors.Is(err, cleanupFailure) || errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup failure was hidden: called=%t error=%v", downCalled, err)
	}
	if !tunDevice.closed.Load() {
		t.Fatal("device left open")
	}
	select {
	case <-connection.closed:
	default:
		t.Fatal("connection left open")
	}
	if events[len(events)-1] != StateDisconnected {
		t.Fatalf("cancel events: %v", events)
	}
}

func TestRunStopsDeviceReaderWithoutCancelingCaller(t *testing.T) {
	tunDevice := &testDevice{readStarted: make(chan struct{})}
	connection := &testConnection{closed: make(chan struct{})}
	connection.receive = func() ([]byte, error) {
		<-tunDevice.readStarted
		return nil, io.EOF
	}
	result := make(chan error, 1)
	go func() { result <- runTestClient(context.Background(), Config{}, nil, connection, tunDevice) }()
	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not finish")
	}
	if !tunDevice.readExited.Load() {
		t.Fatal("Run returned with a live device reader")
	}
}

func TestRunConnectionJoinsBlockedPumps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connection := &testConnection{closed: make(chan struct{})}
	sendStarted, receiveStarted := make(chan struct{}), make(chan struct{})
	var sendExited, receiveExited atomic.Bool
	connection.send = func([]byte) error {
		close(sendStarted)
		<-connection.closed
		sendExited.Store(true)
		return io.EOF
	}
	connection.receive = func() ([]byte, error) {
		close(receiveStarted)
		<-connection.closed
		receiveExited.Store(true)
		return nil, io.EOF
	}
	outbound := make(chan []byte, 1)
	outbound <- []byte{1}
	result := make(chan error, 1)
	go func() { result <- runConnection(ctx, &testDevice{}, connection, outbound, nil, &counters{}, nil) }()
	<-sendStarted
	<-receiveStarted
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked connection pumps did not stop")
	}
	if !sendExited.Load() || !receiveExited.Load() {
		t.Fatal("returned before both connection pumps stopped")
	}
}

func TestRunTrafficEventsFinishBeforeReturn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tunDevice := &testDevice{readStarted: make(chan struct{})}
	connection := &testConnection{closed: make(chan struct{})}
	var states []State
	var callbacks atomic.Int32
	connectedEvents := 0
	observer := func(event Event) {
		if callbacks.Add(1) != 1 {
			t.Error("concurrent observer callbacks")
		}
		defer callbacks.Add(-1)
		states = append(states, event.State)
		if event.State == StateConnected {
			connectedEvents++
			if connectedEvents == 2 {
				cancel()
			}
		}
	}
	result := make(chan error, 1)
	go func() { result <- runTestClient(ctx, Config{}, observer, connection, tunDevice) }()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no periodic traffic event")
	}
	if callbacks.Load() != 0 || states[len(states)-1] != StateDisconnected {
		t.Fatalf("unfinished events: %v", states)
	}
}

func TestReconnectDelayBounds(t *testing.T) {
	for _, test := range []struct {
		failures      int
		maximum, want time.Duration
	}{
		{-1, 30 * time.Second, time.Second},
		{100, 5 * time.Second, 5 * time.Second},
		{0, 0, time.Second},
	} {
		if got := ReconnectDelay(test.failures, test.maximum); got != test.want {
			t.Errorf("ReconnectDelay(%d, %s)=%s, want %s", test.failures, test.maximum, got, test.want)
		}
	}

}

func TestRunStopsReconnectingWhenDeviceFails(t *testing.T) {
	failRead := make(chan struct{})
	deviceFailure := errors.New("device disconnected")
	tunDevice := &testDevice{readStarted: make(chan struct{}), read: func(ctx context.Context) ([]byte, error) {
		select {
		case <-failRead:
			return nil, deviceFailure
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	connection := &testConnection{closed: make(chan struct{})}
	connection.receive = func() ([]byte, error) {
		<-tunDevice.readStarted
		return nil, io.EOF
	}
	var states []State
	observer := func(event Event) {
		states = append(states, event.State)
		if event.State == StateReconnecting {
			select {
			case <-failRead:
			default:
				close(failRead)
			}
		}
	}
	result := make(chan error, 1)
	go func() {
		result <- runTestClient(context.Background(), Config{Reconnect: true}, observer, connection, tunDevice)
	}()
	select {
	case err := <-result:
		if !errors.Is(err, deviceFailure) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect ignored device failure")
	}
	if states[len(states)-1] != StateError {
		t.Fatalf("device failure events: %v", states)
	}
}
