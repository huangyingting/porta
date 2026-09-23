package clientapp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/clientid"
	"github.com/huangyingting/porta/internal/device"
	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/tunnel"
)

type testDevice struct {
	readStarted chan struct{}
	readExited  atomic.Bool
	closed      atomic.Bool
	read        func(context.Context) ([]byte, error)
	write       func(context.Context, []byte) error
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
func (d *testDevice) WritePacket(ctx context.Context, packet []byte) error {
	if d.write != nil {
		return d.write(ctx, packet)
	}
	return ctx.Err()
}
func (*testDevice) Name() string   { return "actual-device" }
func (d *testDevice) Close() error { d.closed.Store(true); return nil }

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

var testClientIdentity = func() *clientid.Identity {
	key, err := deviceauth.GenerateKey()
	if err != nil {
		panic(err)
	}
	identity, err := clientid.New(key, "Office-PC")
	if err != nil {
		panic(err)
	}
	return identity
}()

func testIdentity() (*clientid.Identity, error) {
	return testClientIdentity, nil
}

func runTestClient(ctx context.Context, config Config, observer Observer, connection *testConnection, tunDevice *testDevice) error {
	config.ServerURL = "https://gateway.example"
	config.Token = "token"
	return run(ctx, testIdentity, config, observer,
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
	lease := tunnel.Lease{Address: netip.MustParsePrefix("10.0.0.2/24"), MTU: 1280}
	outbound <- clientTestPacket(lease.Address.Addr(), 64)
	result := make(chan error, 1)
	go func() {
		result <- runConnection(ctx, &testDevice{}, connection, lease, nil, outbound, nil, &counters{}, nil)
	}()
	for _, started := range []<-chan struct{}{sendStarted, receiveStarted} {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("connection pump did not start")
		}
	}
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

func TestRunConnectionDropsStalePacketsAndFullRingWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lease := tunnel.Lease{Address: netip.MustParsePrefix("10.0.0.2/24"), MTU: 1280}
	valid := clientTestPacket(lease.Address.Addr(), 64)
	outbound := make(chan []byte, 4)
	outbound <- []byte{1}
	outbound <- clientTestPacket(netip.MustParseAddr("10.0.0.3"), 64)
	outbound <- clientTestPacket(lease.Address.Addr(), lease.MTU+1)
	outbound <- valid
	sent, written := make(chan struct{}), make(chan struct{})
	connection := &testConnection{closed: make(chan struct{})}
	connection.send = func(packet []byte) error {
		if !bytes.Equal(packet, valid) {
			t.Error("stale or malformed packet reached the transport")
		}
		close(sent)
		return nil
	}
	received := 0
	connection.receive = func() ([]byte, error) {
		received++
		if received <= 2 {
			return valid, nil
		}
		<-connection.closed
		return nil, io.EOF
	}
	writes := 0
	tunDevice := &testDevice{write: func(context.Context, []byte) error {
		writes++
		if writes == 1 {
			return device.ErrPacketDropped
		}
		close(written)
		return nil
	}}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	totals := &counters{}
	result := make(chan error, 1)
	go func() {
		result <- runConnection(ctx, tunDevice, connection, lease, logger, outbound, nil, totals, nil)
	}()
	for _, ready := range []<-chan struct{}{sent, written} {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("packet drop interrupted the active connection")
		}
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("session error = %v", err)
	}
	if totals.packetsUploaded.Load() != 1 || totals.bytesUploaded.Load() != uint64(len(valid)) ||
		totals.packetsDownloaded.Load() != 1 || totals.bytesDownloaded.Load() != uint64(len(valid)) {
		t.Fatal("dropped packets were counted as accepted traffic")
	}
	if !bytes.Contains(logs.Bytes(), []byte("packets_dropped=3")) || !bytes.Contains(logs.Bytes(), []byte("packets_dropped=1")) {
		t.Fatal("packet drop summaries missing")
	}
}

func clientTestPacket(source netip.Addr, size int) []byte {
	packet := make([]byte, size)
	packet[0], packet[8] = 0x45, 64
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], netip.MustParseAddr("10.0.0.1").AsSlice())
	var sum uint32
	for index := 0; index < 20; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[index : index+2]))
	}
	sum = sum&0xffff + sum>>16
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	return packet
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

func TestDeviceReaderOwnsCancellationAndJoinsWithoutClosingDevice(t *testing.T) {
	tunDevice := &testDevice{readStarted: make(chan struct{})}
	reader := startDeviceReader(context.Background(), tunDevice, make(chan []byte, 1), make(chan error, 1))
	<-tunDevice.readStarted
	reader.stop()
	reader.stop()
	if !tunDevice.readExited.Load() || tunDevice.closed.Load() {
		t.Fatalf("reader exited=%t device closed=%t", tunDevice.readExited.Load(), tunDevice.closed.Load())
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
