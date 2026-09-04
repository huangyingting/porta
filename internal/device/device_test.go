package device

import (
	"bytes"
	"context"
	"os"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

type fakeTUN struct {
	readPackets [][]byte
	readCalls   atomic.Int32
	writeOffset int
	written     []byte
	writeResult int
}

func (f *fakeTUN) File() *os.File { return nil }

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	f.readCalls.Add(1)
	for index, packet := range f.readPackets {
		copy(bufs[index][offset:], packet)
		sizes[index] = len(packet)
	}
	return len(f.readPackets), nil
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.writeOffset = offset
	f.written = append([]byte(nil), bufs[0][offset:]...)
	return f.writeResult, nil
}

func (f *fakeTUN) MTU() (int, error)        { return 1300, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake0", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return make(chan tun.Event) }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return len(f.readPackets) }

func TestNativeReadPacketBuffersBatch(t *testing.T) {
	fake := &fakeTUN{readPackets: [][]byte{{0x45, 1}, {0x45, 2}}}
	device := newNative(fake, "fake0", 1300)
	defer device.Close()

	first, err := device.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := device.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, fake.readPackets[0]) || !bytes.Equal(second, fake.readPackets[1]) {
		t.Fatalf("packets = %x, %x; want %x, %x", first, second, fake.readPackets[0], fake.readPackets[1])
	}
	readCalls := fake.readCalls.Load()
	if readCalls < 1 || readCalls > 2 {
		t.Fatalf("Read called %d times while consuming one batch", readCalls)
	}
}

func TestNativeWritePacketUsesHeadroom(t *testing.T) {
	packet := []byte{0x45, 0, 0, 20}
	fake := &fakeTUN{writeResult: len(packet) + 10}
	device := newNative(fake, "fake0", 1300)
	defer device.Close()

	if err := device.WritePacket(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if fake.writeOffset != packetOffset {
		t.Fatalf("write offset = %d, want %d", fake.writeOffset, packetOffset)
	}
	if !bytes.Equal(fake.written, packet) {
		t.Fatalf("written packet = %x, want %x", fake.written, packet)
	}

	firstBuffer := &device.writeBuffer[0]
	if err := device.WritePacket(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if firstBuffer != &device.writeBuffer[0] {
		t.Fatal("write buffer was reallocated")
	}
}
