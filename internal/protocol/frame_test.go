package protocol

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var stream bytes.Buffer
	encoder := NewEncoder(&stream)
	for _, packet := range [][]byte{{1, 2, 3}, nil, {4, 5}} {
		if err := encoder.WritePacket(packet); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}

	decoder := NewDecoder(&stream)
	for i, expected := range [][]byte{{1, 2, 3}, nil, {4, 5}} {
		packet, err := decoder.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket %d: %v", i, err)
		}
		if !bytes.Equal(packet, expected) {
			t.Fatalf("packet %d = %v, want %v", i, packet, expected)
		}
	}
	if _, err := decoder.ReadPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("final read error = %v, want EOF", err)
	}
}

func TestParseIPv4(t *testing.T) {
	packet := testIPv4Packet([4]byte{10, 66, 0, 2}, [4]byte{1, 1, 1, 1})
	info, err := ParseIPv4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if got := info.Source.String(); got != "10.66.0.2" {
		t.Fatalf("source = %s", got)
	}
	if got := info.Destination.String(); got != "1.1.1.1" {
		t.Fatalf("destination = %s", got)
	}
}

func testIPv4Packet(source, destination [4]byte) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = 20
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	return packet
}
