package protocol

import (
	"encoding/binary"
	"testing"
)

func TestClassifyIPv4ControlTraffic(t *testing.T) {
	tests := []struct {
		name     string
		protocol byte
		source   uint16
		target   uint16
		size     int
		flags    byte
	}{
		{name: "icmp", protocol: 1, size: 28},
		{name: "dns udp", protocol: 17, source: 40000, target: 53, size: 28},
		{name: "small udp", protocol: 17, source: 40000, target: 123, size: 64},
		{name: "tcp ack", protocol: 6, source: 443, target: 40000, size: 40, flags: 0x10},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := trafficTestIPv4Packet(test.protocol, test.source, test.target, test.size, test.flags)
			if got := ClassifyIPv4(packet).Class; got != PacketClassControl {
				t.Fatalf("class = %d, want control", got)
			}
		})
	}
}

func TestClassifyIPv4DataTraffic(t *testing.T) {
	tcp := trafficTestIPv4Packet(6, 40000, 443, 100, 0x18)
	if got := ClassifyIPv4(tcp).Class; got != PacketClassTCP {
		t.Fatalf("TCP class = %d", got)
	}
	udp := trafficTestIPv4Packet(17, 40000, 443, 1200, 0)
	if got := ClassifyIPv4(udp).Class; got != PacketClassDatagram {
		t.Fatalf("UDP class = %d", got)
	}
}

func TestClassifyIPv4KeepsFragmentsTogether(t *testing.T) {
	first := trafficTestIPv4Packet(17, 40000, 53, 1200, 0)
	binary.BigEndian.PutUint16(first[4:6], 0x1234)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	next := append([]byte(nil), first[:20]...)
	binary.BigEndian.PutUint16(next[2:4], uint16(len(next)))
	binary.BigEndian.PutUint16(next[6:8], 1)
	firstMetadata := ClassifyIPv4(first)
	nextMetadata := ClassifyIPv4(next)
	if firstMetadata.Class != PacketClassDatagram || nextMetadata.Class != PacketClassDatagram {
		t.Fatal("fragmented DNS was incorrectly classified as control traffic")
	}
	if firstMetadata.Flow != nextMetadata.Flow || firstMetadata.Hash != nextMetadata.Hash {
		t.Fatalf("fragment metadata differs: %#v %#v", firstMetadata, nextMetadata)
	}
}

func trafficTestIPv4Packet(protocol byte, sourcePort, destinationPort uint16, size int, flags byte) []byte {
	if size < 20 {
		size = 20
	}
	packet := make([]byte, size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	packet[9] = protocol
	copy(packet[12:16], []byte{10, 66, 0, 2})
	copy(packet[16:20], []byte{1, 1, 1, 1})
	if (protocol == 6 || protocol == 17) && size >= 24 {
		binary.BigEndian.PutUint16(packet[20:22], sourcePort)
		binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	}
	if protocol == 6 && size >= 40 {
		packet[32] = 5 << 4
		packet[33] = flags
	}
	return packet
}
