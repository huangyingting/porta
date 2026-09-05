package protocol

import (
	"encoding/binary"
)

type PacketClass uint8

const (
	PacketClassTCP PacketClass = iota
	PacketClassDatagram
	PacketClassControl
)

type FlowKey struct {
	Source          [4]byte
	Destination     [4]byte
	SourcePort      uint16
	DestinationPort uint16
	FragmentID      uint16
	Protocol        uint8
	Fragmented      bool
}

type PacketMetadata struct {
	Class PacketClass
	Flow  FlowKey
	Hash  uint32
}

func ClassifyIPv4(packet []byte) PacketMetadata {
	metadata := PacketMetadata{Class: PacketClassDatagram}
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return metadata
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return metadata
	}
	copy(metadata.Flow.Source[:], packet[12:16])
	copy(metadata.Flow.Destination[:], packet[16:20])
	metadata.Flow.Protocol = packet[9]
	flagsAndOffset := binary.BigEndian.Uint16(packet[6:8])
	metadata.Flow.Fragmented = flagsAndOffset&0x3fff != 0
	if metadata.Flow.Fragmented {
		metadata.Flow.FragmentID = binary.BigEndian.Uint16(packet[4:6])
	}
	hasPorts := !metadata.Flow.Fragmented &&
		(metadata.Flow.Protocol == 6 || metadata.Flow.Protocol == 17) &&
		len(packet) >= headerLength+4
	if hasPorts {
		metadata.Flow.SourcePort = binary.BigEndian.Uint16(packet[headerLength : headerLength+2])
		metadata.Flow.DestinationPort = binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4])
	}

	switch metadata.Flow.Protocol {
	case 1:
		metadata.Class = PacketClassControl
	case 6:
		metadata.Class = PacketClassTCP
		if hasPorts && (metadata.Flow.SourcePort == 53 || metadata.Flow.DestinationPort == 53) {
			metadata.Class = PacketClassControl
		} else if hasPorts && tcpACKOnly(packet, headerLength) {
			metadata.Class = PacketClassControl
		}
	case 17:
		if hasPorts && (metadata.Flow.SourcePort == 53 || metadata.Flow.DestinationPort == 53) {
			metadata.Class = PacketClassControl
		} else if hasPorts && len(packet) <= 256 {
			metadata.Class = PacketClassControl
		}
	}
	metadata.Hash = hashFlow(metadata.Flow)
	return metadata
}

func tcpACKOnly(packet []byte, ipHeaderLength int) bool {
	if len(packet) < ipHeaderLength+20 {
		return false
	}
	tcpHeaderLength := int(packet[ipHeaderLength+12]>>4) * 4
	if tcpHeaderLength < 20 || len(packet) < ipHeaderLength+tcpHeaderLength {
		return false
	}
	flags := packet[ipHeaderLength+13]
	const (
		tcpFIN = 0x01
		tcpSYN = 0x02
		tcpRST = 0x04
		tcpACK = 0x10
	)
	return flags&tcpACK != 0 &&
		flags&(tcpFIN|tcpSYN|tcpRST) == 0 &&
		len(packet) == ipHeaderLength+tcpHeaderLength
}

func hashFlow(flow FlowKey) uint32 {
	hash := uint32(2166136261)
	add := func(value byte) {
		hash ^= uint32(value)
		hash *= 16777619
	}
	for _, value := range flow.Source {
		add(value)
	}
	for _, value := range flow.Destination {
		add(value)
	}
	var fields [8]byte
	binary.BigEndian.PutUint16(fields[0:2], flow.SourcePort)
	binary.BigEndian.PutUint16(fields[2:4], flow.DestinationPort)
	binary.BigEndian.PutUint16(fields[4:6], flow.FragmentID)
	fields[6] = flow.Protocol
	if flow.Fragmented {
		fields[7] = 1
	}
	for _, value := range fields {
		add(value)
	}
	return hash
}
