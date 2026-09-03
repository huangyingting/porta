package protocol

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrNotIPv4       = errors.New("only IPv4 packets are supported")
	ErrShortIPv4     = errors.New("IPv4 packet is shorter than its header")
	ErrInvalidLength = errors.New("invalid IPv4 total length")
)

type IPv4Info struct {
	Source      netip.Addr
	Destination netip.Addr
	TotalLength int
}

func ParseIPv4(packet []byte) (IPv4Info, error) {
	if len(packet) < 20 {
		return IPv4Info{}, ErrShortIPv4
	}
	if packet[0]>>4 != 4 {
		return IPv4Info{}, ErrNotIPv4
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return IPv4Info{}, ErrShortIPv4
	}
	totalLength := int(packet[2])<<8 | int(packet[3])
	if totalLength < headerLength || totalLength != len(packet) {
		return IPv4Info{}, fmt.Errorf("%w: header=%d packet=%d", ErrInvalidLength, totalLength, len(packet))
	}

	return IPv4Info{
		Source:      netip.AddrFrom4([4]byte(packet[12:16])),
		Destination: netip.AddrFrom4([4]byte(packet[16:20])),
		TotalLength: totalLength,
	}, nil
}
