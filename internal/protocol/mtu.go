package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
)

var (
	ErrInvalidMTU          = errors.New("IPv4 MTU must be between 68 and 65535")
	ErrInvalidIPv4Packet   = errors.New("invalid IPv4 packet")
	ErrFragmentationNeeded = errors.New("IPv4 fragmentation needed but DF is set")
	ErrICMPSuppressed      = errors.New("ICMP error response suppressed")
	ErrInvalidGateway      = errors.New("ICMP gateway must be a unicast IPv4 address")
)

// FragmentationNeededError reports the next-hop MTU for an oversized DF packet.
// It matches ErrFragmentationNeeded through errors.Is.
type FragmentationNeededError struct {
	MTU int
}

func (e *FragmentationNeededError) Error() string {
	return fmt.Sprintf("%s: MTU %d", ErrFragmentationNeeded, e.MTU)
}

func (e *FragmentationNeededError) Unwrap() error { return ErrFragmentationNeeded }

// ICMPSuppressedError explains why no ICMP response may be sent. It matches
// ErrICMPSuppressed through errors.Is.
type ICMPSuppressedError struct {
	Reason string
}

func (e *ICMPSuppressedError) Error() string {
	return fmt.Sprintf("%s: %s", ErrICMPSuppressed, e.Reason)
}

func (e *ICMPSuppressedError) Unwrap() error { return ErrICMPSuppressed }

const (
	ipv4FlagReserved = 0x8000
	ipv4FlagDF       = 0x4000
	ipv4FlagMF       = 0x2000
	ipv4OffsetMask   = 0x1fff
)

var ipv4ICMPIdentification atomic.Uint32

// FragmentIPv4 splits a complete IPv4 packet into packets no larger than mtu.
// It preserves the identification, payload, and existing fragment offsets/MF,
// copies options as required by their copy bit, and recomputes header checksums.
// Input headers (including checksums and option lengths) must be valid, and mtu
// must be in [68, 65535]. Oversized DF packets return FragmentationNeededError.
//
// The input is never modified. New fragments own their storage; if the packet
// already fits, the sole returned slice aliases packet. Callers on the ordinary
// forwarding path should check packet length first to avoid unnecessary work.
func FragmentIPv4(packet []byte, mtu int) ([][]byte, error) {
	if err := validateIPv4MTU(mtu); err != nil {
		return nil, err
	}
	p, err := inspectIPv4MTUPacket(packet)
	if err != nil {
		return nil, err
	}
	if len(packet) <= mtu {
		return [][]byte{packet}, nil
	}
	if p.flags&ipv4FlagDF != 0 {
		return nil, &FragmentationNeededError{MTU: mtu}
	}

	payload := packet[p.headerLength:]
	offset := int(p.flags&ipv4OffsetMask) * 8
	var fragments [][]byte
	for consumed := 0; consumed < len(payload); {
		headerLength := 20 + p.copiedLength
		if offset == 0 {
			headerLength = p.headerLength
		}
		size := len(payload) - consumed
		if size > mtu-headerLength {
			size = (mtu - headerLength) &^ 7
		}
		// A valid IPv4 MTU always accommodates the largest header plus eight
		// payload bytes, so even a maximum-size options header makes progress.
		fragment := make([]byte, headerLength+size)
		copy(fragment, packet[:20])
		if offset == 0 {
			copy(fragment[20:headerLength], packet[20:p.headerLength])
		} else {
			copy(fragment[20:headerLength], p.copiedOptions[:p.copiedLength])
		}
		fragment[0] = 0x40 | byte(headerLength/4)
		binary.BigEndian.PutUint16(fragment[2:4], uint16(len(fragment)))
		flags := uint16(offset / 8)
		if consumed+size < len(payload) || p.flags&ipv4FlagMF != 0 {
			flags |= ipv4FlagMF
		}
		binary.BigEndian.PutUint16(fragment[6:8], flags)
		copy(fragment[headerLength:], payload[consumed:consumed+size])
		setIPv4MTUChecksum(fragment[:headerLength])
		fragments = append(fragments, fragment)
		consumed += size
		offset += size
	}
	return fragments, nil
}

// ICMPFragmentationNeeded constructs an IPv4 ICMP type 3/code 4 response for an
// oversized DF packet, advertising mtu and quoting its entire IPv4 header plus
// up to eight payload bytes. The source is gateway and destination is the
// original source. The response owns its storage and packet is never modified.
//
// No response is returned for non-first fragments, ICMP errors/unknown types,
// or non-unicast/invalid addresses: these return ICMPSuppressedError. Packets
// that fit or have DF clear also return ICMPSuppressedError. Malformed packets,
// invalid gateways, and MTUs outside [68, 65535] return validation errors.
//
// Pass known subnet prefixes to also suppress subnet-directed broadcasts;
// /31 and /32 prefixes have no broadcast address. The caller must additionally
// suppress packets received as link-layer broadcasts/multicasts and directed
// broadcasts on subnets not provided here, and rate-limit generated errors.
func ICMPFragmentationNeeded(packet []byte, gateway netip.Addr, mtu int, subnets ...netip.Prefix) ([]byte, error) {
	if err := validateIPv4MTU(mtu); err != nil {
		return nil, err
	}
	if !ipv4MTUUnicast(gateway) || ipv4MTUBroadcast(gateway, subnets) {
		return nil, ErrInvalidGateway
	}
	p, err := inspectIPv4MTUPacket(packet)
	if err != nil {
		return nil, err
	}
	suppress := func(reason string) ([]byte, error) {
		return nil, &ICMPSuppressedError{Reason: reason}
	}
	if p.flags&ipv4OffsetMask != 0 {
		return suppress("non-first fragment")
	}
	if !ipv4MTUUnicast(p.info.Source) || !ipv4MTUUnicast(p.info.Destination) ||
		ipv4MTUBroadcast(p.info.Source, subnets) || ipv4MTUBroadcast(p.info.Destination, subnets) {
		return suppress("non-unicast or invalid source/destination")
	}
	if packet[9] == 1 {
		if len(packet)-p.headerLength < 8 {
			return suppress("truncated ICMP message")
		}
		switch packet[p.headerLength] {
		case 0, 8, 9, 10, 13, 14, 15, 16, 17, 18, 42, 43:
			// Only known informational ICMP messages may elicit errors.
		default:
			return suppress("ICMP error or unknown ICMP type")
		}
	}
	if len(packet) <= mtu || p.flags&ipv4FlagDF == 0 {
		return suppress("packet does not require a fragmentation-needed response")
	}

	quoteLength := min(len(packet), p.headerLength+8)
	response := make([]byte, 20+8+quoteLength)
	response[0] = 0x45
	binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
	// Leave DF clear: a quote with options can exceed the minimum IPv4 MTU.
	binary.BigEndian.PutUint16(response[4:6], uint16(ipv4ICMPIdentification.Add(1)))
	response[8], response[9] = 64, 1
	source, destination := gateway.As4(), p.info.Source.As4()
	copy(response[12:16], source[:])
	copy(response[16:20], destination[:])
	icmp := response[20:]
	icmp[0], icmp[1] = 3, 4
	binary.BigEndian.PutUint16(icmp[6:8], uint16(mtu))
	copy(icmp[8:], packet[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], ipv4MTUChecksum(icmp))
	setIPv4MTUChecksum(response[:20])
	return response, nil
}

type ipv4MTUPacket struct {
	info          IPv4Info
	headerLength  int
	flags         uint16
	copiedOptions [40]byte
	copiedLength  int
}

func validateIPv4MTU(mtu int) error {
	if mtu < 68 || mtu > MaxPacket {
		return ErrInvalidMTU
	}
	return nil
}

func inspectIPv4MTUPacket(packet []byte) (ipv4MTUPacket, error) {
	var p ipv4MTUPacket
	info, err := ParseIPv4(packet)
	if err != nil {
		return p, fmt.Errorf("%w: %w", ErrInvalidIPv4Packet, err)
	}
	p.info = info
	p.headerLength = int(packet[0]&0x0f) * 4
	p.flags = binary.BigEndian.Uint16(packet[6:8])
	if ipv4MTUChecksum(packet[:p.headerLength]) != 0 {
		return p, fmt.Errorf("%w: header checksum", ErrInvalidIPv4Packet)
	}
	if p.flags&ipv4FlagReserved != 0 {
		return p, fmt.Errorf("%w: reserved flag", ErrInvalidIPv4Packet)
	}
	options := packet[20:p.headerLength]
	for i := 0; i < len(options); {
		kind := options[i]
		switch kind {
		case 0:
			for _, padding := range options[i:] {
				if padding != 0 {
					return p, fmt.Errorf("%w: nonzero option padding", ErrInvalidIPv4Packet)
				}
			}
			i = len(options)
		case 1:
			i++
		default:
			if i+1 >= len(options) {
				return p, fmt.Errorf("%w: truncated option length", ErrInvalidIPv4Packet)
			}
			size := int(options[i+1])
			if size < 2 || size > len(options)-i {
				return p, fmt.Errorf("%w: invalid option length", ErrInvalidIPv4Packet)
			}
			if kind&0x80 != 0 {
				// Retain copied options' original alignment, replacing any
				// necessary spacing from omitted options with NOPs.
				for p.copiedLength%4 != i%4 {
					p.copiedOptions[p.copiedLength] = 1
					p.copiedLength++
				}
				copy(p.copiedOptions[p.copiedLength:], options[i:i+size])
				p.copiedLength += size
			}
			i += size
		}
	}
	p.copiedLength = (p.copiedLength + 3) &^ 3
	payloadLength := len(packet) - p.headerLength
	offset := int(p.flags&ipv4OffsetMask) * 8
	if (p.flags&ipv4FlagMF != 0 && payloadLength%8 != 0) ||
		(p.flags&(ipv4FlagMF|ipv4OffsetMask) != 0 && payloadLength == 0) {
		return p, fmt.Errorf("%w: invalid fragment payload length", ErrInvalidIPv4Packet)
	}
	minimumHeader := 20 + p.copiedLength
	if offset == 0 {
		minimumHeader = p.headerLength
	}
	end := minimumHeader + offset + payloadLength
	if end > MaxPacket || (p.flags&ipv4FlagMF != 0 && end == MaxPacket) {
		return p, fmt.Errorf("%w: fragment exceeds maximum reassembled length", ErrInvalidIPv4Packet)
	}
	return p, nil
}

func ipv4MTUUnicast(address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	a := address.As4()
	return a[0] != 0 && a[0] != 127 && a[0] < 224
}

func ipv4MTUBroadcast(address netip.Addr, subnets []netip.Prefix) bool {
	if !address.Is4() {
		return false
	}
	value := binary.BigEndian.Uint32(address.AsSlice())
	for _, subnet := range subnets {
		if !subnet.IsValid() || !subnet.Addr().Is4() || subnet.Bits() >= 31 || !subnet.Contains(address) {
			continue
		}
		hostMask := ^uint32(0) >> subnet.Bits()
		if value&hostMask == hostMask {
			return true
		}
	}
	return false
}

func setIPv4MTUChecksum(header []byte) {
	header[10], header[11] = 0, 0
	binary.BigEndian.PutUint16(header[10:12], ipv4MTUChecksum(header))
}

func ipv4MTUChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
