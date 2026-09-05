package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"testing"
)

func TestFragmentIPv4(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload int
		mtu     int
		flags   uint16
		sizes   []int
	}{
		{"one remainder byte", 97, 68, 0, []int{68, 68, 21}},
		{"exact multiple", 96, 68, 0, []int{68, 68}},
		{"unaligned MTU", 145, 71, 0, []int{68, 68, 69}},
		{"large payload", 3981, 1280, 0, []int{1276, 1276, 1276, 233}},
		{"refragment middle", 144, 68, ipv4FlagMF | 100, []int{68, 68, 68}},
		{"refragment last", 145, 68, 100, []int{68, 68, 68, 21}},
		{"refragment first", 144, 68, ipv4FlagMF, []int{68, 68, 68}},
		{"maximum packet", 65515, 1500, 0, nil},
		{"maximum last fragment", 59, 68, 8182, []int{68, 31}},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := mtuTestPacket(test.payload, nil, test.flags)
			before := bytes.Clone(packet)
			fragments, err := FragmentIPv4(packet, test.mtu)
			if err != nil {
				t.Fatal(err)
			}
			if test.sizes != nil {
				if len(fragments) != len(test.sizes) {
					t.Fatalf("fragment count = %d, want %d", len(fragments), len(test.sizes))
				}
				for i, size := range test.sizes {
					if len(fragments[i]) != size {
						t.Errorf("fragment %d length = %d, want %d", i, len(fragments[i]), size)
					}
				}
			}
			mtuCheckFragments(t, before, fragments, test.mtu)
			if !bytes.Equal(packet, before) {
				t.Fatal("input was modified")
			}
			fragments[0][12] ^= 1
			if !bytes.Equal(packet, before) {
				t.Fatal("new fragments alias input")
			}
			if len(fragments) > 1 && fragments[0][12] == fragments[1][12] {
				t.Fatal("new fragments alias each other")
			}
		})
	}
}

func TestFragmentIPv4DFAndNoOp(t *testing.T) {
	for _, flags := range []uint16{0, ipv4FlagDF} {
		packet := mtuTestPacket(48, nil, flags)
		before := bytes.Clone(packet)
		for _, mtu := range []int{68, MaxPacket} {
			fragments, err := FragmentIPv4(packet, mtu)
			if err != nil || len(fragments) != 1 || !bytes.Equal(fragments[0], packet) {
				t.Fatalf("fitting flags=%x mtu=%d: fragments=%v err=%v", flags, mtu, fragments, err)
			}
			if &fragments[0][0] != &packet[0] {
				t.Fatal("fitting packet was unnecessarily copied")
			}
		}
		if !bytes.Equal(packet, before) {
			t.Fatal("fitting input changed")
		}
	}
	packet := mtuTestPacket(49, nil, ipv4FlagDF)
	before := bytes.Clone(packet)
	fragments, err := FragmentIPv4(packet, 68)
	var needed *FragmentationNeededError
	if fragments != nil || !errors.Is(err, ErrFragmentationNeeded) ||
		!errors.As(err, &needed) || needed.MTU != 68 {
		t.Fatalf("DF: fragments=%v err=%v detail=%v", fragments, err, needed)
	}
	if !bytes.Equal(packet, before) {
		t.Fatal("DF input changed")
	}
}

func TestFragmentIPv4Options(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []byte
		copied  []byte
	}{
		{"no copied options", []byte{0x44, 4, 9, 8}, nil},
		{"copied and noncopied", []byte{0x44, 4, 9, 8, 0x82, 4, 7, 6}, []byte{0x82, 4, 7, 6}},
		{"NOP alignment", []byte{1, 0x82, 3, 7, 0x44, 4, 9, 8}, []byte{1, 0x82, 3, 7}},
		{"removed option alignment", []byte{0x44, 3, 9, 0x82, 3, 7, 0, 0}, []byte{1, 1, 1, 0x82, 3, 7, 0, 0}},
		{"multiple copied options", []byte{0x82, 3, 7, 0x44, 3, 9, 0x83, 2}, []byte{0x82, 3, 7, 1, 1, 1, 0x83, 2}},
		{"EOL and padding", []byte{0x82, 2, 0, 0, 0, 0, 0, 0}, []byte{0x82, 2, 0, 0}},
		{"only NOPs", []byte{1, 1, 1, 1}, nil},
		{"maximum copied options", append([]byte{0x82, 40}, make([]byte, 38)...), append([]byte{0x82, 40}, make([]byte, 38)...)},
		{"maximum uncopied options", append([]byte{0x44, 40}, make([]byte, 38)...), nil},
	} {
		for _, offset := range []uint16{0, 100} {
			t.Run(test.name+"/"+strconv.Itoa(int(offset)), func(t *testing.T) {
				packet := mtuTestPacket(144, test.options, offset|ipv4FlagMF)
				before := bytes.Clone(packet)
				fragments, err := FragmentIPv4(packet, 68)
				if err != nil {
					t.Fatal(err)
				}
				mtuCheckFragments(t, before, fragments, 68)
				for i, fragment := range fragments {
					want := test.copied
					if offset == 0 && i == 0 {
						want = test.options
					}
					headerLength := int(fragment[0]&15) * 4
					if !bytes.Equal(fragment[20:headerLength], want) {
						t.Errorf("fragment %d options = %x, want %x", i, fragment[20:headerLength], want)
					}
				}
				if !bytes.Equal(packet, before) {
					t.Fatal("input modified")
				}
			})
		}
	}
}

func TestIPv4MTUBadInputs(t *testing.T) {
	gateway := netip.MustParseAddr("10.66.0.1")
	for _, mtu := range []int{-1, 0, 1, 20, 27, 60, 67, 65536, int(^uint(0) >> 1)} {
		packet := mtuTestPacket(100, nil, ipv4FlagDF)
		fragments, err := FragmentIPv4(packet, mtu)
		if fragments != nil || !errors.Is(err, ErrInvalidMTU) {
			t.Errorf("fragment mtu %d: %v", mtu, err)
		}
		response, err := ICMPFragmentationNeeded(packet, gateway, mtu)
		if response != nil || !errors.Is(err, ErrInvalidMTU) {
			t.Errorf("ICMP mtu %d: %v", mtu, err)
		}
	}
	for _, test := range []struct {
		name   string
		packet func() []byte
	}{
		{"empty", func() []byte { return nil }},
		{"short", func() []byte { return make([]byte, 19) }},
		{"IPv6", func() []byte { p := mtuTestPacket(100, nil, 0); p[0] = 0x65; return p }},
		{"short IHL", func() []byte { p := mtuTestPacket(100, nil, 0); p[0] = 0x44; return p }},
		{"long IHL", func() []byte { p := mtuTestPacket(1, nil, 0); p[0] = 0x4f; return p }},
		{"total too small", func() []byte { p := mtuTestPacket(100, nil, 0); p[3] = 19; return p }},
		{"truncated total", func() []byte { p := mtuTestPacket(100, nil, 0); p[3]++; return p }},
		{"trailing bytes", func() []byte { return append(mtuTestPacket(100, nil, 0), 0) }},
		{"bad checksum", func() []byte { p := mtuTestPacket(100, nil, 0); p[10] ^= 1; return p }},
		{"reserved flag", func() []byte { return mtuTestPacket(100, nil, ipv4FlagReserved) }},
		{"unaligned MF payload", func() []byte { return mtuTestPacket(99, nil, ipv4FlagMF) }},
		{"empty MF fragment", func() []byte { return mtuTestPacket(0, nil, ipv4FlagMF) }},
		{"empty last fragment", func() []byte { return mtuTestPacket(0, nil, 1) }},
		{"fragment offset overflow", func() []byte { return mtuTestPacket(8, nil, 8191) }},
		{"reassembled length overflow", func() []byte { return mtuTestPacket(100, nil, 8182) }},
		{"copied options reassembled overflow", func() []byte {
			return mtuTestPacket(50, append([]byte{0x82, 40}, make([]byte, 38)...), 8180)
		}},
		{"option length zero", func() []byte { return mtuTestPacket(100, []byte{0x82, 0, 0, 0}, 0) }},
		{"option length one", func() []byte { return mtuTestPacket(100, []byte{0x82, 1, 0, 0}, 0) }},
		{"option overruns IHL", func() []byte { return mtuTestPacket(100, []byte{0x82, 5, 0, 0}, 0) }},
		{"missing option length", func() []byte { return mtuTestPacket(100, []byte{1, 1, 1, 0x82}, 0) }},
		{"nonzero after EOL", func() []byte { return mtuTestPacket(100, []byte{0, 0, 1, 0}, 0) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := test.packet()
			before := bytes.Clone(packet)
			for _, mtu := range []int{68, MaxPacket} {
				fragments, err := FragmentIPv4(packet, mtu)
				if fragments != nil || !errors.Is(err, ErrInvalidIPv4Packet) {
					t.Errorf("fragments = %v, err = %v", fragments, err)
				}
				response, err := ICMPFragmentationNeeded(packet, gateway, mtu)
				if response != nil || !errors.Is(err, ErrInvalidIPv4Packet) {
					t.Errorf("response = %v, err = %v", response, err)
				}
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("bad input modified")
			}
		})
	}
	if _, err := FragmentIPv4(nil, 68); !errors.Is(err, ErrShortIPv4) {
		t.Fatalf("ParseIPv4 error not preserved: %v", err)
	}
}

func TestICMPFragmentationNeeded(t *testing.T) {
	gateway := netip.MustParseAddr("10.66.0.1")
	for _, test := range []struct {
		name    string
		payload int
		options []byte
		mtu     int
	}{
		{"ordinary", 1300, nil, 1280},
		{"options", 100, []byte{0x82, 4, 9, 8, 0x44, 4, 7, 6}, 68},
		{"maximum header", 20, append([]byte{0x82, 40}, make([]byte, 38)...), 68},
		{"maximum datagram", 65515, nil, 65534},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := mtuTestPacket(test.payload, test.options, ipv4FlagDF)
			before := bytes.Clone(packet)
			response, err := ICMPFragmentationNeeded(packet, gateway, test.mtu)
			if err != nil {
				t.Fatal(err)
			}
			info, err := ParseIPv4(response)
			if err != nil {
				t.Fatal(err)
			}
			if info.Source != gateway || info.Destination.String() != "10.66.0.2" {
				t.Errorf("response addresses: %+v", info)
			}
			if response[0] != 0x45 || response[8] == 0 || response[9] != 1 || response[1] != 0 ||
				binary.BigEndian.Uint16(response[6:8]) != 0 {
				t.Errorf("response header = %x", response[:20])
			}
			if mtuTestChecksum(response[:20]) != 0 || mtuTestChecksum(response[20:]) != 0 {
				t.Fatal("invalid IP or ICMP checksum")
			}
			if response[20] != 3 || response[21] != 4 || response[24] != 0 || response[25] != 0 {
				t.Errorf("ICMP header = %x", response[20:28])
			}
			if got := binary.BigEndian.Uint16(response[26:28]); got != uint16(test.mtu) {
				t.Errorf("advertised MTU = %d, want %d", got, test.mtu)
			}
			quoteLength := 20 + len(test.options) + 8
			if len(response) != 28+quoteLength || !bytes.Equal(response[28:], packet[:quoteLength]) {
				t.Errorf("incorrect quote: response length = %d quote = %x", len(response), response[28:])
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("input modified")
			}
			response[28] ^= 1
			if !bytes.Equal(packet, before) {
				t.Fatal("response aliases input")
			}
		})
	}
}

func TestICMPFragmentationNeededConcurrent(t *testing.T) {
	packet := mtuTestPacket(100, nil, ipv4FlagDF)
	before := bytes.Clone(packet)
	gateway := netip.MustParseAddr("10.66.0.1")
	ids := make(chan uint16, 32)
	var workers sync.WaitGroup
	for range cap(ids) {
		workers.Go(func() {
			response, err := ICMPFragmentationNeeded(packet, gateway, 68)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- binary.BigEndian.Uint16(response[4:6])
		})
	}
	workers.Wait()
	close(ids)
	seen := make(map[uint16]bool)
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate response ID %d", id)
		}
		seen[id] = true
	}
	if !bytes.Equal(packet, before) {
		t.Fatal("shared input modified")
	}
}

func TestICMPFragmentationNeededSuppression(t *testing.T) {
	gateway := netip.MustParseAddr("10.66.0.1")
	for _, test := range []struct {
		name   string
		change func([]byte)
		mtu    int
	}{
		{"nonfirst fragment", func(p []byte) { binary.BigEndian.PutUint16(p[6:8], ipv4FlagDF|1) }, 68},
		{"no DF", func(p []byte) { p[6] = 0 }, 68},
		{"fits", func(p []byte) {}, 120},
		{"limited broadcast destination", func(p []byte) { copy(p[16:20], []byte{255, 255, 255, 255}) }, 68},
		{"multicast destination", func(p []byte) { copy(p[16:20], []byte{239, 1, 2, 3}) }, 68},
		{"zero destination", func(p []byte) { copy(p[16:20], []byte{0, 0, 0, 0}) }, 68},
		{"multicast source", func(p []byte) { copy(p[12:16], []byte{224, 1, 2, 3}) }, 68},
		{"broadcast source", func(p []byte) { copy(p[12:16], []byte{255, 255, 255, 255}) }, 68},
		{"reserved source", func(p []byte) { copy(p[12:16], []byte{240, 1, 2, 3}) }, 68},
		{"zero source", func(p []byte) { copy(p[12:16], []byte{0, 0, 0, 0}) }, 68},
		{"zero network source", func(p []byte) { copy(p[12:16], []byte{0, 1, 2, 3}) }, 68},
		{"loopback source", func(p []byte) { copy(p[12:16], []byte{127, 1, 2, 3}) }, 68},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := mtuTestPacket(100, nil, ipv4FlagDF)
			test.change(packet)
			mtuTestFixChecksum(packet)
			before := bytes.Clone(packet)
			response, err := ICMPFragmentationNeeded(packet, gateway, test.mtu)
			var suppressed *ICMPSuppressedError
			if response != nil || !errors.Is(err, ErrICMPSuppressed) ||
				!errors.As(err, &suppressed) || suppressed.Reason == "" {
				t.Fatalf("response=%x err=%v detail=%v", response, err, suppressed)
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("suppressed input modified")
			}
		})
	}
	for kind := 0; kind < 256; kind++ {
		packet := mtuTestPacket(100, nil, ipv4FlagDF)
		packet[9], packet[20] = 1, byte(kind)
		mtuTestFixChecksum(packet)
		response, err := ICMPFragmentationNeeded(packet, gateway, 68)
		switch kind {
		case 0, 8, 9, 10, 13, 14, 15, 16, 17, 18, 42, 43:
			if err != nil || response == nil {
				t.Errorf("informational type %d: %v", kind, err)
			}
		default:
			if response != nil || !errors.Is(err, ErrICMPSuppressed) {
				t.Errorf("error/unknown type %d: %v", kind, err)
			}
		}
	}
	packet := mtuTestPacket(7, nil, ipv4FlagDF)
	packet[9], packet[20] = 1, 8
	mtuTestFixChecksum(packet)
	if response, err := ICMPFragmentationNeeded(packet, gateway, 68); response != nil || !errors.Is(err, ErrICMPSuppressed) {
		t.Fatalf("truncated ICMP: response=%x err=%v", response, err)
	}
}

func TestICMPFragmentationNeededBroadcastPrefixesAndGateway(t *testing.T) {
	for _, test := range []struct {
		address string
		prefix  string
		blocked bool
	}{
		{"10.66.0.255", "10.66.0.0/24", true},
		{"10.66.1.255", "10.66.0.42/23", true},
		{"10.66.0.255", "10.66.0.0/23", false},
		{"10.66.0.255", "10.66.0.254/31", false},
		{"10.66.0.255", "10.66.0.255/32", false},
		{"10.67.0.255", "10.66.0.0/24", false},
		{"10.66.0.255", "::/0", false},
		{"10.66.0.255", "0.0.0.0/0", false},
	} {
		for _, pos := range []int{12, 16} {
			packet := mtuTestPacket(100, nil, ipv4FlagDF)
			address := netip.MustParseAddr(test.address).As4()
			copy(packet[pos:pos+4], address[:])
			mtuTestFixChecksum(packet)
			response, err := ICMPFragmentationNeeded(packet, netip.MustParseAddr("10.66.0.1"), 68,
				netip.Prefix{}, netip.MustParsePrefix(test.prefix))
			if test.blocked {
				if response != nil || !errors.Is(err, ErrICMPSuppressed) {
					t.Errorf("%s %s pos=%d should suppress: %v", test.address, test.prefix, pos, err)
				}
			} else if err != nil || response == nil {
				t.Errorf("%s %s pos=%d unexpectedly suppressed: %v", test.address, test.prefix, pos, err)
			}
		}
	}
	for _, address := range []string{"", "::1", "::ffff:10.66.0.1", "0.0.0.0", "0.1.2.3", "127.0.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "10.66.0.255"} {
		gateway, _ := netip.ParseAddr(address)
		response, err := ICMPFragmentationNeeded(mtuTestPacket(100, nil, ipv4FlagDF), gateway, 68,
			netip.MustParsePrefix("10.66.0.0/24"))
		if response != nil || !errors.Is(err, ErrInvalidGateway) {
			t.Errorf("gateway %q: response=%x err=%v", address, response, err)
		}
	}
}

func TestIPv4MTUChecksum(t *testing.T) {
	for _, input := range [][]byte{nil, {0}, {1}, {1, 2, 3}, bytes.Repeat([]byte{255}, MaxPacket)} {
		if got, want := ipv4MTUChecksum(input), mtuTestChecksum(input); got != want {
			t.Errorf("length=%d checksum=%04x want=%04x", len(input), got, want)
		}
	}
}

func FuzzIPv4MTU(f *testing.F) {
	f.Add(mtuTestPacket(100, nil, 0), 68)
	f.Add(mtuTestPacket(100, []byte{0x82, 4, 1, 2}, ipv4FlagDF), 68)
	f.Add(mtuTestPacket(144, []byte{0x44, 3, 9, 0x82, 3, 7, 0, 0}, ipv4FlagMF|100), 71)
	f.Add([]byte{}, 0)
	f.Fuzz(func(t *testing.T, data []byte, mtu int) {
		// Recompute a structurally valid header's checksum so mutations also
		// exercise option/fragment validation rather than only checksum rejection.
		if _, err := ParseIPv4(data); err == nil {
			data = bytes.Clone(data)
			mtuTestFixChecksum(data)
		}
		before := bytes.Clone(data)
		fragments, err := FragmentIPv4(data, mtu)
		if err == nil {
			mtuCheckFragments(t, data, fragments, mtu)
		} else if fragments != nil {
			t.Fatal("error returned partial fragments")
		}
		response, err := ICMPFragmentationNeeded(data, netip.MustParseAddr("10.66.0.1"), mtu)
		if err == nil {
			if _, err := ParseIPv4(response); err != nil || len(response) > 96 ||
				mtuTestChecksum(response[:20]) != 0 || mtuTestChecksum(response[20:]) != 0 {
				t.Fatalf("invalid ICMP response: %x err=%v", response, err)
			}
		} else if response != nil {
			t.Fatal("error returned ICMP bytes")
		}
		if !bytes.Equal(data, before) {
			t.Fatal("input modified")
		}
	})
}

func mtuTestPacket(payloadLength int, options []byte, flags uint16) []byte {
	headerLength := 20 + len(options)
	packet := make([]byte, headerLength+payloadLength)
	packet[0], packet[1] = 0x40|byte(headerLength/4), 0xbb
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234)
	binary.BigEndian.PutUint16(packet[6:8], flags)
	packet[8], packet[9] = 47, 17
	copy(packet[12:20], []byte{10, 66, 0, 2, 1, 1, 1, 1})
	copy(packet[20:headerLength], options)
	for i := headerLength; i < len(packet); i++ {
		packet[i] = byte((i - headerLength) * 31)
	}
	mtuTestFixChecksum(packet)
	return packet
}

func mtuTestFixChecksum(packet []byte) {
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], mtuTestChecksum(packet[:int(packet[0]&15)*4]))
}

// Deliberately independent, byte-at-a-time checksum oracle.
func mtuTestChecksum(data []byte) uint16 {
	sum := uint64(0)
	for i, value := range data {
		if i%2 == 0 {
			sum += uint64(value) * 256
		} else {
			sum += uint64(value)
		}
	}
	for sum > 65535 {
		sum = sum%65536 + sum/65536
	}
	return ^uint16(sum)
}

func mtuCheckFragments(t *testing.T, original []byte, fragments [][]byte, mtu int) {
	t.Helper()
	if len(fragments) == 0 {
		t.Fatal("no fragments")
	}
	originalHeaderLength := int(original[0]&15) * 4
	originalFlags := binary.BigEndian.Uint16(original[6:8])
	offset := int(originalFlags&ipv4OffsetMask) * 8
	var payload []byte
	for i, fragment := range fragments {
		if _, err := ParseIPv4(fragment); err != nil {
			t.Fatalf("fragment %d parse: %v", i, err)
		}
		headerLength := int(fragment[0]&15) * 4
		if len(fragment) > mtu {
			t.Fatalf("fragment %d length=%d exceeds mtu=%d", i, len(fragment), mtu)
		}
		if mtuTestChecksum(fragment[:headerLength]) != 0 {
			t.Fatalf("fragment %d invalid checksum", i)
		}
		if !bytes.Equal(fragment[4:6], original[4:6]) || !bytes.Equal(fragment[8:10], original[8:10]) ||
			!bytes.Equal(fragment[12:20], original[12:20]) || fragment[1] != original[1] {
			t.Fatalf("fragment %d modified preserved fields", i)
		}
		flags := binary.BigEndian.Uint16(fragment[6:8])
		wantMF := i+1 < len(fragments) || originalFlags&ipv4FlagMF != 0
		if int(flags&ipv4OffsetMask)*8 != offset || (flags&ipv4FlagMF != 0) != wantMF {
			t.Fatalf("fragment %d flags=%04x want offset=%d MF=%v", i, flags, offset, wantMF)
		}
		if len(fragments) > 1 && flags&ipv4FlagDF != 0 {
			t.Fatal("fragment has DF set")
		}
		body := fragment[headerLength:]
		if wantMF && len(body)%8 != 0 {
			t.Fatalf("fragment %d MF payload not aligned: %d", i, len(body))
		}
		payload = append(payload, body...)
		offset += len(body)
	}
	if !bytes.Equal(payload, original[originalHeaderLength:]) {
		t.Fatal("reassembled payload differs")
	}
}
