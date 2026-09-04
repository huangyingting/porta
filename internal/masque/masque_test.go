package masque

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestRFC9484AddressRequestEncoding(t *testing.T) {
	value, err := EncodeAddressRequest([]Address{{
		RequestID: 1,
		Prefix:    netip.PrefixFrom(netip.IPv4Unspecified(), 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x20}
	if !bytes.Equal(value, want) {
		t.Fatalf("ADDRESS_REQUEST value = %x, want %x", value, want)
	}

	var stream bytes.Buffer
	if err := NewEncoder(&stream).Write(CapsuleAddressRequest, value); err != nil {
		t.Fatal(err)
	}
	wantCapsule := append([]byte{0x02, 0x07}, want...)
	if !bytes.Equal(stream.Bytes(), wantCapsule) {
		t.Fatalf("ADDRESS_REQUEST capsule = %x, want %x", stream.Bytes(), wantCapsule)
	}
	decoded, err := DecodeAddressRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].RequestID != 1 || decoded[0].Prefix.String() != "0.0.0.0/32" {
		t.Fatalf("decoded ADDRESS_REQUEST = %+v", decoded)
	}
}

func TestRouteAdvertisementRoundTrip(t *testing.T) {
	routes := []Route{{
		Start: netip.MustParseAddr("0.0.0.0"),
		End:   netip.MustParseAddr("255.255.255.255"),
	}}
	value, err := EncodeRouteAdvertisement(routes)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x04, 0, 0, 0, 0, 255, 255, 255, 255, 0}
	if !bytes.Equal(value, want) {
		t.Fatalf("ROUTE_ADVERTISEMENT value = %x, want %x", value, want)
	}
	decoded, err := DecodeRouteAdvertisement(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0] != routes[0] {
		t.Fatalf("decoded routes = %+v", decoded)
	}
}

func TestIPPacketContextZero(t *testing.T) {
	packet := []byte{0x45, 0, 0, 20}
	encoded := EncodeIPPacket(packet)
	if !bytes.Equal(encoded, append([]byte{0}, packet...)) {
		t.Fatalf("encoded packet = %x", encoded)
	}
	decoded, err := DecodeIPPacket(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, packet) {
		t.Fatalf("decoded packet = %x", decoded)
	}
}

func TestCapsuleDecoderReusesBuffer(t *testing.T) {
	var stream bytes.Buffer
	if err := NewEncoder(&stream).Write(CapsuleDatagram, []byte{0, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 0, 16)
	capsule, err := NewDecoder(&stream).ReadInto(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(capsule.Value, []byte{0, 1, 2, 3}) {
		t.Fatalf("capsule value = %v", capsule.Value)
	}
	if &capsule.Value[0] != &buffer[:cap(buffer)][0] {
		t.Fatal("decoder did not reuse the supplied buffer")
	}
}
