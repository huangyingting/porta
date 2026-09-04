package masque

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkEncodeIPPacket(b *testing.B) {
	packet := make([]byte, 1100)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		_ = EncodeIPPacket(packet)
	}
}

func BenchmarkCapsuleWrite(b *testing.B) {
	packet := make([]byte, 1100)
	encoder := NewEncoder(io.Discard)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		if err := encoder.Write(CapsuleDatagram, packet); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCapsuleReadInto(b *testing.B) {
	var encoded bytes.Buffer
	if err := NewEncoder(&encoded).Write(CapsuleDatagram, make([]byte, 1100)); err != nil {
		b.Fatal(err)
	}
	source := bytes.NewReader(encoded.Bytes())
	decoder := NewDecoder(source)
	buffer := make([]byte, 1100)
	b.ReportAllocs()
	for b.Loop() {
		source.Reset(encoded.Bytes())
		decoder.r.Reset(source)
		if _, err := decoder.ReadInto(buffer); err != nil {
			b.Fatal(err)
		}
	}

}

func BenchmarkIPCapsuleWrite(b *testing.B) {
	packet := make([]byte, 1100)
	encoder := NewEncoder(io.Discard)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		if err := encoder.WriteIPPacket(packet); err != nil {
			b.Fatal(err)
		}
	}
}
