package protocol

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkFrameWrite(b *testing.B) {
	packet := make([]byte, 1100)
	encoder := NewEncoder(io.Discard)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		if err := encoder.WritePacket(packet); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrameReadInto(b *testing.B) {
	var encoded bytes.Buffer
	if err := NewEncoder(&encoded).WritePacket(make([]byte, 1100)); err != nil {
		b.Fatal(err)
	}
	source := bytes.NewReader(encoded.Bytes())
	decoder := NewDecoder(source)
	buffer := make([]byte, 1100)
	b.ReportAllocs()
	for b.Loop() {
		source.Reset(encoded.Bytes())
		decoder.r.Reset(source)
		if _, err := decoder.ReadPacketInto(buffer); err != nil {
			b.Fatal(err)
		}
	}
}
