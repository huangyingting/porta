package protocol

import "testing"

func BenchmarkClassifyIPv4(b *testing.B) {
	packet := trafficTestIPv4Packet(6, 40000, 443, 1400, 0x18)
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		metadata := ClassifyIPv4(packet)
		if metadata.Class != PacketClassTCP {
			b.Fatal("unexpected packet class")
		}
	}
}
