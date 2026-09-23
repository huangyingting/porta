package masque

import (
	"context"
	"io"
	"testing"
)

func TestDatagramSuccessAndOtherErrorsDoNotFallback(t *testing.T) {
	for _, sendErr := range []error{nil, io.ErrClosedPipe} {
		writer := PacketWriter{
			Ceiling:  1400,
			Datagram: func([]byte) error { return sendErr },
			Capsule:  func([]byte) error { t.Fatal("unexpected fallback"); return nil },
		}
		if err := writer.Send(context.Background(), adaptivePacket(68, false)); err != sendErr {
			t.Fatalf("result = %v, want %v", err, sendErr)
		}
	}
}
