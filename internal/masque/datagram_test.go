package masque

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/quic-go/quic-go"
)

type flushedBuffer struct {
	bytes.Buffer
	flushes int
}

func (b *flushedBuffer) Flush() { b.flushes++ }

func TestOversizedDatagramFallsBackWithoutChangingPacket(t *testing.T) {
	packet := bytes.Repeat([]byte{0x45}, 1300)
	var output flushedBuffer
	err := SendIPPacket(packet, func(value []byte) error {
		if !bytes.Equal(value, EncodeIPPacket(packet)) {
			t.Fatal("datagram payload changed")
		}
		return fmt.Errorf("HTTP/3: %w", &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1150})
	}, NewEncoder(&output))
	if err != nil {
		t.Fatal(err)
	}
	capsule, err := NewDecoder(&output).Read()
	if err != nil || capsule.Type != CapsuleDatagram || !bytes.Equal(capsule.Value, EncodeIPPacket(packet)) {
		t.Fatalf("fallback capsule = %+v, %v", capsule, err)
	}
	if output.flushes != 1 {
		t.Fatal("fallback capsule was not flushed")
	}
}

func TestDatagramSuccessAndOtherErrorsDoNotFallback(t *testing.T) {
	for _, sendErr := range []error{nil, io.ErrClosedPipe} {
		var output flushedBuffer
		err := SendIPPacket([]byte{1}, func([]byte) error { return sendErr }, NewEncoder(&output))
		if err != sendErr || output.Len() != 0 || output.flushes != 0 {
			t.Fatalf("result = %v, bytes = %d, flushes = %d", err, output.Len(), output.flushes)
		}
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestDatagramFallbackPropagatesStreamFailure(t *testing.T) {
	err := SendIPPacket([]byte{1}, func([]byte) error {
		return &quic.DatagramTooLargeError{}
	}, NewEncoder(failedWriter{}))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("stream failure = %v", err)
	}
}
