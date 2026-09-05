package masque

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

var ErrUnknownContext = errors.New("unknown MASQUE context ID")

func EncodeIPPacket(packet []byte) []byte {
	value := make([]byte, 1+len(packet))
	copy(value[1:], packet)
	return value
}

// SendIPPacket uses a reliable DATAGRAM capsule only when a packet exceeds the
// current QUIC path limit. Both forms can coexist on the same CONNECT-IP tunnel.
func SendIPPacket(packet []byte, sendDatagram func([]byte) error, encoder *Encoder) error {
	err := sendDatagram(EncodeIPPacket(packet))
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	if err := encoder.WriteIPPacket(packet); err != nil {
		return err
	}
	encoder.Flush()
	return nil
}

func DecodeIPPacket(value []byte) ([]byte, error) {
	contextID, consumed, err := quicvarint.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse MASQUE context ID: %w", err)
	}
	if contextID != 0 {
		return nil, fmt.Errorf("%w: %d", ErrUnknownContext, contextID)
	}
	if len(value) == consumed {
		return nil, errors.New("MASQUE IP datagram has an empty payload")
	}
	return value[consumed:], nil
}
