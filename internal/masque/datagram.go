package masque

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go/quicvarint"
)

var ErrUnknownContext = errors.New("unknown MASQUE context ID")

func EncodeIPPacket(packet []byte) []byte {
	value := make([]byte, 1+len(packet))
	copy(value[1:], packet)
	return value
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
