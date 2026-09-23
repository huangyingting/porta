package masque

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

var ErrUnknownContext = errors.New("unknown MASQUE context ID")
var ErrDatagramTimeout = errors.New("HTTP/3 datagram send deadline exceeded")

// quic-go can wait for space in its connection-level datagram queue. Only
// closing that connection can interrupt the wait; stream cancellation cannot.
func BoundedDatagramSend(ctx context.Context, send func([]byte) error, abort func(), timeout time.Duration) func([]byte) error {
	var mu sync.Mutex
	active := 0
	context.AfterFunc(ctx, func() {
		mu.Lock()
		blocked := active != 0
		mu.Unlock()
		if blocked {
			abort()
		}
	})
	return func(value []byte) error {
		mu.Lock()
		if err := ctx.Err(); err != nil {
			mu.Unlock()
			return err
		}
		active++
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		expired := make(chan struct{})
		timer := time.AfterFunc(timeout, func() {
			abort()
			close(expired)
		})
		err := send(value)
		if !timer.Stop() {
			<-expired
			return fmt.Errorf("%w: %w", ErrDatagramTimeout, context.DeadlineExceeded)
		}
		return err
	}
}

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
