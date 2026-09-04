package masque

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/quic-go/quic-go/quicvarint"
)

const (
	CapsuleDatagram           uint64 = 0x00
	CapsuleAddressAssign      uint64 = 0x01
	CapsuleAddressRequest     uint64 = 0x02
	CapsuleRouteAdvertisement uint64 = 0x03

	MaxCapsuleSize = 1 << 20
)

var ErrCapsuleTooLarge = errors.New("MASQUE capsule exceeds maximum size")

type Capsule struct {
	Type  uint64
	Value []byte
}

type Encoder struct {
	w      io.Writer
	mu     sync.Mutex
	header [16]byte
}

func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w} }

func (e *Encoder) Write(capsuleType uint64, value []byte) error {
	if len(value) > MaxCapsuleSize {
		return ErrCapsuleTooLarge
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	header := quicvarint.Append(e.header[:0], capsuleType)
	header = quicvarint.Append(header, uint64(len(value)))
	if err := writeAll(e.w, header); err != nil {
		return err
	}
	return writeAll(e.w, value)
}

// WriteIPPacket writes Context ID 0 and the packet without copying its payload.
func (e *Encoder) WriteIPPacket(packet []byte) error {
	if len(packet) >= MaxCapsuleSize {
		return ErrCapsuleTooLarge
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	header := quicvarint.Append(e.header[:0], CapsuleDatagram)
	header = quicvarint.Append(header, uint64(len(packet)+1))
	header = append(header, 0)
	if err := writeAll(e.w, header); err != nil {
		return err
	}
	return writeAll(e.w, packet)
}

// Flush serializes response flushing with capsule writes.
func (e *Encoder) Flush() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if flusher, ok := e.w.(interface{ Flush() }); ok {
		flusher.Flush()
	}
}

type Decoder struct {
	r *bufio.Reader
}

func NewDecoder(r io.Reader) *Decoder { return &Decoder{r: bufio.NewReader(r)} }

func (d *Decoder) Read() (Capsule, error) {
	return d.ReadInto(nil)
}

// ReadInto reads a capsule value into buffer when it has sufficient capacity.
// The returned value is only valid until buffer is reused by the caller.
func (d *Decoder) ReadInto(buffer []byte) (Capsule, error) {
	capsuleType, err := quicvarint.Read(d.r)
	if err != nil {
		return Capsule{}, err
	}
	length, err := quicvarint.Read(d.r)
	if err != nil {
		return Capsule{}, fmt.Errorf("read capsule length: %w", err)
	}
	if length > MaxCapsuleSize {
		return Capsule{}, ErrCapsuleTooLarge
	}
	var value []byte
	if int(length) <= cap(buffer) {
		value = buffer[:int(length)]
	} else {
		value = make([]byte, int(length))
	}
	if _, err := io.ReadFull(d.r, value); err != nil {
		return Capsule{}, fmt.Errorf("read capsule value: %w", err)
	}
	return Capsule{Type: capsuleType, Value: value}, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
