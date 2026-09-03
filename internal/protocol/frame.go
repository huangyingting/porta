package protocol

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	Version     = "1"
	ContentType = "application/x-htun-packets"
	MaxPacket   = 65535
)

var ErrFrameTooLarge = errors.New("htun frame exceeds maximum packet size")

// Encoder writes complete IP packets to an ordered hTun byte stream. Encoder
// is safe for concurrent callers because keepalives and packet writes may be
// emitted by different goroutines.
type Encoder struct {
	w  io.Writer
	mu sync.Mutex
}

func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w} }

func (e *Encoder) WritePacket(packet []byte) error {
	if len(packet) > MaxPacket {
		return ErrFrameTooLarge
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(packet)))
	if err := writeAll(e.w, header[:]); err != nil {
		return err
	}
	if len(packet) == 0 {
		return nil
	}
	return writeAll(e.w, packet)
}

// Decoder reads complete IP packets from an ordered hTun byte stream. A nil
// packet represents a zero-length keepalive frame.
type Decoder struct {
	r *bufio.Reader
}

func NewDecoder(r io.Reader) *Decoder { return &Decoder{r: bufio.NewReader(r)} }

func (d *Decoder) ReadPacket() ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(d.r, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 {
		return nil, nil
	}
	if size > MaxPacket {
		return nil, ErrFrameTooLarge
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(d.r, packet); err != nil {
		return nil, fmt.Errorf("read packet payload: %w", err)
	}
	return packet, nil
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
