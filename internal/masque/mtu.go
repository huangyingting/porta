package masque

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	MTUDiscoveryHeader = "X-Porta-MTU-Discovery"
	CapsuleMTUSelect   = 0xff7000
	CapsuleMTUSelected = 0xff7001
	SafeMTU            = 1100
	MaxDiscoveredMTU   = 1400
	mtuProbeContext    = 1
	maxMTUProbes       = 16
)

var ErrMTUMessage = errors.New("invalid MTU discovery message")

type MTUToken [16]byte

func ParseMTUToken(value string) (MTUToken, error) {
	var token MTUToken
	if len(value) != 2*len(token) {
		return token, ErrMTUMessage
	}
	data, err := hex.DecodeString(value)
	if err != nil || len(data) != len(token) {
		return token, ErrMTUMessage
	}
	copy(token[:], data)
	return token, nil
}

type MTUProbe struct {
	Token    MTUToken
	Sequence uint16
	Size     int
}

// The probe occupies exactly as much HTTP Datagram payload as Context ID 0
// plus an inner IP packet of Size bytes. It is never carried in a capsule.
func EncodeMTUProbe(probe MTUProbe) ([]byte, error) {
	if probe.Size < SafeMTU || probe.Size > MaxDiscoveredMTU || probe.Sequence == 0 {
		return nil, ErrMTUMessage
	}
	data := make([]byte, probe.Size+1)
	data[0] = mtuProbeContext
	copy(data[1:17], probe.Token[:])
	binary.BigEndian.PutUint16(data[17:19], probe.Sequence)
	binary.BigEndian.PutUint16(data[19:21], uint16(probe.Size))
	return data, nil
}

func IsMTUProbe(data []byte) bool { return len(data) != 0 && data[0] == mtuProbeContext }

func DecodeMTUProbe(data []byte) (MTUProbe, error) {
	var probe MTUProbe
	if !IsMTUProbe(data) || len(data) < SafeMTU+1 || len(data) > MaxDiscoveredMTU+1 {
		return probe, ErrMTUMessage
	}
	copy(probe.Token[:], data[1:17])
	probe.Sequence = binary.BigEndian.Uint16(data[17:19])
	probe.Size = int(binary.BigEndian.Uint16(data[19:21]))
	if probe.Sequence == 0 || probe.Size != len(data)-1 {
		return probe, ErrMTUMessage
	}
	for _, value := range data[21:] {
		if value != 0 {
			return probe, ErrMTUMessage
		}
	}
	return probe, nil
}

func EncodeMTUSelection(token MTUToken, mtu int) []byte {
	data := make([]byte, 18)
	copy(data, token[:])
	binary.BigEndian.PutUint16(data[16:], uint16(mtu))
	return data
}

func DecodeMTUSelection(data []byte, token MTUToken) (int, error) {
	if len(data) != 18 || string(data[:16]) != string(token[:]) {
		return 0, ErrMTUMessage
	}
	return int(binary.BigEndian.Uint16(data[16:])), nil
}

type MTUResponder struct {
	mu        sync.Mutex
	token     MTUToken
	maximum   int
	selected  atomic.Int32
	probes    int
	proven    map[int]bool
	expires   time.Time
	committed bool
}

func NewMTUResponder(maximum int) (*MTUResponder, error) {
	if maximum <= SafeMTU || maximum > 9000 {
		return nil, ErrMTUMessage
	}
	p := &MTUResponder{
		maximum: min(maximum, MaxDiscoveredMTU),
		proven:  make(map[int]bool), expires: time.Now().Add(3 * time.Second),
	}
	if _, err := rand.Read(p.token[:]); err != nil {
		return nil, err
	}
	p.selected.Store(int32(maximum))
	return p, nil
}

func (p *MTUResponder) Offer() string { return hex.EncodeToString(p.token[:]) }

func (p *MTUResponder) MTU() int {
	return int(p.selected.Load())
}

func (p *MTUResponder) Committed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.committed
}

func (p *MTUResponder) Echo(data []byte, send func([]byte) error) error {
	probe, err := DecodeMTUProbe(data)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.committed || time.Now().After(p.expires) || p.probes >= maxMTUProbes ||
		probe.Token != p.token || probe.Size > p.maximum {
		return ErrMTUMessage
	}
	p.probes++
	if err := send(data); err != nil {
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			return nil
		}
		return err
	}
	p.proven[probe.Size] = true
	return nil
}

func (p *MTUResponder) Commit(data []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	mtu, err := DecodeMTUSelection(data, p.token)
	if err != nil || mtu < SafeMTU || mtu > p.maximum ||
		(mtu > SafeMTU && !p.proven[mtu]) || (p.committed && mtu != p.MTU()) {
		return nil, ErrMTUMessage
	}
	p.selected.Store(int32(mtu))
	p.committed = true
	return EncodeMTUSelection(p.token, mtu), nil
}

// DiscoverMTU raises the baseline only after an exact-size datagram echo proves
// delivery in both directions. Loss only prevents an increase, never live
// interface resizing. QUIC's local size limits remain authoritative.
func DiscoverMTU(ctx context.Context, maximum int, token MTUToken, send func([]byte) error, echoes <-chan MTUProbe, failures <-chan error) (int, error) {
	return discoverMTU(ctx, maximum, token, send, echoes, failures, 750*time.Millisecond, 150*time.Millisecond)
}

func discoverMTU(ctx context.Context, maximum int, token MTUToken, send func([]byte) error, echoes <-chan MTUProbe, failures <-chan error, budget, wait time.Duration) (int, error) {
	if maximum <= SafeMTU {
		return 0, ErrMTUMessage
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	maximum = min(maximum, MaxDiscoveredMTU)
	sizes := []int{SafeMTU}
	for _, size := range []int{1152, 1200, 1280, 1360, 1400} {
		if size < maximum {
			sizes = append(sizes, size)
		}
	}
	sizes = append(sizes, maximum)
	best := SafeMTU
	var sequence uint16
	for _, size := range sizes {
		confirmed := false
		for attempt := 0; attempt < 2 && !confirmed; attempt++ {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if discoveryCtx.Err() != nil {
				return best, nil
			}
			sequence++
			probe := MTUProbe{Token: token, Sequence: sequence, Size: size}
			data, err := EncodeMTUProbe(probe)
			if err != nil {
				return 0, err
			}
			if err := send(data); err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					return best, nil
				}
				return 0, err
			}
			timer := time.NewTimer(wait)
		waitEcho:
			for {
				select {
				case echo, ok := <-echoes:
					if !ok {
						timer.Stop()
						return 0, ErrMTUMessage
					}
					if echo == probe {
						confirmed = true
						break waitEcho
					}
				case err, ok := <-failures:
					timer.Stop()
					if !ok || err == nil {
						return 0, ErrMTUMessage
					}
					return 0, err
				case <-timer.C:
					break waitEcho
				case <-discoveryCtx.Done():
					timer.Stop()
					if ctx.Err() != nil {
						return 0, ctx.Err()
					}
					return best, nil
				}
			}
			timer.Stop()
		}
		if !confirmed {
			return best, nil
		}
		best = size
	}
	return best, nil
}
