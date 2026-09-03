package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/htun-project/htun/internal/device"
	"github.com/htun-project/htun/internal/protocol"
)

var (
	ErrSourceSpoofed = errors.New("packet source does not match tunnel lease")
)

type Session struct {
	Address  netip.Addr
	Outgoing <-chan []byte

	outgoing chan []byte
	cancel   context.CancelFunc
	once     sync.Once
}

func (s *Session) Close() {
	s.once.Do(func() { s.cancel() })
}

func (s *Session) enqueue(packet []byte) {
	select {
	case s.outgoing <- packet:
		return
	default:
	}

	// VPN traffic is packet-oriented. Drop stale congestion rather than
	// disconnecting the whole tunnel when a client briefly falls behind.
	select {
	case <-s.outgoing:
	default:
	}
	select {
	case s.outgoing <- packet:
	default:
	}
}

type Router struct {
	device   device.PacketDevice
	logger   *slog.Logger
	mu       sync.RWMutex
	sessions map[netip.Addr]*sessionGroup
}

type sessionGroup struct {
	id        string
	laneCount int
	lanes     map[int]*Session
}

func NewRouter(dev device.PacketDevice, logger *slog.Logger) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	return &Router{
		device:   dev,
		logger:   logger,
		sessions: make(map[netip.Addr]*sessionGroup),
	}
}

func (r *Router) Register(parent context.Context, address netip.Addr) (*Session, context.Context) {
	session, ctx := newSession(parent, address)
	r.mu.Lock()
	previous := r.sessions[address]
	r.sessions[address] = &sessionGroup{
		laneCount: 1,
		lanes:     map[int]*Session{0: session},
	}
	r.mu.Unlock()
	closeSessionGroup(previous)
	r.removeSessionWhenDone(ctx, address, "", 0, session)
	return session, ctx
}

func (r *Router) RegisterGroup(
	parent context.Context,
	address netip.Addr,
	groupID string,
	laneIndex int,
	laneCount int,
) (*Session, context.Context, error) {
	if groupID == "" {
		return nil, nil, errors.New("router session group ID is required")
	}
	if laneCount < 2 || laneCount > 8 || laneIndex < 0 || laneIndex >= laneCount {
		return nil, nil, errors.New("invalid router lane configuration")
	}
	session, ctx := newSession(parent, address)
	var replacedGroup *sessionGroup
	var replacedLane *Session
	r.mu.Lock()
	group := r.sessions[address]
	if group == nil || group.id != groupID {
		replacedGroup = group
		group = &sessionGroup{
			id:        groupID,
			laneCount: laneCount,
			lanes:     make(map[int]*Session, laneCount),
		}
		r.sessions[address] = group
	} else if group.laneCount != laneCount {
		r.mu.Unlock()
		session.Close()
		return nil, nil, errors.New("router lane count does not match existing group")
	}
	replacedLane = group.lanes[laneIndex]
	group.lanes[laneIndex] = session
	r.mu.Unlock()
	closeSessionGroup(replacedGroup)
	if replacedLane != nil {
		replacedLane.Close()
	}
	r.removeSessionWhenDone(ctx, address, groupID, laneIndex, session)
	return session, ctx, nil
}

func newSession(parent context.Context, address netip.Addr) (*Session, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	queue := make(chan []byte, 256)
	session := &Session{Address: address, Outgoing: queue, outgoing: queue, cancel: cancel}
	return session, ctx
}

func closeSessionGroup(group *sessionGroup) {
	if group == nil {
		return
	}
	for _, session := range group.lanes {
		session.Close()
	}
}

func (r *Router) removeSessionWhenDone(
	ctx context.Context,
	address netip.Addr,
	groupID string,
	laneIndex int,
	session *Session,
) {
	go func() {
		<-ctx.Done()
		r.mu.Lock()
		group := r.sessions[address]
		if group != nil && group.id == groupID && group.lanes[laneIndex] == session {
			delete(group.lanes, laneIndex)
		}
		if group != nil && len(group.lanes) == 0 {
			delete(r.sessions, address)
		}
		r.mu.Unlock()
	}()
}

func (r *Router) Inject(ctx context.Context, lease netip.Addr, packet []byte) error {
	info, err := protocol.ParseIPv4(packet)
	if err != nil {
		return err
	}
	if info.Source != lease {
		return fmt.Errorf("%w: got %s want %s", ErrSourceSpoofed, info.Source, lease)
	}
	return r.device.WritePacket(ctx, packet)
}

func (r *Router) Run(ctx context.Context) error {
	for {
		packet, err := r.device.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read gateway TUN: %w", err)
		}
		info, err := protocol.ParseIPv4(packet)
		if err != nil {
			r.logger.Warn("dropping invalid packet from gateway TUN", "error", err)
			continue
		}

		r.mu.RLock()
		group := r.sessions[info.Destination]
		session := selectLane(group, packet)
		r.mu.RUnlock()
		if session == nil {
			continue
		}
		copyOfPacket := append([]byte(nil), packet...)
		if ctx.Err() != nil {
			return nil
		}
		session.enqueue(copyOfPacket)
	}
}

func selectLane(group *sessionGroup, packet []byte) *Session {
	if group == nil || len(group.lanes) == 0 {
		return nil
	}
	preferred := packetLane(packet, group.laneCount)
	if session := group.lanes[preferred]; session != nil {
		return session
	}
	for lane := 0; lane < group.laneCount; lane++ {
		if session := group.lanes[lane]; session != nil {
			return session
		}
	}
	return nil
}

func packetLane(packet []byte, laneCount int) int {
	if laneCount <= 1 || len(packet) < 20 {
		return 0
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return 0
	}
	protocolNumber := packet[9]
	if (protocolNumber == 6 || protocolNumber == 17) && len(packet) >= headerLength+4 {
		sourcePort := int(packet[headerLength])<<8 | int(packet[headerLength+1])
		destinationPort := int(packet[headerLength+2])<<8 | int(packet[headerLength+3])
		if sourcePort == 53 || destinationPort == 53 {
			return 0
		}
	}
	hash := uint32(2166136261)
	hash ^= uint32(protocolNumber)
	hash *= 16777619
	for _, value := range packet[12:20] {
		hash ^= uint32(value)
		hash *= 16777619
	}
	if (protocolNumber == 6 || protocolNumber == 17) && len(packet) >= headerLength+4 {
		for _, value := range packet[headerLength : headerLength+4] {
			hash ^= uint32(value)
			hash *= 16777619
		}
	}
	return 1 + int(hash%uint32(laneCount-1))
}
