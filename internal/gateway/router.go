package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/device"
	"github.com/huangyingting/porta/internal/protocol"
)

var (
	ErrSourceSpoofed = errors.New("packet source does not match tunnel lease")
)

type Session struct {
	Address netip.Addr

	cancel  context.CancelFunc
	once    sync.Once
	ctx     context.Context
	metrics *Metrics
	queue   *packetQueue
}

func (s *Session) Close() {
	s.once.Do(func() {
		s.cancel()
		s.queue.close()
	})
}

func (s *Session) enqueue(packet []byte) {
	if s.ctx != nil && s.ctx.Err() != nil {
		if s.metrics != nil {
			s.metrics.closedSessionDrops.Add(1)
		}
		return
	}
	s.queue.enqueue(packet, time.Now())
}

func (s *Session) ready() <-chan struct{} {
	return s.queue.readySignal()
}

func (s *Session) dequeue() ([]byte, bool) {
	return s.queue.dequeue(time.Now())
}

func (s *Session) queueBytes() int {
	return s.queue.queuedBytes()
}

type Router struct {
	device   device.PacketDevice
	logger   *slog.Logger
	mu       sync.RWMutex
	sessions map[netip.Addr]*sessionGroup
	metrics  atomic.Pointer[Metrics]
}

type sessionGroup struct {
	id              string
	laneCount       int
	lanes           map[int]*Session
	laneConnections map[int]string
	flowMu          sync.Mutex
	flows           map[protocol.FlowKey]flowLane
	collapseWarned  bool
}

type flowLane struct {
	lane     int
	lastSeen time.Time
}

func NewRouter(dev device.PacketDevice, logger *slog.Logger) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	router := &Router{
		device:   dev,
		logger:   logger,
		sessions: make(map[netip.Addr]*sessionGroup),
	}
	router.metrics.Store(&Metrics{})
	return router
}

func (r *Router) Register(parent context.Context, address netip.Addr) (*Session, context.Context) {
	session, ctx := newSession(parent, address, r.metrics.Load(), -1, masquePacketQueueConfig)
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
	outerConnection string,
) (*Session, context.Context, bool, error) {
	if groupID == "" {
		return nil, nil, false, errors.New("router session group ID is required")
	}
	if laneCount < minTunnelLanes || laneCount > maxTunnelLanes || laneIndex < 0 || laneIndex >= laneCount {
		return nil, nil, false, errors.New("invalid router lane configuration")
	}
	session, ctx := newSession(parent, address, r.metrics.Load(), laneIndex, defaultPacketQueueConfig)
	var replacedGroup *sessionGroup
	var replacedLane *Session
	r.mu.Lock()
	group := r.sessions[address]
	if group == nil || group.id != groupID {
		replacedGroup = group
		group = &sessionGroup{
			id:              groupID,
			laneCount:       laneCount,
			lanes:           make(map[int]*Session, laneCount),
			laneConnections: make(map[int]string, laneCount),
			flows:           make(map[protocol.FlowKey]flowLane),
		}
		r.sessions[address] = group
	} else if group.laneCount != laneCount {
		r.mu.Unlock()
		session.Close()
		return nil, nil, false, errors.New("router lane count does not match existing group")
	}
	replacedLane = group.lanes[laneIndex]
	group.lanes[laneIndex] = session
	group.laneConnections[laneIndex] = outerConnection
	collapsed := collapsedLaneGroup(group)
	if collapsed && !group.collapseWarned {
		group.collapseWarned = true
		if metrics := r.metrics.Load(); metrics != nil {
			metrics.laneCollapsedGroups.Add(1)
		}
	}
	r.mu.Unlock()
	closeSessionGroup(replacedGroup)
	if replacedLane != nil {
		replacedLane.Close()
	}
	r.removeSessionWhenDone(ctx, address, groupID, laneIndex, session)
	return session, ctx, collapsed, nil
}

func newSession(
	parent context.Context,
	address netip.Addr,
	metrics *Metrics,
	lane int,
	queueConfig packetQueueConfig,
) (*Session, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	session := &Session{Address: address, cancel: cancel, ctx: ctx, metrics: metrics}
	session.queue = newPacketQueue(queueConfig, metrics, lane)
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
			delete(group.laneConnections, laneIndex)
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
	return r.injectValidated(ctx, packet)
}

func (r *Router) injectValidated(ctx context.Context, packet []byte) error {
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
			r.metrics.Load().invalidTUNDrops.Add(1)
			r.logger.Warn("dropping invalid packet from gateway TUN", "error", err)
			continue
		}

		r.mu.RLock()
		group := r.sessions[info.Destination]
		session := selectLane(group, packet)
		r.mu.RUnlock()
		if session == nil {
			r.metrics.Load().noSessionDrops.Add(1)
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		session.enqueue(packet)
	}
}

func selectLane(group *sessionGroup, packet []byte) *Session {
	if group == nil || len(group.lanes) == 0 {
		return nil
	}
	metadata := protocol.ClassifyIPv4(packet)
	preferred := 0
	if metadata.Class != protocol.PacketClassControl {
		preferred = selectDataLane(group, metadata)
	}
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

func selectDataLane(group *sessionGroup, metadata protocol.PacketMetadata) int {
	group.flowMu.Lock()
	defer group.flowMu.Unlock()
	now := time.Now()
	if assignment, ok := group.flows[metadata.Flow]; ok {
		if group.lanes[assignment.lane] != nil {
			assignment.lastSeen = now
			group.flows[metadata.Flow] = assignment
			return assignment.lane
		}
		delete(group.flows, metadata.Flow)
	}
	if len(group.flows) >= 4096 {
		var (
			oldestFlow protocol.FlowKey
			oldest     time.Time
		)
		for flow, assignment := range group.flows {
			if now.Sub(assignment.lastSeen) >= 2*time.Minute {
				delete(group.flows, flow)
				continue
			}
			if oldest.IsZero() || assignment.lastSeen.Before(oldest) {
				oldestFlow = flow
				oldest = assignment.lastSeen
			}
		}
		if len(group.flows) >= 4096 {
			delete(group.flows, oldestFlow)
		}
	}
	candidates := make([]int, 0, group.laneCount-1)
	for lane := 1; lane < group.laneCount; lane++ {
		if group.lanes[lane] != nil {
			candidates = append(candidates, lane)
		}
	}
	if len(candidates) == 0 {
		return 0
	}
	start := int(metadata.Hash % uint32(len(candidates)))
	selected := candidates[start]
	selectedBytes := group.lanes[selected].queueBytes()
	for offset := 1; offset < len(candidates); offset++ {
		lane := candidates[(start+offset)%len(candidates)]
		queued := group.lanes[lane].queueBytes()
		if queued < selectedBytes {
			selected = lane
			selectedBytes = queued
		}
	}
	group.flows[metadata.Flow] = flowLane{lane: selected, lastSeen: now}
	return selected
}

func collapsedLaneGroup(group *sessionGroup) bool {
	if len(group.lanes) < 2 {
		return false
	}
	connections := make(map[string]struct{}, len(group.laneConnections))
	for lane := range group.lanes {
		connection := group.laneConnections[lane]
		if connection != "" {
			connections[connection] = struct{}{}
		}
	}
	return len(connections) > 0 && len(connections) < len(group.lanes)
}

func packetLane(packet []byte, laneCount int) int {
	if laneCount <= 1 {
		return 0
	}
	metadata := protocol.ClassifyIPv4(packet)
	if metadata.Class == protocol.PacketClassControl {
		return 0
	}
	return 1 + int(metadata.Hash%uint32(laneCount-1))
}
