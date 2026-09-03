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
	ErrSlowClient    = errors.New("client receive queue is full")
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

type Router struct {
	device   device.PacketDevice
	logger   *slog.Logger
	mu       sync.RWMutex
	sessions map[netip.Addr]*Session
}

func NewRouter(dev device.PacketDevice, logger *slog.Logger) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	return &Router{
		device:   dev,
		logger:   logger,
		sessions: make(map[netip.Addr]*Session),
	}
}

func (r *Router) Register(parent context.Context, address netip.Addr) (*Session, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	queue := make(chan []byte, 256)
	session := &Session{Address: address, Outgoing: queue, outgoing: queue, cancel: cancel}

	r.mu.Lock()
	previous := r.sessions[address]
	r.sessions[address] = session
	r.mu.Unlock()
	if previous != nil {
		previous.Close()
	}

	go func() {
		<-ctx.Done()
		r.mu.Lock()
		if r.sessions[address] == session {
			delete(r.sessions, address)
		}
		r.mu.Unlock()
	}()
	return session, ctx
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
		session := r.sessions[info.Destination]
		r.mu.RUnlock()
		if session == nil {
			continue
		}
		copyOfPacket := append([]byte(nil), packet...)
		select {
		case session.outgoing <- copyOfPacket:
		case <-ctx.Done():
			return nil
		default:
			r.logger.Warn("closing slow tunnel client", "address", session.Address)
			session.Close()
		}
	}
}
