package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Transport string

const (
	TransportHTTP2 Transport = "h2"
	TransportHTTP3 Transport = "h3"
)

type Config struct {
	URL       string
	Token     string
	ClientID  string
	Transport Transport
	TLSConfig *tls.Config
	Timeout   time.Duration

	// PacketConn and RemoteAddr allow callers such as Android VPN clients to
	// create and protect the UDP socket before QUIC starts. They must be set
	// together and are only used by HTTP/3 MASQUE. PacketConn remains owned by
	// the caller and is never closed by Conn.
	PacketConn net.PacketConn
	RemoteAddr net.Addr
}

type Lease struct {
	Address netip.Prefix
	Gateway netip.Addr
	DNS     netip.Addr
	MTU     int
}

type Conn struct {
	Lease      Lease
	RemoteAddr net.Addr

	sendPacket    func([]byte) error
	receivePacket func() ([]byte, error)
	closePacket   func() error
	close         sync.Once
}

func Dial(ctx context.Context, config Config) (*Conn, error) {
	return dialMasque(ctx, config)
}

func (c *Conn) Send(packet []byte) error {
	return c.sendPacket(packet)
}

func (c *Conn) Receive() ([]byte, error) {
	return c.receivePacket()
}

func (c *Conn) Close() error {
	var result error
	c.close.Do(func() {
		result = c.closePacket()
	})
	return result
}
