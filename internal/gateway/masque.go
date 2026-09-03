package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"

	"github.com/htun-project/htun/internal/masque"
	"github.com/htun-project/htun/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const connectIPProtocol = "connect-ip"

func (c HandlerConfig) serveMasque(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor < 2 || !isConnectIP(r) {
		http.Error(w, "CONNECT-IP requires HTTP Extended CONNECT", http.StatusBadRequest)
		return
	}
	if r.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		http.Error(w, "Capsule-Protocol: ?1 is required", http.StatusBadRequest)
		return
	}
	if !authorized(r.Header.Get("Authorization"), c.Token) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="htun"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	clientID := r.Header.Get("X-HTun-Client-ID")
	if !validClientID.MatchString(clientID) {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return
	}

	lease, err := c.Pool.Acquire(clientID)
	if err != nil {
		http.Error(w, "no tunnel addresses available", http.StatusServiceUnavailable)
		return
	}
	defer c.Pool.Release(lease)
	session, sessionCtx := c.Router.Register(r.Context(), lease.Address)
	defer session.Close()

	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-HTun-MTU", strconv.Itoa(c.MTU))
	if c.DNS != "" {
		w.Header().Set("X-HTun-DNS", c.DNS)
	}
	w.WriteHeader(http.StatusOK)

	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	transportName := "masque-h2-capsule"
	var stream *http3.Stream
	useDatagrams := false
	reader := io.Reader(r.Body)
	writer := io.Writer(w)
	if r.ProtoMajor == 3 {
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			return
		}
		stream = streamer.HTTPStream()
		defer stream.Close()
		defer stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		reader, writer = stream, stream
		if settings, ok := w.(http3.Settingser); ok {
			useDatagrams = c.EnableH3Datagrams && settings.Settings().EnableDatagrams
		}
		if useDatagrams {
			transportName = "masque-h3-datagram"
		} else {
			transportName = "masque-h3-capsule"
		}
	} else {
		flush(w)
	}

	c.Logger.Info("tunnel connected", "client_id", clientID, "address", lease.Address, "transport", transportName, "remote", remoteHost)
	defer c.Logger.Info("tunnel disconnected", "client_id", clientID, "address", lease.Address)

	encoder := masque.NewEncoder(writer)
	var assigned atomic.Bool
	inboundDone := make(chan error, 2)
	go c.readMasqueCapsules(sessionCtx, reader, encoder, w, lease, &assigned, inboundDone)
	if useDatagrams {
		go c.readMasqueDatagrams(sessionCtx, stream, lease, &assigned, inboundDone)
	}

	for {
		select {
		case packet := <-session.Outgoing:
			value := masque.EncodeIPPacket(packet)
			if useDatagrams {
				if err := stream.SendDatagram(value); err != nil {
					return
				}
			} else {
				if err := encoder.Write(masque.CapsuleDatagram, value); err != nil {
					return
				}
				flush(w)
			}
		case err := <-inboundDone:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
				c.Logger.Warn("MASQUE receive stopped", "client_id", clientID, "error", err)
			}
			return
		case <-sessionCtx.Done():
			return
		}
	}
}

func (c HandlerConfig) readMasqueCapsules(
	ctx context.Context,
	reader io.Reader,
	encoder *masque.Encoder,
	w http.ResponseWriter,
	lease Lease,
	assigned *atomic.Bool,
	done chan<- error,
) {
	decoder := masque.NewDecoder(reader)
	for {
		capsule, err := decoder.Read()
		if err != nil {
			done <- err
			return
		}
		switch capsule.Type {
		case masque.CapsuleAddressRequest:
			if err := c.answerAddressRequest(encoder, w, lease, assigned, capsule.Value); err != nil {
				done <- err
				return
			}
		case masque.CapsuleDatagram:
			if !assigned.Load() {
				continue
			}
			packet, err := masque.DecodeIPPacket(capsule.Value)
			if err != nil {
				if errors.Is(err, masque.ErrUnknownContext) {
					continue
				}
				done <- err
				return
			}
			if err := c.injectMasquePacket(ctx, lease.Address, packet); err != nil {
				done <- err
				return
			}
		case masque.CapsuleAddressAssign:
			if _, err := masque.DecodeAddressAssign(capsule.Value); err != nil {
				done <- err
				return
			}
		case masque.CapsuleRouteAdvertisement:
			if _, err := masque.DecodeRouteAdvertisement(capsule.Value); err != nil {
				done <- err
				return
			}
		default:
			// RFC 9297 requires unknown capsule types to be skipped.
		}
	}
}

func (c HandlerConfig) readMasqueDatagrams(
	ctx context.Context,
	stream *http3.Stream,
	lease Lease,
	assigned *atomic.Bool,
	done chan<- error,
) {
	for {
		value, err := stream.ReceiveDatagram(ctx)
		if err != nil {
			done <- err
			return
		}
		if !assigned.Load() {
			continue
		}
		packet, err := masque.DecodeIPPacket(value)
		if err != nil {
			if errors.Is(err, masque.ErrUnknownContext) {
				continue
			}
			done <- err
			return
		}
		if err := c.injectMasquePacket(ctx, lease.Address, packet); err != nil {
			done <- err
			return
		}
	}
}

func (c HandlerConfig) answerAddressRequest(
	encoder *masque.Encoder,
	w http.ResponseWriter,
	lease Lease,
	assigned *atomic.Bool,
	value []byte,
) error {
	requests, err := masque.DecodeAddressRequest(value)
	if err != nil {
		return err
	}
	responses := make([]masque.Address, 0, len(requests))
	assignedIPv4 := assigned.Load()
	requestAssignedIPv4 := false
	for _, request := range requests {
		response := masque.Address{RequestID: request.RequestID}
		if request.Prefix.Addr().Is4() && !requestAssignedIPv4 {
			response.Prefix = netip.PrefixFrom(lease.Address, 32)
			requestAssignedIPv4 = true
			assignedIPv4 = true
		} else if request.Prefix.Addr().Is4() {
			response.Prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 32)
		} else {
			response.Prefix = netip.PrefixFrom(netip.IPv6Unspecified(), 128)
		}
		responses = append(responses, response)
	}
	if assigned.Load() && !requestAssignedIPv4 {
		responses = append(responses, masque.Address{
			RequestID: 0,
			Prefix:    netip.PrefixFrom(lease.Address, 32),
		})
	}
	assignment, err := masque.EncodeAddressAssign(responses)
	if err != nil {
		return err
	}
	if err := encoder.Write(masque.CapsuleAddressAssign, assignment); err != nil {
		return err
	}
	if assignedIPv4 {
		routes, err := masque.EncodeRouteAdvertisement([]masque.Route{{
			Start: netip.MustParseAddr("0.0.0.0"),
			End:   netip.MustParseAddr("255.255.255.255"),
		}})
		if err != nil {
			return err
		}
		if err := encoder.Write(masque.CapsuleRouteAdvertisement, routes); err != nil {
			return err
		}
		assigned.Store(true)
	}
	flush(w)
	return nil
}

func (c HandlerConfig) injectMasquePacket(ctx context.Context, address netip.Addr, packet []byte) error {
	if len(packet) > c.MTU {
		return fmt.Errorf("packet length %d exceeds tunnel MTU %d", len(packet), c.MTU)
	}
	if _, err := protocol.ParseIPv4(packet); err != nil {
		return err
	}
	return c.Router.Inject(ctx, address, packet)
}

func isConnectIP(r *http.Request) bool {
	if r.Method != http.MethodConnect {
		return false
	}
	if r.ProtoMajor == 3 {
		return r.Proto == connectIPProtocol
	}
	return r.Header.Get(":protocol") == connectIPProtocol
}
