package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/huangyingting/porta/internal/usage"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const connectIPProtocol = "connect-ip"

var errInvalidClientPacket = errors.New("invalid client packet")

type masqueSession struct {
	HandlerConfig
	mtuDiscovery *masque.MTUResponder
	addressReady chan struct{}
	icmpAfter    time.Time
}

func (config HandlerConfig) serveMasque(w http.ResponseWriter, r *http.Request) {
	c := masqueSession{HandlerConfig: config, addressReady: make(chan struct{}, 1)}
	if r.ProtoMajor < 2 || !isConnectIP(r) {
		http.Error(w, "CONNECT-IP requires HTTP Extended CONNECT", http.StatusBadRequest)
		return
	}
	if r.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		http.Error(w, "Capsule-Protocol: ?1 is required", http.StatusBadRequest)
		return
	}
	clientID := r.Header.Get("X-Porta-Client-ID")
	if !validClientID.MatchString(clientID) {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return
	}
	identity, sessionParent, release, err := c.authorizeSession(r.Context(), r.Header.Get("Authorization"), clientID)
	if err != nil {
		c.Metrics.authenticationFailed()
		w.Header().Set("WWW-Authenticate", `Bearer realm="porta"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	defer release()
	r = r.WithContext(sessionParent)
	if !requireProtocolVersion(w, r) {
		return
	}

	lease, err := c.Pool.Acquire(identity.LeaseID)
	if err != nil {
		http.Error(w, "no tunnel addresses available", http.StatusServiceUnavailable)
		return
	}
	defer c.Pool.Release(lease)
	session, sessionCtx := c.Router.Register(r.Context(), lease.Address)
	defer session.Close()
	stopResponseIO := stopStreamOnCancel(sessionCtx, w, r.Body)
	defer stopResponseIO()

	useDatagrams := false
	if r.ProtoMajor == 3 {
		if settings, ok := w.(http3.Settingser); ok {
			select {
			case <-settings.ReceivedSettings():
				peerSettings := settings.Settings()
				useDatagrams = c.EnableH3Datagrams && peerSettings != nil && peerSettings.EnableDatagrams
			case <-sessionCtx.Done():
				return
			}
		}
	}
	if c.AutoMTU && c.MTU > masque.SafeMTU && useDatagrams && r.Header.Get(masque.MTUDiscoveryHeader) == "1" {
		c.mtuDiscovery, err = masque.NewMTUResponder(c.MTU)
		if err != nil {
			c.Logger.Error("initialize MTU discovery", "error", err)
			http.Error(w, "MTU discovery unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set(masque.MTUDiscoveryHeader, c.mtuDiscovery.Offer())
	}
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.Header().Set("Cache-Control", "no-store")
	setProtocolVersionHeaders(w.Header())
	w.Header().Set("X-Porta-MTU", strconv.Itoa(c.MTU))
	if c.DNS != "" {
		w.Header().Set("X-Porta-DNS", c.DNS)
	}
	w.WriteHeader(http.StatusOK)

	remoteHost := clientAddress(r, c.TrustProxyHeaders)
	transportName := "masque-h2-capsule"
	var stream *http3.Stream
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
		stopIO := onSessionCancel(sessionCtx, func() {
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		})
		defer stopIO()
		if useDatagrams {
			transportName = "masque-h3-datagram"
		} else {
			transportName = "masque-h3-capsule"
		}
	} else {
		flush(w)
	}
	usageSession := c.Usage.Begin(
		"",
		identity.AccountID,
		clientID,
		transportName,
		lease.Address.String(),
		"",
	)
	defer usageSession.Close()
	c.Metrics.connected()
	defer c.Metrics.disconnected()
	c.Logger.Info("tunnel connected", "client_id", clientID, "account_id", identity.AccountID, "address", lease.Address, "transport", transportName, "remote", remoteHost)
	defer c.Logger.Info("tunnel disconnected", "client_id", clientID, "address", lease.Address)

	encoder := masque.NewEncoder(writer)
	var assigned atomic.Bool
	inboundDone := make(chan error, 2)
	var readers sync.WaitGroup
	defer func() {
		session.Close()
		// Unblock control-stream writes before waiting for the reader to exit.
		if stream != nil {
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		} else {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now())
			_ = r.Body.Close()
		}
		readers.Wait()
	}()
	readers.Go(func() {
		c.readMasqueCapsules(sessionCtx, reader, encoder, lease, &assigned, usageSession, inboundDone)
	})
	if useDatagrams {
		readers.Go(func() {
			c.readMasqueDatagrams(sessionCtx, stream, lease, &assigned, usageSession, inboundDone)
		})
	}

	var outgoing <-chan []byte
	ready := c.addressReady
	for {
		select {
		case <-ready:
			outgoing, ready = session.Outgoing, nil
		case packet := <-outgoing:
			if useDatagrams {
				send := func(packet []byte) error { return c.sendMasqueIPPacket(packet, stream.SendDatagram, encoder) }
				if err := c.sendDownlink(sessionCtx, lease, packet, send, usageSession); err != nil {
					c.Logger.Warn("MASQUE send stopped", "client_id", clientID, "error", err)
					return
				}
			} else {
			drain:
				for count := 0; ; count++ {
					if err := c.sendDownlink(sessionCtx, lease, packet, encoder.WriteIPPacket, usageSession); err != nil {
						c.Logger.Warn("MASQUE send stopped", "client_id", clientID, "error", err)
						return
					}
					if count+1 >= streamPacketBatch {
						break
					}
					select {
					case packet = <-session.Outgoing:
					default:
						break drain
					}
				}
				encoder.Flush()
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

func (c HandlerConfig) sendMasqueIPPacket(packet []byte, sendDatagram func([]byte) error, encoder *masque.Encoder) error {
	return masque.SendIPPacket(packet, func(value []byte) error {
		err := sendDatagram(value)
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			c.Metrics.DatagramOversize()
		}
		return err
	}, encoder)
}

func (c *masqueSession) readMasqueCapsules(
	ctx context.Context,
	reader io.Reader,
	encoder *masque.Encoder,
	lease Lease,
	assigned *atomic.Bool,
	usageSession *usage.Session,
	done chan<- error,
) {
	decoder := masque.NewDecoder(reader)
	valueBuffer := make([]byte, c.MTU+16)
	for {
		capsule, err := decoder.ReadInto(valueBuffer)
		if err != nil {
			if errors.Is(err, masque.ErrCapsuleTooLarge) {
				c.Metrics.droppedFromClient()
			}
			done <- err
			return
		}
		switch capsule.Type {
		case masque.CapsuleMTUSelect:
			if c.mtuDiscovery == nil {
				done <- masque.ErrMTUMessage
				return
			}
			wasCommitted := c.mtuDiscovery.Committed()
			selected, err := c.mtuDiscovery.Commit(capsule.Value)
			if err != nil {
				done <- err
				return
			}
			if err := encoder.Write(masque.CapsuleMTUSelected, selected); err != nil {
				done <- err
				return
			}
			encoder.Flush()
			if !wasCommitted {
				c.Logger.Info("tunnel MTU selected", "address", lease.Address, "mtu", c.packetMTU(), "ceiling", c.MTU)
			}
		case masque.CapsuleAddressRequest:
			if err := c.answerAddressRequest(encoder, lease, assigned, capsule.Value); err != nil {
				done <- err
				return
			}
		case masque.CapsuleDatagram:
			if !assigned.Load() {
				c.Metrics.droppedFromClient()
				continue
			}
			packet, err := masque.DecodeIPPacket(capsule.Value)
			if err != nil {
				c.Metrics.droppedFromClient()
				continue
			}
			if err := c.injectMasquePacket(ctx, lease.Address, packet); err != nil {
				if errors.Is(err, errInvalidClientPacket) {
					continue
				}
				done <- err
				return
			}
			usageSession.AddUploaded(uint64(len(packet)), 1)
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

func (c *masqueSession) readMasqueDatagrams(
	ctx context.Context,
	stream *http3.Stream,
	lease Lease,
	assigned *atomic.Bool,
	usageSession *usage.Session,
	done chan<- error,
) {
	for {
		value, err := stream.ReceiveDatagram(ctx)
		if err != nil {
			done <- err
			return
		}
		if c.mtuDiscovery != nil && masque.IsMTUProbe(value) {
			if err := c.mtuDiscovery.Echo(value, stream.SendDatagram); err != nil {
				if errors.Is(err, masque.ErrMTUMessage) {
					c.Metrics.droppedFromClient()
					continue
				}
				done <- err
				return
			}
			continue
		}
		if !assigned.Load() {
			c.Metrics.droppedFromClient()
			continue
		}
		packet, err := masque.DecodeIPPacket(value)
		if err != nil {
			c.Metrics.droppedFromClient()
			continue
		}
		if err := c.injectMasquePacket(ctx, lease.Address, packet); err != nil {
			if errors.Is(err, errInvalidClientPacket) {
				continue
			}
			done <- err
			return
		}
		usageSession.AddUploaded(uint64(len(packet)), 1)
	}
}

func (c *masqueSession) answerAddressRequest(
	encoder *masque.Encoder,
	lease Lease,
	assigned *atomic.Bool,
	value []byte,
) (err error) {
	if c.mtuDiscovery != nil && !c.mtuDiscovery.Committed() {
		return fmt.Errorf("%w: MTU selection must precede address assignment", masque.ErrMTUMessage)
	}
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
	if assignedIPv4 {
		previous := assigned.Load()
		// QUIC can deliver ADDRESS_ASSIGN before Write returns. Accept the
		// peer's first datagram as soon as it can observe its assigned address.
		assigned.Store(true)
		defer func() {
			if err != nil {
				assigned.Store(previous)
			}
		}()
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
	}
	encoder.Flush()
	if assignedIPv4 {
		select {
		case c.addressReady <- struct{}{}:
		default:
		}
	}
	return nil
}

func (c *masqueSession) packetMTU() int {
	if c.mtuDiscovery != nil {
		return c.mtuDiscovery.MTU()
	}
	return c.MTU
}

func (c *masqueSession) injectMasquePacket(ctx context.Context, address netip.Addr, packet []byte) error {
	if mtu := c.packetMTU(); len(packet) > mtu {
		c.Metrics.droppedFromClient()
		return fmt.Errorf("%w: packet length %d exceeds tunnel MTU %d", errInvalidClientPacket, len(packet), mtu)
	}
	info, err := protocol.ParseIPv4(packet)
	if err != nil || info.Source != address {
		c.Metrics.droppedFromClient()
		return errInvalidClientPacket
	}
	if err := c.Router.injectValidated(ctx, packet); err != nil {
		return err
	}
	c.Metrics.receivedFromClient()
	return nil
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
