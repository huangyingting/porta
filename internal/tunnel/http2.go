package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/protocol"
	"golang.org/x/net/http2"
)

const (
	http2LaneCount           = 4
	http2UploadBatchPackets  = 16
	http2UploadBatchBytes    = 16 << 10
	http2DownstreamPackets   = 64
	http2ControlBurst        = 4
	http2FlowLimit           = 4096
	http2FlowIdle            = 2 * time.Minute
	http2LaneRetryInitial    = 100 * time.Millisecond
	http2LaneRetryMaximum    = 2 * time.Second
	http2TransportReadIdle   = 30 * time.Second
	http2TransportPing       = 10 * time.Second
	http2MinimumSessionIDLen = 16
)

type http2FlowAssignment struct {
	lane     int
	lastSeen time.Time
}

type http2Lane struct {
	index      int
	upload     *http2UploadQueue
	downstream chan []byte
	active     atomic.Bool
	attempts   atomic.Uint64

	mu         sync.Mutex
	remoteAddr net.Addr
	lastErr    error
}

type http2Group struct {
	ctx      context.Context
	cancel   context.CancelFunc
	config   Config
	endpoint *url.URL
	tls      *tls.Config
	session  string
	lanes    [http2LaneCount]*http2Lane

	retryInitial    time.Duration
	retryMaximum    time.Duration
	recoveryTimeout time.Duration
	now             func() time.Time

	leaseMu  sync.Mutex
	lease    Lease
	leaseSet bool
	proofMu  sync.Mutex

	flowMu sync.Mutex
	flows  map[protocol.FlowKey]http2FlowAssignment

	receiveMu     sync.Mutex
	nextDataLane  int
	controlBudget int
	downloadReady chan struct{}
	stateChanged  chan struct{}
	established   atomic.Bool
	workers       sync.WaitGroup
	closeOnce     sync.Once
	failureOnce   sync.Once
	failureMu     sync.Mutex
	failureErr    error
	failureSignal chan struct{}
}

type http2LaneConnection struct {
	writer    *io.PipeWriter
	body      io.ReadCloser
	transport *http2.Transport
	remote    net.Addr
	closeOnce sync.Once
}

func dialFramedHTTP2(
	parent context.Context,
	config Config,
	masqueURL *url.URL,
	tlsConfig *tls.Config,
) (*Conn, error) {
	endpoint := *masqueURL
	endpoint.Path = protocol.TunnelPath
	sessionID, err := newHTTP2SessionID()
	if err != nil {
		return nil, PermanentError{Err: fmt.Errorf("create HTTP/2 lane session: %w", err)}
	}
	ctx, cancel := context.WithCancel(parent)
	group := &http2Group{
		ctx:             ctx,
		cancel:          cancel,
		config:          config,
		endpoint:        &endpoint,
		tls:             tlsConfig,
		session:         sessionID,
		retryInitial:    http2LaneRetryInitial,
		retryMaximum:    http2LaneRetryMaximum,
		recoveryTimeout: config.Timeout,
		now:             time.Now,
		flows:           make(map[protocol.FlowKey]http2FlowAssignment),
		nextDataLane:    1,
		controlBudget:   http2ControlBurst,
		downloadReady:   make(chan struct{}, 1),
		stateChanged:    make(chan struct{}, 1),
		failureSignal:   make(chan struct{}),
	}
	for index := range http2LaneCount {
		upload := newHTTP2UploadQueue(defaultHTTP2QueueConfig)
		upload.deactivateAndClear()
		group.lanes[index] = &http2Lane{
			index:      index,
			upload:     upload,
			downstream: make(chan []byte, http2DownstreamPackets),
		}
		group.workers.Add(1)
		go group.runLane(group.lanes[index])
	}

	if err := group.waitForStartup(); err != nil {
		_ = group.close()
		return nil, err
	}
	group.established.Store(true)
	group.workers.Add(1)
	go group.monitorCapacity()

	lease := group.leaseSnapshot()
	remoteAddr := group.laneRemoteAddr(0)
	return &Conn{
		Lease:         lease,
		RemoteAddr:    remoteAddr,
		DeliveryMode:  DeliveryModeFramed,
		MTUAutomatic:  false,
		MTUCeiling:    0,
		sendPacket:    group.send,
		receivePacket: group.receive,
		closePacket:   group.close,
	}, nil
}

func newHTTP2SessionID() (string, error) {
	var value [18]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	session := base64.RawURLEncoding.EncodeToString(value[:])
	if len(session) < http2MinimumSessionIDLen {
		return "", errors.New("generated lane session is too short")
	}
	return session, nil
}

func (g *http2Group) runLane(lane *http2Lane) {
	defer g.workers.Done()
	backoff := g.retryInitial
	for {
		if g.ctx.Err() != nil {
			return
		}
		lane.attempts.Add(1)
		connection, lease, err := g.connectLane(lane.index)
		if err != nil {
			g.recordLaneError(lane, err)
			if isPermanent(err) {
				g.fail(err)
				return
			}
			if !g.waitRetry(backoff) {
				return
			}
			backoff = min(backoff*2, g.retryMaximum)
			continue
		}
		if err := g.acceptLease(lease); err != nil {
			connection.close(err)
			g.recordLaneError(lane, err)
			g.fail(err)
			return
		}

		backoff = g.retryInitial
		g.activateLane(lane, connection.remote)
		err = connection.run(g, lane)
		g.deactivateLane(lane)
		connection.close(err)
		if g.ctx.Err() != nil {
			return
		}
		if err == nil {
			err = io.EOF
		}
		g.recordLaneError(lane, err)
		if isPermanent(err) {
			g.fail(err)
			return
		}
		if !g.waitRetry(backoff) {
			return
		}
		backoff = min(backoff*2, g.retryMaximum)
	}
}

func (g *http2Group) connectLane(index int) (*http2LaneConnection, Lease, error) {
	reader, writer := io.Pipe()
	primed := make(chan error, 1)
	go func() {
		primed <- protocol.NewEncoder(writer).WritePacket(nil)
	}()
	transport := &http2.Transport{
		TLSClientConfig: g.tls.Clone(),
		ReadIdleTimeout: http2TransportReadIdle,
		PingTimeout:     http2TransportPing,
	}
	var remoteAddr net.Addr
	transport.DialTLSContext = func(ctx context.Context, network, address string, options *tls.Config) (net.Conn, error) {
		if g.config.DialAddress != "" {
			address = g.config.DialAddress
		}
		connection, err := (&tls.Dialer{Config: options}).DialContext(ctx, network, address)
		if err == nil {
			remoteAddr = connection.RemoteAddr()
		}
		return connection, err
	}
	request, err := http.NewRequestWithContext(g.ctx, http.MethodPost, g.endpoint.String(), reader)
	if err != nil {
		_ = reader.Close()
		_ = writer.CloseWithError(err)
		transport.CloseIdleConnections()
		return nil, Lease{}, PermanentError{Err: err}
	}
	request.ContentLength = -1
	request.Header.Set("Content-Type", protocol.ContentType)
	request.Header.Set("Authorization", "Bearer "+g.config.Token)
	request.Header.Set(protocol.HeaderVersion, protocol.Version)
	request.Header.Set("X-Porta-Lane-Session", g.session)
	request.Header.Set("X-Porta-Lane", strconv.Itoa(index))
	request.Header.Set("X-Porta-Lanes", strconv.Itoa(http2LaneCount))
	g.proofMu.Lock()
	proof, err := g.config.DeviceProof(request.Method, request.URL.Path)
	g.proofMu.Unlock()
	if err != nil {
		_ = reader.Close()
		_ = writer.CloseWithError(err)
		transport.CloseIdleConnections()
		return nil, Lease{}, PermanentError{Err: fmt.Errorf("create device proof: %w", err)}
	}
	deviceauth.Apply(request, proof)

	response, err := timedRoundTrip(g.ctx, transport, request, g.config.Timeout)
	if err != nil {
		_ = reader.Close()
		_ = writer.CloseWithError(err)
		transport.CloseIdleConnections()
		return nil, Lease{}, preSessionFailure(fmt.Errorf("open HTTP/2 lane %d: %w", index, err))
	}
	if err := <-primed; err != nil {
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, Lease{}, preSessionFailure(fmt.Errorf("prime HTTP/2 lane %d: %w", index, err))
	}
	if err := validateHTTP2TunnelResponse(response, g.session, index); err != nil {
		_ = writer.CloseWithError(err)
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, Lease{}, err
	}
	lease, err := leaseFromHTTP2Headers(response.Header)
	if err != nil {
		_ = writer.CloseWithError(err)
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, Lease{}, err
	}
	return &http2LaneConnection{
		writer: writer, body: response.Body, transport: transport, remote: remoteAddr,
	}, lease, nil
}

func (c *http2LaneConnection) run(group *http2Group, lane *http2Lane) error {
	ctx, cancel := context.WithCancel(group.ctx)
	defer cancel()
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		errs <- group.uploadLane(ctx, lane, c.writer)
	}()
	go func() {
		defer workers.Done()
		errs <- group.downloadLane(ctx, lane, c.body)
	}()
	err := <-errs
	cancel()
	c.close(err)
	workers.Wait()
	return err
}

func (c *http2LaneConnection) close(err error) {
	c.closeOnce.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		_ = c.writer.CloseWithError(err)
		_ = c.body.Close()
		c.transport.CloseIdleConnections()
	})
}

func (g *http2Group) uploadLane(
	ctx context.Context,
	lane *http2Lane,
	writer io.Writer,
) error {
	buffered := bufio.NewWriterSize(writer, http2UploadBatchBytes)
	encoder := protocol.NewEncoder(buffered)
	for {
		batch, ok := lane.upload.takeBatch(ctx, g.now, http2UploadBatchPackets, http2UploadBatchBytes)
		if !ok {
			if err := ctx.Err(); err != nil {
				return err
			}
			return net.ErrClosed
		}
		for _, packet := range batch {
			if err := encoder.WritePacket(packet); err != nil {
				return err
			}
		}
		if err := buffered.Flush(); err != nil {
			return err
		}
	}
}

func (g *http2Group) downloadLane(
	ctx context.Context,
	lane *http2Lane,
	reader io.Reader,
) error {
	lease := g.leaseSnapshot()
	decoder := protocol.NewDecoder(reader)
	buffer := make([]byte, lease.MTU)
	for {
		packet, err := decoder.ReadPacketInto(buffer)
		if err != nil {
			return err
		}
		if len(packet) == 0 || len(packet) > lease.MTU {
			continue
		}
		info, err := protocol.ParseIPv4(packet)
		if err != nil || info.Destination != lease.Address.Addr() {
			continue
		}
		owned := append([]byte(nil), packet...)
		select {
		case lane.downstream <- owned:
			g.signalDownload()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *http2Group) send(packet []byte) error {
	if err := g.failure(); err != nil {
		return err
	}
	if err := g.ctx.Err(); err != nil {
		return err
	}
	lease := g.leaseSnapshot()
	if len(packet) > lease.MTU {
		return fmt.Errorf("packet length %d exceeds tunnel MTU %d", len(packet), lease.MTU)
	}
	info, err := protocol.ParseIPv4(packet)
	if err != nil {
		return err
	}
	if info.Source != lease.Address.Addr() {
		return fmt.Errorf("packet source %s does not match lease %s", info.Source, lease.Address)
	}

	metadata := protocol.ClassifyIPv4(packet)
	var lane *http2Lane
	if metadata.Class == protocol.PacketClassControl {
		lane = g.controlLane()
	} else {
		lane = g.dataLane(metadata, g.now())
		if lane == nil && g.lanes[0].active.Load() {
			lane = g.lanes[0]
		}
	}
	if lane == nil {
		return nil
	}
	if lane.upload.enqueue(packet, metadata, g.now()) {
		return nil
	}
	if err := g.failure(); err != nil {
		return err
	}
	if err := g.ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (g *http2Group) controlLane() *http2Lane {
	if g.lanes[0].active.Load() {
		return g.lanes[0]
	}
	now := g.now()
	var selected *http2Lane
	for index := 1; index < http2LaneCount; index++ {
		lane := g.lanes[index]
		if !lane.active.Load() {
			continue
		}
		if selected == nil || lane.upload.queuedBytesAt(now) < selected.upload.queuedBytesAt(now) {
			selected = lane
		}
	}
	return selected
}

func (g *http2Group) dataLane(metadata protocol.PacketMetadata, now time.Time) *http2Lane {
	g.flowMu.Lock()
	defer g.flowMu.Unlock()
	if assignment, ok := g.flows[metadata.Flow]; ok {
		if now.Sub(assignment.lastSeen) < http2FlowIdle &&
			assignment.lane > 0 && assignment.lane < http2LaneCount &&
			g.lanes[assignment.lane].active.Load() {
			assignment.lastSeen = now
			g.flows[metadata.Flow] = assignment
			return g.lanes[assignment.lane]
		}
		delete(g.flows, metadata.Flow)
	}
	if len(g.flows) >= http2FlowLimit {
		var (
			oldestFlow protocol.FlowKey
			oldest     time.Time
		)
		for flow, assignment := range g.flows {
			if now.Sub(assignment.lastSeen) >= http2FlowIdle {
				delete(g.flows, flow)
				continue
			}
			if oldest.IsZero() || assignment.lastSeen.Before(oldest) {
				oldestFlow = flow
				oldest = assignment.lastSeen
			}
		}
		if len(g.flows) >= http2FlowLimit {
			delete(g.flows, oldestFlow)
		}
	}
	candidates := make([]*http2Lane, 0, http2LaneCount-1)
	for index := 1; index < http2LaneCount; index++ {
		if g.lanes[index].active.Load() {
			candidates = append(candidates, g.lanes[index])
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	start := int(metadata.Hash % uint32(len(candidates)))
	selected := candidates[start]
	selectedBytes := selected.upload.queuedBytesAt(now)
	for offset := 1; offset < len(candidates); offset++ {
		candidate := candidates[(start+offset)%len(candidates)]
		queued := candidate.upload.queuedBytesAt(now)
		if queued < selectedBytes {
			selected = candidate
			selectedBytes = queued
		}
	}
	g.flows[metadata.Flow] = http2FlowAssignment{lane: selected.index, lastSeen: now}
	return selected
}

func (g *http2Group) receive() ([]byte, error) {
	g.receiveMu.Lock()
	defer g.receiveMu.Unlock()
	for {
		if g.controlBudget > 0 {
			if packet, ok := tryHTTP2Packet(g.lanes[0].downstream); ok {
				g.controlBudget--
				g.resignalDownloads()
				return packet, nil
			}
		}
		for offset := 0; offset < http2LaneCount-1; offset++ {
			index := 1 + (g.nextDataLane-1+offset)%(http2LaneCount-1)
			if packet, ok := tryHTTP2Packet(g.lanes[index].downstream); ok {
				g.nextDataLane = 1 + index%(http2LaneCount-1)
				g.controlBudget = http2ControlBurst
				g.resignalDownloads()
				return packet, nil
			}
		}
		if packet, ok := tryHTTP2Packet(g.lanes[0].downstream); ok {
			g.controlBudget = max(g.controlBudget-1, 0)
			g.resignalDownloads()
			return packet, nil
		}
		if err := g.failure(); err != nil {
			return nil, err
		}
		select {
		case <-g.downloadReady:
		case <-g.failureSignal:
			return nil, g.failure()
		case <-g.ctx.Done():
			if err := g.failure(); err != nil {
				return nil, err
			}
			return nil, g.ctx.Err()
		}
	}
}

func tryHTTP2Packet(packets <-chan []byte) ([]byte, bool) {
	select {
	case packet := <-packets:
		return packet, true
	default:
		return nil, false
	}
}

func (g *http2Group) resignalDownloads() {
	for _, lane := range g.lanes {
		if len(lane.downstream) > 0 {
			g.signalDownload()
			return
		}
	}
}

func (g *http2Group) signalDownload() {
	select {
	case g.downloadReady <- struct{}{}:
	default:
	}
}

func (g *http2Group) waitForStartup() error {
	for {
		if g.requiredCapacity() {
			return nil
		}
		select {
		case <-g.stateChanged:
		case <-g.failureSignal:
			return g.failure()
		case <-g.ctx.Done():
			if err := g.failure(); err != nil {
				return err
			}
			return preSessionFailure(fmt.Errorf("establish HTTP/2 lane capacity: %w", g.ctx.Err()))
		}
	}
}

func (g *http2Group) monitorCapacity() {
	defer g.workers.Done()
	var (
		timer    *time.Timer
		deadline <-chan time.Time
	)
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer = nil
		deadline = nil
	}
	defer stopTimer()
	for {
		if !g.established.Load() || g.requiredCapacity() {
			stopTimer()
		} else if timer == nil {
			timer = time.NewTimer(g.recoveryTimeout)
			deadline = timer.C
		}
		select {
		case <-g.stateChanged:
		case <-deadline:
			timer = nil
			deadline = nil
			if g.requiredCapacity() {
				continue
			}
			g.fail(fmt.Errorf("HTTP/2 required lane capacity unavailable: %w", context.DeadlineExceeded))
			return
		case <-g.ctx.Done():
			return
		}
	}
}

func (g *http2Group) requiredCapacity() bool {
	if !g.lanes[0].active.Load() {
		return false
	}
	for index := 1; index < http2LaneCount; index++ {
		if g.lanes[index].active.Load() {
			return true
		}
	}
	return false
}

func (g *http2Group) acceptLease(lease Lease) error {
	g.leaseMu.Lock()
	defer g.leaseMu.Unlock()
	if !g.leaseSet {
		g.lease = lease
		g.leaseSet = true
		return nil
	}
	if g.lease != lease {
		if g.established.Load() && !g.hasActiveLane() {
			return fmt.Errorf("HTTP/2 lease changed after a full lane outage: %w", net.ErrClosed)
		}
		return PermanentError{Err: errors.New("HTTP/2 lanes returned different tunnel leases")}
	}
	return nil
}

func (g *http2Group) hasActiveLane() bool {
	for _, lane := range g.lanes {
		if lane.active.Load() {
			return true
		}
	}
	return false
}

func (g *http2Group) leaseSnapshot() Lease {
	g.leaseMu.Lock()
	defer g.leaseMu.Unlock()
	return g.lease
}

func (g *http2Group) activateLane(lane *http2Lane, remoteAddr net.Addr) {
	lane.mu.Lock()
	lane.remoteAddr = remoteAddr
	lane.lastErr = nil
	lane.mu.Unlock()
	lane.upload.activate()
	lane.active.Store(true)
	g.signalState()
}

func (g *http2Group) deactivateLane(lane *http2Lane) {
	lane.active.Store(false)
	lane.upload.deactivateAndClear()
	g.signalState()
}

func (g *http2Group) recordLaneError(lane *http2Lane, err error) {
	lane.mu.Lock()
	lane.lastErr = err
	lane.mu.Unlock()
}

func (g *http2Group) laneRemoteAddr(index int) net.Addr {
	lane := g.lanes[index]
	lane.mu.Lock()
	defer lane.mu.Unlock()
	return lane.remoteAddr
}

func (g *http2Group) signalState() {
	select {
	case g.stateChanged <- struct{}{}:
	default:
	}
}

func (g *http2Group) waitRetry(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-g.ctx.Done():
		return false
	}
}

func (g *http2Group) fail(err error) {
	if err == nil {
		err = errors.New("HTTP/2 lane group failed")
	}
	g.failureOnce.Do(func() {
		g.failureMu.Lock()
		g.failureErr = err
		g.failureMu.Unlock()
		close(g.failureSignal)
		g.cancel()
	})
}

func (g *http2Group) failure() error {
	g.failureMu.Lock()
	defer g.failureMu.Unlock()
	return g.failureErr
}

func (g *http2Group) close() error {
	g.closeOnce.Do(func() {
		g.cancel()
		for _, lane := range g.lanes {
			lane.upload.close()
		}
		g.workers.Wait()
	})
	return nil
}

func validateHTTP2TunnelResponse(response *http.Response, session string, lane int) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()
		failure := &GatewayResponseError{
			StatusCode:       response.StatusCode,
			Status:           response.Status,
			ServerVersion:    response.Header.Get(protocol.HeaderVersion),
			ServerMinVersion: response.Header.Get(protocol.HeaderMinVersion),
			ServerMaxVersion: response.Header.Get(protocol.HeaderMaxVersion),
			ClientVersion:    protocol.Version,
		}
		switch response.StatusCode {
		case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusMisdirectedRequest,
			http.StatusNotImplemented, http.StatusHTTPVersionNotSupported:
			return TransportUnavailableError{Err: failure}
		case http.StatusUpgradeRequired:
			if failure.ServerMinVersion == "" && failure.ServerMaxVersion == "" {
				return TransportUnavailableError{Err: failure}
			}
			return PermanentError{Err: failure}
		default:
			return failure
		}
	}
	if response.ProtoMajor != 2 {
		return PermanentError{Err: errors.New("gateway did not negotiate HTTP/2")}
	}
	if response.Header.Get(protocol.HeaderVersion) != protocol.Version {
		return PermanentError{Err: fmt.Errorf(
			"gateway selected Porta protocol %q, client requires %q",
			response.Header.Get(protocol.HeaderVersion),
			protocol.Version,
		)}
	}
	mediaType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	if mediaType != protocol.ContentType {
		return PermanentError{Err: errors.New("gateway returned an invalid tunnel content type")}
	}
	if response.Header.Get("X-Porta-Lane-Session") != session ||
		response.Header.Get("X-Porta-Lane") != strconv.Itoa(lane) ||
		response.Header.Get("X-Porta-Lanes") != strconv.Itoa(http2LaneCount) {
		return PermanentError{Err: errors.New("gateway rejected HTTP/2 lane negotiation")}
	}
	return nil
}

func leaseFromHTTP2Headers(header http.Header) (Lease, error) {
	prefix, err := netip.ParsePrefix(header.Get("X-Porta-Address"))
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsGlobalUnicast() ||
		prefix.Bits() < 16 || prefix.Bits() > 32 {
		return Lease{}, PermanentError{Err: errors.New("gateway returned an invalid IPv4 tunnel address")}
	}
	gatewayAddress, err := netip.ParseAddr(header.Get("X-Porta-Gateway"))
	if err != nil || !gatewayAddress.Is4() || !gatewayAddress.IsGlobalUnicast() ||
		gatewayAddress == prefix.Addr() || !prefix.Contains(gatewayAddress) {
		return Lease{}, PermanentError{Err: errors.New("gateway returned an invalid IPv4 tunnel gateway")}
	}
	mtu, err := strconv.Atoi(header.Get("X-Porta-MTU"))
	if err != nil || mtu < 576 || mtu > 9000 {
		return Lease{}, PermanentError{Err: errors.New("gateway returned an invalid tunnel MTU")}
	}
	var dns netip.Addr
	if value := header.Get("X-Porta-DNS"); value != "" {
		dns, err = netip.ParseAddr(value)
		if err != nil || !dns.Is4() || !dns.IsGlobalUnicast() {
			return Lease{}, PermanentError{Err: errors.New("gateway returned an invalid IPv4 DNS address")}
		}
	}
	return Lease{Address: prefix, Gateway: gatewayAddress, DNS: dns, MTU: mtu}, nil
}
