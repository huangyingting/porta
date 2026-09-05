package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/protocol"
	"golang.org/x/net/http2"
)

type http2LaneEvent struct {
	lane    int
	attempt int
	session string
	remote  string
	nonce   string
}

type http2UploadEvent struct {
	lane   int
	packet []byte
}

type http2LaneScript struct {
	delays     [http2LaneCount]<-chan struct{}
	failFirst  [http2LaneCount]<-chan struct{}
	downstream [http2LaneCount]chan []byte
	arrived    chan http2LaneEvent
	ready      chan http2LaneEvent
	uploads    chan http2UploadEvent
	attempts   [http2LaneCount]atomic.Int32
}

func newHTTP2LaneScript() *http2LaneScript {
	script := &http2LaneScript{
		arrived: make(chan http2LaneEvent, 32),
		ready:   make(chan http2LaneEvent, 32),
		uploads: make(chan http2UploadEvent, 32),
	}
	for index := range http2LaneCount {
		script.downstream[index] = make(chan []byte, 8)
	}
	return script
}

func (s *http2LaneScript) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	lane, err := strconv.Atoi(r.Header.Get("X-Porta-Lane"))
	if err != nil || lane < 0 || lane >= http2LaneCount {
		http.Error(w, "bad lane", http.StatusBadRequest)
		return
	}
	attempt := int(s.attempts[lane].Add(1))
	event := http2LaneEvent{
		lane: lane, attempt: attempt,
		session: r.Header.Get("X-Porta-Lane-Session"),
		remote:  r.RemoteAddr,
		nonce:   r.Header.Get(deviceauth.HeaderNonce),
	}
	s.arrived <- event
	if delay := s.delays[lane]; delay != nil {
		select {
		case <-delay:
		case <-r.Context().Done():
			return
		}
	}

	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set(protocol.HeaderVersion, protocol.Version)
	w.Header().Set("X-Porta-Address", "10.66.0.2/29")
	w.Header().Set("X-Porta-Gateway", "10.66.0.1")
	w.Header().Set("X-Porta-DNS", "1.1.1.1")
	w.Header().Set("X-Porta-MTU", "1300")
	w.Header().Set("X-Porta-Lane-Session", event.session)
	w.Header().Set("X-Porta-Lane", strconv.Itoa(lane))
	w.Header().Set("X-Porta-Lanes", strconv.Itoa(http2LaneCount))
	w.WriteHeader(http.StatusOK)
	encoder := protocol.NewEncoder(w)
	if err := encoder.WritePacket(nil); err != nil {
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	s.ready <- event

	uploadDone := make(chan error, 1)
	go func() {
		decoder := protocol.NewDecoder(r.Body)
		for {
			packet, err := decoder.ReadPacket()
			if err != nil {
				uploadDone <- err
				return
			}
			if len(packet) != 0 {
				s.uploads <- http2UploadEvent{lane: lane, packet: packet}
			}
		}
	}()
	for {
		var fail <-chan struct{}
		if attempt == 1 {
			fail = s.failFirst[lane]
		}
		select {
		case <-fail:
			return
		case packet := <-s.downstream[lane]:
			if err := encoder.WritePacket(packet); err != nil {
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		case <-uploadDone:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func TestHTTP2PartialStartupNeedsControlAndAnyDataLane(t *testing.T) {
	script := newHTTP2LaneScript()
	releaseLane1 := make(chan struct{})
	releaseLane3 := make(chan struct{})
	script.delays[1] = releaseLane1
	script.delays[3] = releaseLane3
	config, proofCalls, badProof := startHTTP2LaneServer(t, script)
	var release1Once, release3Once sync.Once
	release1 := func() { release1Once.Do(func() { close(releaseLane1) }) }
	release3 := func() { release3Once.Do(func() { close(releaseLane3) }) }
	t.Cleanup(release1)
	t.Cleanup(release3)

	type result struct {
		connection *Conn
		err        error
	}
	dialed := make(chan result, 1)
	go func() {
		connection, err := Dial(context.Background(), config)
		dialed <- result{connection: connection, err: err}
	}()
	events := make([]http2LaneEvent, 0, http2LaneCount)
	for len(events) < http2LaneCount {
		events = append(events, waitHTTP2LaneEvent(t, script.arrived, func(http2LaneEvent) bool { return true }))
	}
	requiredReady := make(map[int]bool, 2)
	for !requiredReady[0] || !requiredReady[2] {
		event := waitHTTP2LaneEvent(t, script.ready, func(http2LaneEvent) bool { return true })
		if event.lane == 0 || event.lane == 2 {
			requiredReady[event.lane] = true
		}
	}
	var connection *Conn
	select {
	case got := <-dialed:
		if got.err != nil {
			t.Fatal(got.err)
		}
		connection = got.connection
	case <-time.After(time.Second):
		t.Fatal("Dial waited for non-required HTTP/2 lanes")
	}
	t.Cleanup(func() { _ = connection.Close() })
	if connection.DeliveryMode != DeliveryModeFramed {
		t.Fatalf("delivery mode = %q, want framed", connection.DeliveryMode)
	}
	if script.attempts[0].Load() != 1 || script.attempts[2].Load() != 1 {
		t.Fatal("control lane zero and available data lane two were not used for startup")
	}
	if proofCalls.Load() != http2LaneCount || badProof.Load() {
		t.Fatalf("device proof calls=%d bad method/path=%v", proofCalls.Load(), badProof.Load())
	}
	nonces := make(map[string]struct{}, len(events))
	for _, event := range events {
		nonces[event.nonce] = struct{}{}
	}
	if len(nonces) != http2LaneCount {
		t.Fatalf("lane requests did not carry independent device proofs: %+v", events)
	}

	release1()
	waitHTTP2LaneEvent(t, script.ready, func(event http2LaneEvent) bool { return event.lane == 1 })
	release3()
	waitHTTP2LaneEvent(t, script.ready, func(event http2LaneEvent) bool { return event.lane == 3 })
}

func TestHTTP2FailedLaneIsReplacedWithoutStoppingHealthyLanes(t *testing.T) {
	script := newHTTP2LaneScript()
	failLane3 := make(chan struct{})
	script.failFirst[3] = failLane3
	config, _, _ := startHTTP2LaneServer(t, script)

	connection, err := Dial(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	first := waitHTTP2LaneEvent(t, script.ready, func(event http2LaneEvent) bool {
		return event.lane == 3 && event.attempt == 1
	})
	close(failLane3)
	replacement := waitHTTP2LaneEvent(t, script.ready, func(event http2LaneEvent) bool {
		return event.lane == 3 && event.attempt == 2
	})
	if replacement.session != first.session || replacement.remote == first.remote {
		t.Fatalf("lane replacement changed group or reused TCP connection: first=%+v replacement=%+v", first, replacement)
	}

	control := http2TestIPv4([4]byte{10, 66, 0, 2}, [4]byte{1, 1, 1, 1}, 1, 28)
	if err := connection.Send(control); err != nil {
		t.Fatalf("healthy lanes unusable during replacement: %v", err)
	}
	upload := waitHTTP2Upload(t, script.uploads)
	if upload.lane != 0 || string(upload.packet) != string(control) {
		t.Fatalf("control upload used lane %d or changed packet", upload.lane)
	}

	downstream := http2TestUDP([4]byte{8, 8, 8, 8}, [4]byte{10, 66, 0, 2}, 53, 40000, 80)
	script.downstream[1] <- downstream
	received := make(chan []byte, 1)
	receiveErr := make(chan error, 1)
	go func() {
		packet, err := connection.Receive()
		if err != nil {
			receiveErr <- err
			return
		}
		received <- packet
	}()
	select {
	case packet := <-received:
		if string(packet) != string(downstream) {
			t.Fatal("healthy downstream lane changed packet")
		}
	case err := <-receiveErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("healthy downstream lane stopped during replacement")
	}
}

func startHTTP2LaneServer(
	t *testing.T,
	handler http.Handler,
) (Config, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	if err := http2.ConfigureServer(server.Config, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	proofCalls := &atomic.Int32{}
	badProof := &atomic.Bool{}
	config := Config{
		URL:       server.URL,
		Token:     "0123456789abcdef0123456789abcdef",
		Transport: TransportHTTP2,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // test-only certificate
		Timeout:   2 * time.Second,
		DeviceProof: func(method, path string) (deviceauth.Proof, error) {
			call := proofCalls.Add(1)
			if method != http.MethodPost || path != gateway.TunnelPath {
				badProof.Store(true)
			}
			return deviceauth.Proof{
				DeviceID: "d-AAAAAAAAAAAAAAAAAAAAAA",
				Name:     "test",
				Nonce:    fmt.Sprintf("proof-%d", call),
			}, nil
		},
	}
	return config, proofCalls, badProof
}

func waitHTTP2LaneEvent(
	t *testing.T,
	events <-chan http2LaneEvent,
	match func(http2LaneEvent) bool,
) http2LaneEvent {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if match(event) {
				return event
			}
		case <-timer.C:
			t.Fatal("timed out waiting for HTTP/2 lane event")
		}
	}
}

func waitHTTP2Upload(t *testing.T, uploads <-chan http2UploadEvent) http2UploadEvent {
	t.Helper()
	select {
	case upload := <-uploads:
		return upload
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for HTTP/2 upload")
		return http2UploadEvent{}
	}
}
