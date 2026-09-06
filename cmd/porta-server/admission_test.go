package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/certutil"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestTCPAdmissionLimitsAndReleasesConnections(t *testing.T) {
	listener := &tcpAdmissionListener{
		maxGlobal:    2,
		maxPerSource: 1,
		bySource:     make(map[netip.Addr]int),
	}
	first, reason := listener.admit(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1})
	if reason != "" {
		t.Fatalf("first connection rejected: %s", reason)
	}
	if _, reason := listener.admit(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 2}); reason != "source" {
		t.Fatalf("mapped source rejection = %q", reason)
	}
	second, reason := listener.admit(&net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 3})
	if reason != "" {
		t.Fatalf("second connection rejected: %s", reason)
	}
	if _, reason := listener.admit(&net.TCPAddr{IP: net.ParseIP("192.0.2.3"), Port: 4}); reason != "global" {
		t.Fatalf("global rejection = %q", reason)
	}
	first()
	first()
	if replacement, reason := listener.admit(&net.TCPAddr{IP: net.ParseIP("192.0.2.3"), Port: 5}); reason != "" {
		t.Fatalf("released capacity remained unavailable: %s", reason)
	} else {
		replacement()
	}
	second()
}

func TestRetryControllerActivatesOnlyUnderPressure(t *testing.T) {
	now := time.Unix(100, 0)
	controller := &retryController{
		rate: 2, burst: 2, tokens: 2, updated: now,
		sourceBurst: 2,
		now:         func() time.Time { return now },
	}
	first := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
	if controller.ShouldRetry(first) || controller.ShouldRetry(first) {
		t.Fatal("normal handshake burst required Retry")
	}
	if !controller.ShouldRetry(first) {
		t.Fatal("per-source handshake excess did not require Retry")
	}
	second := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 2}
	if !controller.ShouldRetry(second) {
		t.Fatal("global handshake excess did not require Retry")
	}
	now = now.Add(500 * time.Millisecond)
	if controller.ShouldRetry(second) {
		t.Fatal("refilled handshake budget still required Retry")
	}
}

func TestRetryControllerRespondsToUnverifiedOccupancy(t *testing.T) {
	controller := newRetryController(nil)
	controller.underUnverifiedPressure = func() bool { return true }
	if !controller.ShouldRetry(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1}) {
		t.Fatal("unverified occupancy pressure did not require Retry")
	}
}

func TestQUICAdmissionReleasesCanceledConnection(t *testing.T) {
	admission := &quicAdmission{
		maxGlobal:      3,
		maxPerSource:   1,
		maxUnverified:  1,
		retryThreshold: 1,
		bySource:       make(map[netip.Addr]int),
	}
	ctx, cancel := context.WithCancel(context.Background())
	firstSource := &quic.ClientInfo{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1},
		AddrVerified: true,
	}
	if _, err := admission.ConnContext(ctx, firstSource); err != nil {
		t.Fatal(err)
	}
	mappedSource := &quic.ClientInfo{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 2},
		AddrVerified: true,
	}
	if _, err := admission.ConnContext(context.Background(), mappedSource); err == nil {
		t.Fatal("QUIC source capacity overflow was accepted")
	}
	unverifiedCtx, unverifiedCancel := context.WithCancel(context.Background())
	defer unverifiedCancel()
	unverifiedSource := &quic.ClientInfo{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5},
	}
	if _, err := admission.ConnContext(unverifiedCtx, unverifiedSource); err != nil {
		t.Fatalf("unverified address inherited spoofable source quota: %v", err)
	}
	otherUnverified := &quic.ClientInfo{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 6},
	}
	if _, err := admission.ConnContext(context.Background(), otherUnverified); err == nil {
		t.Fatal("unverified QUIC capacity overflow was accepted")
	}
	if !admission.underUnverifiedPressure() {
		t.Fatal("unverified capacity did not trigger Retry pressure")
	}
	secondCtx, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	secondSource := &quic.ClientInfo{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 3},
		AddrVerified: true,
	}
	if _, err := admission.ConnContext(secondCtx, secondSource); err != nil {
		t.Fatal(err)
	}
	thirdSource := &quic.ClientInfo{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 4},
		AddrVerified: true,
	}
	if _, err := admission.ConnContext(context.Background(), thirdSource); err == nil {
		t.Fatal("QUIC capacity overflow was accepted")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for admission.active.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if admission.active.Load() != 2 {
		t.Fatal("canceled QUIC connection retained capacity")
	}
	replacementCtx, replacementCancel := context.WithCancel(context.Background())
	if _, err := admission.ConnContext(replacementCtx, thirdSource); err != nil {
		t.Fatalf("released QUIC capacity remained unavailable: %v", err)
	}
	replacementCancel()
	secondCancel()
	unverifiedCancel()
}

func TestBoundedHTTP2ServerSettings(t *testing.T) {
	config := boundedHTTP2Server()
	if config.MaxConcurrentStreams != 128 ||
		config.MaxReadFrameSize != 64<<10 ||
		config.MaxUploadBufferPerConnection != 1<<20 ||
		config.MaxUploadBufferPerStream != 1<<20 ||
		config.ReadIdleTimeout != 30*time.Second ||
		config.PingTimeout != 10*time.Second ||
		config.WriteByteTimeout != 30*time.Second {
		t.Fatalf("unexpected HTTP/2 admission settings: %+v", config)
	}
}

func TestOwnedHTTP3ServerServesAndShutsDown(t *testing.T) {
	directory := t.TempDir()
	certificate := filepath.Join(directory, "server.crt")
	key := filepath.Join(directory, "server.key")
	if err := certutil.Generate(certificate, key, certutil.Options{Hosts: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := staticTLSConfig(certificate, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newOwnedHTTP3Server(
		"127.0.0.1:0",
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		tlsConfig,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()

	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://" + server.packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	_ = transport.Close()
	if err != nil || string(body) != "ok" || response.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 response = %q over %s, %v", body, response.Proto, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve exit = %v", err)
	}
}
