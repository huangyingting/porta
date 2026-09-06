package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/gateway"
	"github.com/huangyingting/porta/internal/masque"
	"github.com/huangyingting/porta/internal/protocol"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const (
	benchmarkToken = "benchmark-token-1234567890"
	benchmarkMTU   = 1400
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18443", "TLS listen address")
	certificate := flag.String("cert", "", "TLS certificate")
	privateKey := flag.String("key", "", "TLS private key")
	mode := flag.String("mode", "direct", "server mode: direct or porta")
	transport := flag.String("transport", "h2", "transport: h2 or h3")
	flag.Parse()
	if *certificate == "" || *privateKey == "" {
		log.Fatal("--cert and --key are required")
	}

	handler, stop, err := benchmarkHandler(*mode)
	if err != nil {
		log.Fatal(err)
	}
	defer stop()

	pair, err := tls.LoadX509KeyPair(*certificate, *privateKey)
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}
	if *transport == "h3" {
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
		server := &http3.Server{
			Addr:            *listen,
			Handler:         selectTransportHandler(handler, *mode, *transport),
			TLSConfig:       tlsConfig,
			EnableDatagrams: true,
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		go func() {
			<-ctx.Done()
			_ = server.Close()
		}()
		fmt.Printf("LISTEN https://%s\n", *listen)
		err = server.ListenAndServeTLS(*certificate, *privateKey)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
		return
	}
	if *transport != "h2" {
		log.Fatalf("unknown transport %q", *transport)
	}
	tlsConfig.NextProtos = []string{http2.NextProtoTLS}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if err := http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams:         1024,
		MaxReadFrameSize:             64 << 10,
		MaxUploadBufferPerConnection: 4 << 20,
		MaxUploadBufferPerStream:     1 << 20,
	}); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, stopShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopShutdown()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Printf("LISTEN https://%s\n", listener.Addr())
	err = server.Serve(tls.NewListener(listener, tlsConfig))
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func selectTransportHandler(handler http.Handler, mode, transport string) http.Handler {
	if transport == "h3" && mode == "direct" {
		return http.HandlerFunc(serveDirectH3)
	}
	return handler
}

func benchmarkHandler(mode string) (http.Handler, func(), error) {
	switch mode {
	case "direct":
		return http.HandlerFunc(serveDirect), func() {}, nil
	case "porta":
		return portaHandler()
	default:
		return nil, nil, fmt.Errorf("unknown mode %q", mode)
	}
}

func serveDirect(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != gateway.TunnelPath ||
		request.ProtoMajor != 2 ||
		request.Header.Get("Content-Type") != protocol.ContentType ||
		request.Header.Get(protocol.HeaderVersion) != protocol.Version ||
		request.Header.Get("Authorization") != "Bearer "+benchmarkToken {
		http.Error(w, "invalid benchmark tunnel", http.StatusBadRequest)
		return
	}
	lane := request.Header.Get("X-Porta-Lane")
	lanes := request.Header.Get("X-Porta-Lanes")
	session := request.Header.Get("X-Porta-Lane-Session")
	index, indexErr := strconv.Atoi(lane)
	count, countErr := strconv.Atoi(lanes)
	if indexErr != nil || countErr != nil || count != 4 || index < 0 || index >= count || len(session) < 16 {
		http.Error(w, "invalid benchmark lanes", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(protocol.HeaderVersion, protocol.Version)
	w.Header().Set(protocol.HeaderMinVersion, protocol.MinVersion)
	w.Header().Set(protocol.HeaderMaxVersion, protocol.MaxVersion)
	w.Header().Set("X-Porta-Address", "10.66.0.2/16")
	w.Header().Set("X-Porta-Gateway", "10.66.0.1")
	w.Header().Set("X-Porta-DNS", "1.1.1.1")
	w.Header().Set("X-Porta-MTU", strconv.Itoa(benchmarkMTU))
	w.Header().Set("X-Porta-Lane-Session", session)
	w.Header().Set("X-Porta-Lane", lane)
	w.Header().Set("X-Porta-Lanes", lanes)
	w.WriteHeader(http.StatusOK)
	encoder := protocol.NewEncoder(w)
	if err := encoder.WritePacket(nil); err != nil {
		return
	}
	flush(w)

	decoder := protocol.NewDecoder(request.Body)
	buffer := make([]byte, benchmarkMTU)
	for {
		packet, err := decoder.ReadPacketInto(buffer)
		if err != nil {
			return
		}
		if len(packet) == 0 {
			continue
		}
		if !validDirectPacket(packet) {
			continue
		}
		response := append([]byte(nil), packet...)
		swapIPv4Endpoints(response)
		if err := encoder.WritePacket(response); err != nil {
			return
		}
		flush(w)
	}
}

func serveDirectH3(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect || request.URL.Path != gateway.MasquePath ||
		request.ProtoMajor != 3 || request.Proto != "connect-ip" ||
		request.Header.Get(http3.CapsuleProtocolHeader) != "?1" ||
		request.Header.Get(protocol.HeaderVersion) != protocol.Version ||
		request.Header.Get("Authorization") != "Bearer "+benchmarkToken {
		http.Error(w, "invalid benchmark tunnel", http.StatusBadRequest)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "HTTP/3 stream unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(protocol.HeaderVersion, protocol.Version)
	w.Header().Set(protocol.HeaderMinVersion, protocol.MinVersion)
	w.Header().Set(protocol.HeaderMaxVersion, protocol.MaxVersion)
	w.Header().Set("X-Porta-DNS", "1.1.1.1")
	w.Header().Set("X-Porta-MTU", strconv.Itoa(benchmarkMTU))
	w.WriteHeader(http.StatusOK)

	stream := streamer.HTTPStream()
	decoder := masque.NewDecoder(stream)
	encoder := masque.NewEncoder(stream)
	capsule, err := decoder.Read()
	if err != nil || capsule.Type != masque.CapsuleAddressRequest {
		return
	}
	requested, err := masque.DecodeAddressRequest(capsule.Value)
	if err != nil || len(requested) == 0 {
		return
	}
	assignment, err := masque.EncodeAddressAssign([]masque.Address{{
		RequestID: requested[0].RequestID,
		Prefix:    netip.MustParsePrefix("10.66.0.2/32"),
	}})
	if err != nil {
		return
	}
	routes, err := masque.EncodeRouteAdvertisement([]masque.Route{{
		Start: netip.MustParseAddr("0.0.0.0"),
		End:   netip.MustParseAddr("255.255.255.255"),
	}})
	if err != nil || encoder.Write(masque.CapsuleAddressAssign, assignment) != nil ||
		encoder.Write(masque.CapsuleRouteAdvertisement, routes) != nil {
		return
	}
	encoder.Flush()

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			capsule, err := decoder.Read()
			if err != nil {
				return
			}
			if capsule.Type != masque.CapsuleDatagram {
				continue
			}
			response, ok := directH3Response(capsule.Value)
			if !ok {
				continue
			}
			if encoder.WriteIPPacket(response) != nil {
				return
			}
			encoder.Flush()
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			value, err := stream.ReceiveDatagram(request.Context())
			if err != nil {
				return
			}
			response, ok := directH3Response(value)
			if !ok {
				continue
			}
			if err := stream.SendDatagram(masque.EncodeIPPacket(response)); err != nil {
				return
			}
		}
	}()
	<-done
}

func directH3Response(value []byte) ([]byte, bool) {
	packet, err := masque.DecodeIPPacket(value)
	if err != nil || !validDirectPacket(packet) {
		return nil, false
	}
	response := append([]byte(nil), packet...)
	swapIPv4Endpoints(response)
	return response, true
}

func portaHandler() (http.Handler, func(), error) {
	pool, err := gateway.NewPool("10.66.0.0/16")
	if err != nil {
		return nil, nil, err
	}
	device := newEchoDevice()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := gateway.NewRouter(device, logger)
	handler, err := gateway.NewHandler(gateway.HandlerConfig{
		AuthorizeSession: func(parent context.Context, token string, proof deviceauth.Proof, _, _ string) (gateway.ClientIdentity, context.Context, func(), error) {
			if token != benchmarkToken {
				return gateway.ClientIdentity{}, nil, nil, errors.New("unauthorized")
			}
			return gateway.ClientIdentity{
				AccountID: "benchmark",
				LeaseID:   proof.DeviceID,
			}, parent, func() {}, nil
		},
		Pool:              pool,
		Router:            router,
		DNS:               "1.1.1.1",
		MTU:               benchmarkMTU,
		KeepaliveInterval: time.Hour,
		Logger:            logger,
	})
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = router.Run(ctx)
	}()
	return handler, func() {
		cancel()
		device.Close()
		<-done
	}, nil
}

type echoDevice struct {
	packets chan []byte
	closed  chan struct{}
}

func newEchoDevice() *echoDevice {
	return &echoDevice{
		packets: make(chan []byte, 4096),
		closed:  make(chan struct{}),
	}
}

func (*echoDevice) Name() string { return "benchmark-echo" }

func (d *echoDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-d.packets:
		return packet, nil
	case <-d.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *echoDevice) WritePacket(ctx context.Context, packet []byte) error {
	if _, err := protocol.ParseIPv4(packet); err != nil || len(packet) > benchmarkMTU {
		return errors.New("invalid benchmark packet")
	}
	response := append([]byte(nil), packet...)
	swapIPv4Endpoints(response)
	select {
	case d.packets <- response:
		return nil
	case <-d.closed:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *echoDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

func validDirectPacket(packet []byte) bool {
	info, err := protocol.ParseIPv4(packet)
	return err == nil && len(packet) <= benchmarkMTU &&
		info.Source == netip.MustParseAddr("10.66.0.2")
}

func swapIPv4Endpoints(packet []byte) {
	source := [4]byte(packet[12:16])
	copy(packet[12:16], packet[16:20])
	copy(packet[16:20], source[:])
	packet[10], packet[11] = 0, 0
	checksum := ipv4Checksum(packet[:int(packet[0]&0x0f)*4])
	packet[10], packet[11] = byte(checksum>>8), byte(checksum)
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(header[index])<<8 | uint32(header[index+1])
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func flush(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
