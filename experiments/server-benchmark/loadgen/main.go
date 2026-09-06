package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/deviceauth"
	"github.com/huangyingting/porta/internal/tunnel"
)

const benchmarkToken = "benchmark-token-1234567890"

type result struct {
	Clients        int     `json:"clients"`
	DurationMS     int64   `json:"duration_ms"`
	WarmupMS       int64   `json:"warmup_ms"`
	Operations     uint64  `json:"operations"`
	OperationsSec  float64 `json:"operations_per_second"`
	GigabitsSec    float64 `json:"gigabits_per_second"`
	LatencyP50US   float64 `json:"latency_p50_us"`
	LatencyP95US   float64 `json:"latency_p95_us"`
	LatencyP99US   float64 `json:"latency_p99_us"`
	ConnectMS      int64   `json:"connect_ms"`
	PayloadBytes   int     `json:"payload_bytes"`
	Transport      string  `json:"transport"`
	Inflight       int     `json:"inflight"`
	GOMAXPROCS     int     `json:"gomaxprocs"`
	SampledLatency int     `json:"sampled_latencies"`
}

func main() {
	serverURL := flag.String("url", "https://127.0.0.1:18443", "benchmark server URL")
	clients := flag.Int("clients", 1, "concurrent tunnel clients")
	duration := flag.Duration("duration", 6*time.Second, "measured duration")
	warmup := flag.Duration("warmup", 2*time.Second, "warmup duration")
	payloadBytes := flag.Int("payload", 1200, "IPv4 packet size")
	transport := flag.String("transport", "h2", "transport: h2 or h3")
	inflight := flag.Int("inflight", 1, "maximum outstanding packets per tunnel")
	flag.Parse()
	if *clients <= 0 || *duration <= 0 || *warmup < 0 || *payloadBytes < 36 ||
		*payloadBytes > 1400 || *inflight <= 0 || *inflight > 256 {
		fmt.Fprintln(os.Stderr, "invalid benchmark arguments")
		os.Exit(2)
	}

	connectStarted := time.Now()
	connections, err := connectAll(*serverURL, *clients, *transport)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	connectElapsed := time.Since(connectStarted)

	start := make(chan struct{})
	measureAt := time.Now().Add(*warmup)
	stopAt := measureAt.Add(*duration)
	var operations atomic.Uint64
	samples := make(chan []int64, *clients)
	errs := make(chan error, *clients)
	var workers sync.WaitGroup
	for index, connection := range connections {
		workers.Add(1)
		go func(worker int, connection *tunnel.Conn) {
			defer workers.Done()
			<-start
			template := benchmarkPacket(connection.Lease.Address.Addr(), *payloadBytes, worker)
			latencies := make([]int64, 0, 8192)
			responses := make(chan []byte, *inflight)
			receiveErrors := make(chan error, 1)
			go func() {
				for {
					response, err := connection.Receive()
					if err != nil {
						receiveErrors <- err
						return
					}
					responses <- response
				}
			}()
			type pendingPacket struct {
				started  time.Time
				measured bool
				sampled  bool
			}
			pending := make(map[uint64]pendingPacket, *inflight)
			var sequence uint64
			sendNext := func() error {
				packet := append([]byte(nil), template...)
				binary.BigEndian.PutUint16(packet[22:24], uint16(1024+(sequence+uint64(worker)*257)%60000))
				binary.BigEndian.PutUint64(packet[28:36], sequence)
				started := time.Now()
				if err := connection.Send(packet); err != nil {
					return err
				}
				pending[sequence] = pendingPacket{
					started:  started,
					measured: !started.Before(measureAt),
					sampled:  sequence%8 == 0,
				}
				sequence++
				return nil
			}
			for len(pending) < *inflight && time.Now().Before(stopAt) {
				if err := sendNext(); err != nil {
					errs <- fmt.Errorf("client %d send: %w", worker, err)
					return
				}
			}
			for len(pending) > 0 {
				timer := time.NewTimer(2 * time.Second)
				var response []byte
				select {
				case response = <-responses:
					if !timer.Stop() {
						<-timer.C
					}
				case err := <-receiveErrors:
					if !timer.Stop() {
						<-timer.C
					}
					errs <- fmt.Errorf("client %d receive: %w", worker, err)
					return
				case <-timer.C:
					_ = connection.Close()
					errs <- fmt.Errorf("client %d receive timed out after packet loss", worker)
					return
				}
				if len(response) != len(template) {
					errs <- fmt.Errorf("client %d response length %d, want %d", worker, len(response), len(template))
					return
				}
				responseSequence := binary.BigEndian.Uint64(response[28:36])
				sent, ok := pending[responseSequence]
				if !ok {
					errs <- fmt.Errorf("client %d received unknown response sequence %d", worker, responseSequence)
					return
				}
				delete(pending, responseSequence)
				finished := time.Now()
				if sent.measured && finished.Before(stopAt) {
					operations.Add(1)
					if sent.sampled {
						latencies = append(latencies, finished.Sub(sent.started).Nanoseconds())
					}
				}
				if finished.Before(stopAt) {
					if err := sendNext(); err != nil {
						errs <- fmt.Errorf("client %d send: %w", worker, err)
						return
					}
				}
			}
			samples <- latencies
		}(index, connection)
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	close(samples)

	allSamples := make([]int64, 0)
	for values := range samples {
		allSamples = append(allSamples, values...)
	}
	sort.Slice(allSamples, func(i, j int) bool { return allSamples[i] < allSamples[j] })
	count := operations.Load()
	seconds := duration.Seconds()
	output := result{
		Clients:        *clients,
		DurationMS:     duration.Milliseconds(),
		WarmupMS:       warmup.Milliseconds(),
		Operations:     count,
		OperationsSec:  float64(count) / seconds,
		GigabitsSec:    float64(count) * float64(*payloadBytes*2) * 8 / seconds / 1e9,
		LatencyP50US:   percentile(allSamples, 0.50),
		LatencyP95US:   percentile(allSamples, 0.95),
		LatencyP99US:   percentile(allSamples, 0.99),
		ConnectMS:      connectElapsed.Milliseconds(),
		PayloadBytes:   *payloadBytes,
		Transport:      *transport,
		Inflight:       *inflight,
		GOMAXPROCS:     runtime.GOMAXPROCS(0),
		SampledLatency: len(allSamples),
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func connectAll(serverURL string, count int, selectedTransport string) ([]*tunnel.Conn, error) {
	var transport tunnel.Transport
	switch selectedTransport {
	case "h2":
		transport = tunnel.TransportHTTP2
	case "h3":
		transport = tunnel.TransportHTTP3
	default:
		return nil, fmt.Errorf("unknown transport %q", selectedTransport)
	}
	type connected struct {
		index      int
		connection *tunnel.Conn
		err        error
	}
	results := make(chan connected, count)
	ctx := context.Background()
	for index := range count {
		go func(index int) {
			key, err := deviceauth.GenerateKey()
			if err != nil {
				results <- connected{index: index, err: err}
				return
			}
			config := tunnel.Config{
				URL:       serverURL,
				Token:     benchmarkToken,
				Transport: transport,
				TLSConfig: &tls.Config{InsecureSkipVerify: true},
				Timeout:   10 * time.Second,
				DeviceProof: func(method, path string) (deviceauth.Proof, error) {
					return proof(key, index, method, path)
				},
			}
			connection, err := tunnel.Dial(ctx, config)
			results <- connected{index: index, connection: connection, err: err}
		}(index)
	}
	connections := make([]*tunnel.Conn, count)
	for range count {
		value := <-results
		if value.err != nil {
			for _, connection := range connections {
				if connection != nil {
					_ = connection.Close()
				}
			}
			return nil, fmt.Errorf("connect client %d: %w", value.index, value.err)
		}
		connections[value.index] = value.connection
	}
	return connections, nil
}

func proof(key *ecdsa.PrivateKey, index int, method, path string) (deviceauth.Proof, error) {
	return deviceauth.NewProof(
		key,
		fmt.Sprintf("benchmark-%d", index),
		benchmarkToken,
		method,
		path,
		time.Now(),
		nil,
	)
}

func benchmarkPacket(source netip.Addr, size, worker int) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source.AsSlice())
	packet[16], packet[17], packet[18], packet[19] = 1, 1, 1, 1
	binary.BigEndian.PutUint16(packet[20:22], uint16(20000+worker%40000))
	binary.BigEndian.PutUint16(packet[22:24], 443)
	binary.BigEndian.PutUint16(packet[24:26], uint16(size-20))
	checksum := ipv4Checksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], checksum)
	return packet
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(header[index])<<8 | uint32(header[index+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func percentile(values []int64, quantile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)-1) * quantile)
	return float64(values[index]) / 1000
}
