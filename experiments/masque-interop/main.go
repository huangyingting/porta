// masque-probe connects to a CONNECT-IP proxy with the independent
// quic-go/connect-ip-go implementation, as any RFC 9484 client would: a
// bearer token and no Porta extensions. It prints the assigned addresses
// and routes, then pings a destination through the tunnel.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	proxy := flag.String("proxy", "", "proxy origin, such as https://vpn.example.com:8443")
	caPath := flag.String("ca", "", "PEM CA certificate of the proxy")
	ping := flag.String("ping", "", "IPv4 address to ping through the tunnel")
	request := flag.Bool("request", false, "request an address instead of waiting for one")
	timeout := flag.Duration("timeout", 15*time.Second, "overall deadline")
	flag.Parse()
	if err := run(*proxy, os.Getenv("PORTA_TOKEN"), *caPath, *ping, *request, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "masque-probe:", err)
		os.Exit(1)
	}
}

func run(proxy, token, caPath, ping string, request bool, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tlsConfig := &tls.Config{NextProtos: []string{http3.NextProtoH3}}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("no certificates in the CA file")
		}
		tlsConfig.RootCAs = pool
	}
	// RFC 6570 expansion of the RFC 9484 template with target and ipproto
	// "*" percent-encodes them.
	template, err := uritemplate.New(proxy + "/.well-known/masque/ip/%2A/%2A/")
	if err != nil {
		return err
	}
	req, err := connectip.NewRequest(ctx, template)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	transport := &connectip.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350},
	}
	conn, response, err := transport.Dial(req)
	if err != nil {
		if response != nil {
			return fmt.Errorf("%w (reason %q)", err, response.Header.Get("X-Porta-Reason"))
		}
		return err
	}
	defer conn.Close()
	if request {
		if _, err := conn.RequestAddresses([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")}); err != nil {
			return err
		}
	}
	assigned, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		return fmt.Errorf("address assignment: %w", err)
	}
	var source netip.Addr
	for _, address := range assigned {
		fmt.Printf("address %s\n", address.IPPrefix)
		if address.IPPrefix.Addr().Is4() && !address.Rejected() {
			source = address.IPPrefix.Addr()
		}
	}
	routes, err := conn.Routes(ctx)
	if err != nil {
		return fmt.Errorf("routes: %w", err)
	}
	for _, route := range routes {
		fmt.Printf("route %s-%s protocol %d\n", route.StartIP, route.EndIP, route.IPProtocol)
	}
	if ping == "" {
		return nil
	}
	if !source.IsValid() {
		return errors.New("no IPv4 address was assigned")
	}
	destination, err := netip.ParseAddr(ping)
	if err != nil {
		return err
	}
	packet := echoRequest(source, destination, 0x5054, 1)
	if _, err := conn.WritePacket(packet); err != nil {
		return fmt.Errorf("send echo request: %w", err)
	}
	buffer := make([]byte, 2048)
	for {
		n, err := conn.ReadPacket(buffer)
		if err != nil {
			return fmt.Errorf("receive echo reply: %w", err)
		}
		reply := buffer[:n]
		if len(reply) >= 28 && reply[9] == 1 && reply[20] == 0 &&
			netip.AddrFrom4([4]byte(reply[12:16])) == destination &&
			binary.BigEndian.Uint16(reply[24:26]) == 0x5054 {
			fmt.Printf("echo reply from %s\n", destination)
			return nil
		}
	}
}

// echoRequest is an IPv4 ICMP echo request.
func echoRequest(source, destination netip.Addr, id, sequence uint16) []byte {
	payload := []byte("porta interop")
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20]))
	icmp := packet[20:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:], checksum(icmp))
	return packet
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}
