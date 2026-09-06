//go:build linux

package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/huangyingting/porta/internal/device"
	"golang.org/x/sys/unix"
)

// Compile without privileges, then run only this test with:
//
//	sudo -n unshare --net -- env PORTA_MTU_NATIVE_TEST=1 <test-binary> \
//	  -test.run '^TestNativeMTUFeedback$' -test.v -test.timeout=30s
//
// The working directory must be internal/gateway so the real helper is used.
func TestNativeMTUFeedback(t *testing.T) {
	if os.Getenv("PORTA_MTU_NATIVE_TEST") != "1" {
		t.Skip("set PORTA_MTU_NATIVE_TEST=1 inside a fresh unshare --net namespace")
	}
	// Fail closed before opening TUN, sockets, or running any network commands.
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("cannot establish network namespace isolation: %v", err)
	}
	initial, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		t.Fatalf("cannot identify initial network namespace: %v", err)
	}
	if os.SameFile(current, initial) {
		t.Fatal("refusing native network test in PID 1's network namespace; use sudo -n unshare --net --")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("refusing native network test outside a fresh, loopback-only network namespace")
	}
	t.Setenv("PORTA_RUNTIME_DIRECTORY", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	network := mtuNativeNetwork{t: t, ctx: ctx}
	const tunName, outName, peerName = "porta-test-tun", "porta-test-out", "porta-test-in"
	network.run("sysctl", "-w", "net.ipv4.ip_forward=1")
	network.set("all/rp_filter", "1")
	network.set("default/rp_filter", "1")
	network.set("all/accept_local", "0")
	network.set("default/accept_local", "0")
	network.run("ip", "link", "set", "lo", "up")
	native, err := device.OpenNative(tunName, 1400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := native.Close(); err != nil {
			t.Errorf("close native TUN: %v", err)
		}
	})
	network.run("ip", "link", "add", outName, "type", "veth", "peer", "name", peerName)
	network.run("ip", "address", "add", "198.18.0.1/24", "dev", outName)
	network.run("ip", "link", "set", outName, "up")
	network.run("ip", "link", "set", peerName, "up")
	out, err := net.InterfaceByName(outName)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := net.InterfaceByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	network.run("ip", "neigh", "add", "198.18.0.2", "lladdr", peer.HardwareAddr.String(),
		"nud", "permanent", "dev", outName)
	helperArgs := []string{"../../scripts/server-up.sh", tunName, "10.66.0.1/24", "10.66.0.0/24", outName, "8443"}
	network.run("bash", append(append([]string(nil), helperArgs...), "--auto-mtu=false")...)
	network.check(tunName+"/accept_local", "0")
	network.check(tunName+"/rp_filter", "1")
	// Pin the gateway's local reverse route to loopback. A local route owned by
	// TUN can pass strict RPF on some kernels even though route-get reports lo.
	// This fixture exercises the loopback reverse-route case deterministically.
	network.run("ip", "route", "replace", "local", "10.66.0.1/32", "dev", "lo", "table", "local")
	// Both veth ends are in this namespace. The peer is an Ethernet test endpoint,
	// not another router; disabling forwarding prevents recirculation.
	network.set(peerName+"/forwarding", "0")

	etherIPv4 := binary.NativeEndian.Uint16([]byte{0x08, 0x00})
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(etherIPv4))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: etherIPv4}); err != nil {
		t.Fatal(err)
	}

	session, lease, _, usageSession := newMTUTestSession(t, 1100)
	session.Router = NewRouter(native, nil)
	clientIP, gatewayIP := lease.Address.As4(), lease.Gateway.As4()
	wanIP, remoteIP := [4]byte{198, 18, 0, 1}, [4]byte{198, 18, 0, 2}
	for index, phase := range []struct {
		name        string
		acceptLocal string
		rpf         string
		auto        bool
	}{
		{"local_source_rejected_even_with_loose_rpf", "0", "2", false},
		{"accepted_local_source_rejected_by_strict_rpf", "1", "1", false},
		{"automatic_mtu_helper_allows_nat_icmp_egress", "1", "2", true},
	} {
		if !t.Run(phase.name, func(t *testing.T) {
			network := mtuNativeNetwork{t: t, ctx: ctx}
			if phase.auto {
				network.set(tunName+"/accept_local", "0")
				network.set(tunName+"/rp_filter", "1")
				network.run("bash", helperArgs...)
				network.set(peerName+"/forwarding", "0")
			} else {
				network.set(tunName+"/accept_local", phase.acceptLocal)
				network.set(tunName+"/rp_filter", phase.rpf)
			}
			network.check(tunName+"/accept_local", phase.acceptLocal)
			network.check(tunName+"/rp_filter", phase.rpf)
			network.check("all/rp_filter", "1")
			network.check("default/rp_filter", "1")
			network.check(outName+"/rp_filter", "1")
			network.check(peerName+"/rp_filter", "1")
			network.check("all/accept_local", "0")
			network.check("default/accept_local", "0")
			network.check(outName+"/accept_local", "0")
			network.check(peerName+"/accept_local", "0")
			network.check(peerName+"/forwarding", "0")
			if route := network.run("ip", "route", "show", "table", "local", "exact", "10.66.0.1/32"); !strings.Contains(route, "dev lo") {
				t.Fatalf("gateway reverse-route fixture no longer points to loopback: %s", route)
			}

			clientPort := uint16(40000 + index)
			upload := mtuNativeUDP(100, clientIP, remoteIP, clientPort, 443)
			if err := native.WritePacket(ctx, upload); err != nil {
				t.Fatal(err)
			}
			captureCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			snat, err := mtuNativeCapture(captureCtx, fd, out.HardwareAddr, peer.HardwareAddr, 17)
			stop()
			if err != nil {
				t.Fatalf("capture SNATed client upload: %v", err)
			}
			mtuNativeCheckIPv4(t, snat, wanIP, remoteIP, len(upload))
			mtuNativeCheckUDP(t, snat)
			wanPort := binary.BigEndian.Uint16(snat[20:22])
			if wanPort == 0 || binary.BigEndian.Uint16(snat[22:24]) != 443 ||
				!bytes.Equal(snat[28:], upload[28:]) {
				t.Fatalf("incorrect SNATed UDP upload: %x", snat[:28])
			}

			reply := mtuNativeUDP(1300, remoteIP, wanIP, 443, wanPort)
			ethernet := make([]byte, 14+len(reply))
			copy(ethernet[:6], out.HardwareAddr)
			copy(ethernet[6:12], peer.HardwareAddr)
			binary.BigEndian.PutUint16(ethernet[12:14], unix.ETH_P_IP)
			copy(ethernet[14:], reply)
			if err := unix.Sendto(fd, ethernet, 0, &unix.SockaddrLinklayer{
				Ifindex: peer.Index, Protocol: etherIPv4,
			}); err != nil {
				t.Fatalf("inject remote UDP reply: %v", err)
			}
			readCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			var downlink []byte
			for {
				downlink, err = native.ReadPacket(readCtx)
				if err != nil || len(downlink) == 0 || downlink[0]>>4 != 6 {
					break
				}
				// TUN may queue IPv6 router solicitation before the helper
				// disables IPv6; it is unrelated to this IPv4 exchange.
			}
			stop()
			if err != nil {
				t.Fatalf("read conntrack-DNATed remote reply from native TUN: %v", err)
			}
			mtuNativeCheckIPv4(t, downlink, remoteIP, clientIP, 1300)
			mtuNativeCheckUDP(t, downlink)
			if binary.BigEndian.Uint16(downlink[6:8]) != 0x4000 ||
				binary.BigEndian.Uint16(downlink[20:22]) != 443 ||
				binary.BigEndian.Uint16(downlink[22:24]) != clientPort ||
				!bytes.Equal(downlink[28:], reply[28:]) {
				t.Fatalf("incorrect DF/DNATed UDP reply: %x", downlink[:28])
			}
			session.icmpAfter = time.Time{}
			before := session.Metrics.mtuICMPSent.Load()
			if err := session.sendDownlink(ctx, lease, downlink, func([]byte) error {
				t.Error("oversized DF packet was sent to the client")
				return nil
			}, usageSession); err != nil {
				t.Fatalf("sendDownlink native ICMP injection: %v", err)
			}
			if session.Metrics.mtuICMPSent.Load() != before+1 {
				t.Fatal("ICMP was not successfully written to the native TUN")
			}
			wait := 500 * time.Millisecond
			if phase.auto {
				wait = 2 * time.Second
			}
			captureCtx, stop = context.WithTimeout(ctx, wait)
			icmp, err := mtuNativeCapture(captureCtx, fd, out.HardwareAddr, peer.HardwareAddr, 1)
			stop()
			if !phase.auto {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expected kernel to suppress ICMP despite successful TUN write; packet=%x error=%v", icmp, err)
				}
				t.Logf("real NAT downlink succeeded; native ICMP write succeeded but kernel suppressed egress (accept_local=%s, tun rp_filter=%s)",
					phase.acceptLocal, phase.rpf)
				return
			}
			if err != nil {
				t.Fatalf("capture fragmentation-needed ICMP on WAN: %v", err)
			}
			mtuNativeCheckIPv4(t, icmp, wanIP, remoteIP, 56)
			if icmp[20] != 3 || icmp[21] != 4 ||
				binary.BigEndian.Uint16(icmp[26:28]) != 1100 || mtuChecksum(icmp[20:]) != 0 {
				t.Fatalf("invalid ICMP type/code/MTU/checksum: %x", icmp)
			}
			// RELATED conntrack NAT must undo DNAT in the quoted UDP header,
			// and translate the locally sourced outer IP to the WAN address.
			quoted := icmp[28:]
			if !bytes.Equal(quoted[12:16], remoteIP[:]) ||
				!bytes.Equal(quoted[16:20], wanIP[:]) ||
				binary.BigEndian.Uint16(quoted[20:22]) != 443 ||
				binary.BigEndian.Uint16(quoted[22:24]) != wanPort ||
				mtuChecksum(quoted[:20]) != 0 {
				t.Fatalf("ICMP quoted packet did not receive conntrack NAT translation: %x", quoted)
			}
			expectedQuote := bytes.Clone(reply[:28])
			expectedQuote[8] = downlink[8]
			mtuSetChecksum(expectedQuote)
			if !bytes.Equal(quoted, expectedQuote) {
				t.Fatalf("quoted headers/checksums differ from translated remote reply:\n got %x\nwant %x", quoted, expectedQuote)
			}
			t.Logf("captured real ICMP type=3 code=4 MTU=1100: gateway %v NATed to %v; quoted UDP destination=%v:%d; global and physical RPF remain strict",
				gatewayIP, wanIP, wanIP, wanPort)
		}) {
			return
		}
	}
}

type mtuNativeNetwork struct {
	t   *testing.T
	ctx context.Context
}

func (n mtuNativeNetwork) run(name string, args ...string) string {
	n.t.Helper()
	output, err := exec.CommandContext(n.ctx, name, args...).CombinedOutput()
	if err != nil {
		n.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func (n mtuNativeNetwork) set(key, value string) {
	n.t.Helper()
	n.run("sysctl", "-w", "net/ipv4/conf/"+key+"="+value)
}

func (n mtuNativeNetwork) check(key, value string) {
	n.t.Helper()
	if got := n.run("sysctl", "-n", "net/ipv4/conf/"+key); got != value {
		n.t.Fatalf("%s = %s, want %s", key, got, value)
	}
}

func mtuNativeUDP(size int, source, destination [4]byte, sourcePort, destinationPort uint16) []byte {
	packet := mtuIPv4Packet(size, true)
	packet[9] = 17
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(size-20))
	packet[26], packet[27] = 0, 0
	checksum := mtuNativeUDPChecksum(packet)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[26:28], checksum)
	mtuSetChecksum(packet)
	return packet
}

func mtuNativeUDPChecksum(packet []byte) uint16 {
	pseudo := make([]byte, 12+len(packet)-20)
	copy(pseudo[:8], packet[12:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	copy(pseudo[12:], packet[20:])
	return mtuChecksum(pseudo)
}

func mtuNativeCheckIPv4(t *testing.T, packet []byte, source, destination [4]byte, size int) {
	t.Helper()
	if len(packet) != size || len(packet) < 20 || packet[0] != 0x45 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != size ||
		!bytes.Equal(packet[12:16], source[:]) || !bytes.Equal(packet[16:20], destination[:]) ||
		mtuChecksum(packet[:20]) != 0 {
		t.Fatalf("invalid IPv4 packet; want length=%d source=%v destination=%v: %x", size, source, destination, packet)
	}
}

func mtuNativeCheckUDP(t *testing.T, packet []byte) {
	t.Helper()
	if len(packet) < 28 || packet[9] != 17 ||
		int(binary.BigEndian.Uint16(packet[24:26])) != len(packet)-20 ||
		binary.BigEndian.Uint16(packet[26:28]) == 0 || mtuNativeUDPChecksum(packet) != 0 {
		t.Fatalf("invalid UDP length/checksum: %x", packet)
	}
}

func mtuNativeCapture(ctx context.Context, fd int, source, destination net.HardwareAddr, protocol byte) ([]byte, error) {
	frame := make([]byte, 2048)
	for received := 0; ; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, 25); err != nil && !errors.Is(err, unix.EINTR) {
			return nil, err
		}
		if fds[0].Revents == 0 {
			continue
		}
		n, from, err := unix.Recvfrom(fd, frame, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		received++
		if received > 64 {
			return nil, fmt.Errorf("unexpected packet flood in isolated namespace; possible forwarding loop")
		}
		address, ok := from.(*unix.SockaddrLinklayer)
		if !ok || address.Pkttype == unix.PACKET_OUTGOING || n < 34 ||
			!bytes.Equal(frame[:6], destination) || !bytes.Equal(frame[6:12], source) ||
			binary.BigEndian.Uint16(frame[12:14]) != unix.ETH_P_IP || frame[23] != protocol {
			continue
		}
		size := int(binary.BigEndian.Uint16(frame[16:18]))
		if size < 20 || size > n-14 {
			return nil, fmt.Errorf("truncated IPv4 Ethernet frame: IPv4 length=%d frame length=%d", size, n)
		}
		return bytes.Clone(frame[14 : 14+size]), nil
	}
}
