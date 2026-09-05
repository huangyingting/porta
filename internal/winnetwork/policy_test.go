package winnetwork

import (
	"net"
	"net/netip"
	"testing"
)

func testSpec(ip string) guardSpec {
	return guardSpec{Key: "test", InterfaceLUID: 77, Endpoint: endpoint{IP: netip.MustParseAddr(ip), Port: 443}, Application: `C:\Porta\porta.exe`}
}

type packet struct {
	ip          netip.Addr
	luid        uint64
	protocol    uint8
	port, local uint16
	app         string
	loopback    bool
}

func matches(c condition, p packet) bool {
	switch c.field {
	case "loopback":
		return p.loopback
	case "interface":
		return c.value.(uint64) == p.luid
	case "application":
		return c.value.(string) == p.app
	case "address":
		return c.value.(netip.Prefix).Contains(p.ip)
	case "protocol":
		return c.value.(uint8) == p.protocol
	case "port":
		return c.value.(uint16) == p.port
	case "local-port":
		return c.value.(uint16) == p.local
	default:
		panic("unrecognized condition")
	}
}

// Model per-sublayer WFP arbitration: the first matching terminating action
// wins. Soft permits never decide what another provider's sublayer will do.
func permits(filters []filter, layer string, p packet) bool {
	for _, rule := range filters {
		if rule.layer != layer {
			continue
		}
		match := true
		for _, c := range rule.conditions {
			match = match && matches(c, p)
		}
		if match {
			return rule.permit
		}
	}
	panic("layer missing a final block")
}

func TestGuardPolicyAllowsOnlyTunnelAndPinnedTransport(t *testing.T) {
	for _, endpointIP := range []string{"192.0.2.1", "2001:db8::1"} {
		spec := testSpec(endpointIP)
		filters := guardFilters(spec)
		if len(filters) > maxGuardFilters {
			t.Fatal("filter key capacity exceeded")
		}
		for _, family := range []string{"4", "6"} {
			for _, kind := range []string{"packet", "transport", "connect", "accept"} {
				layer := kind + family
				if !permits(filters, layer, packet{loopback: true}) {
					t.Fatalf("%s blocked loopback", layer)
				}
				for _, luid := range []uint64{0, 7, 77, 999999} {
					p := packet{ip: netip.MustParseAddr("8.8.8.8"), luid: luid, protocol: 17, port: 53}
					if family == "6" {
						p.ip = netip.MustParseAddr("2001:4860:4860::8888")
					}
					want := luid == 77 && family == "4"
					if permits(filters, layer, p) != want {
						t.Fatalf("%s DNS/payload interface %d bypassed policy", layer, luid)
					}
				}
				if (family == "4") == spec.Endpoint.IP.Is4() {
					p := packet{ip: spec.Endpoint.IP, luid: 7, protocol: 17, port: 443, app: spec.Application}
					if !permits(filters, layer, p) {
						t.Fatalf("%s blocked transport endpoint", layer)
					}
					if kind != "packet" {
						p.port = 53
						if permits(filters, layer, p) {
							t.Fatalf("%s widened endpoint port exemption to DNS", layer)
						}
						p.port = 443
						p.protocol = 1
						if permits(filters, layer, p) {
							t.Fatalf("%s widened endpoint protocol exemption", layer)
						}
					}
					if kind == "connect" || kind == "accept" {
						p.protocol = 17
						p.app = `C:\other.exe`
						if permits(filters, layer, p) {
							t.Fatalf("%s widened endpoint application exemption", layer)
						}
					}
				}
			}
			if permits(filters, "forward"+family, packet{luid: 77, ip: spec.Endpoint.IP}) {
				t.Fatal("forwarded traffic bypassed application identity checks")
			}
		}
	}
}

func TestIPv6ControlExceptionDoesNotAllowPayload(t *testing.T) {
	filters := guardFilters(testSpec("2001:db8::1"))
	for _, destination := range []string{"fe80::1", "ff02::1:ff00:1"} {
		p := packet{ip: netip.MustParseAddr(destination), luid: 7, protocol: 58, local: 135}
		for _, kind := range []string{"packet", "transport", "connect", "accept"} {
			if !permits(filters, kind+"6", p) {
				t.Fatalf("blocked necessary IPv6 neighbor discovery at %s", kind)
			}
		}
		p.protocol, p.port = 17, 53
		for _, kind := range []string{"transport", "connect", "accept"} {
			if permits(filters, kind+"6", p) {
				t.Fatalf("link-local IPv6 DNS bypass at %s", kind)
			}
		}
		p.protocol, p.local, p.port = 58, 128, 0
		if permits(filters, "transport6", p) {
			t.Fatal("ICMPv6 echo payload bypass")
		}
		p.local = 134
		if permits(filters, "transport6", p) || !permits(filters, "accept6", p) {
			t.Fatal("router advertisement exception must be receive-only")
		}
		p.local, p.port = 135, 1
		for _, kind := range []string{"transport", "connect", "accept"} {
			if permits(filters, kind+"6", p) {
				t.Fatalf("nonzero ICMPv6 code bypass at %s", kind)
			}
		}
	}
}

func TestGuardPolicyWithoutTUN(t *testing.T) {
	for _, endpointIP := range []string{"192.0.2.1", "2001:db8::1"} {
		spec := testSpec(endpointIP)
		spec.InterfaceLUID = 0
		filters := guardFilters(spec)
		for _, rule := range filters {
			for _, c := range rule.conditions {
				if c.field == "interface" {
					t.Fatal("no-TUN guard must not permit any interface, including zero")
				}
			}
		}
		for _, family := range []string{"4", "6"} {
			p := packet{ip: netip.MustParseAddr("8.8.8.8"), protocol: 17, port: 53, app: spec.Application}
			if family == "6" {
				p.ip = netip.MustParseAddr("2001:4860:4860::8888")
			}
			for _, kind := range []string{"packet", "transport", "connect", "accept", "forward"} {
				for _, luid := range []uint64{0, 7, 77} {
					p.luid = luid
					if permits(filters, kind+family, p) {
						t.Fatalf("%s%s no-TUN guard leaked on LUID %d", kind, family, luid)
					}
				}
			}
		}
		family := "4"
		if spec.Endpoint.IP.Is6() {
			family = "6"
		}
		p := packet{ip: spec.Endpoint.IP, luid: 7, protocol: 17, port: spec.Endpoint.Port, app: spec.Application}
		for _, kind := range []string{"packet", "transport", "connect", "accept"} {
			if !permits(filters, kind+family, p) {
				t.Fatalf("no-TUN guard blocked pinned transport at %s%s", kind, family)
			}
		}
	}
}

func TestGuardPolicyCoversExistingFlowReauthorization(t *testing.T) {
	for _, endpointIP := range []string{"192.0.2.1", "2001:db8::1"} {
		spec := testSpec(endpointIP)
		family := "4"
		other := netip.MustParseAddr("192.0.2.2")
		if spec.Endpoint.IP.Is6() {
			family = "6"
			other = netip.MustParseAddr("2001:db8::2")
		}
		filters := guardFilters(spec)
		oldFlow := packet{ip: spec.Endpoint.IP, luid: 7, protocol: 6, port: spec.Endpoint.Port, app: `C:\other.exe`}
		// A policy change reauthorizes at the ORIGINAL direction's ALE layer,
		// even when the triggering packet travels in the reverse direction.
		for _, kind := range []string{"connect", "accept"} {
			if permits(filters, kind+family, oldFlow) {
				t.Fatalf("existing foreign application bypassed %s reauthorization", kind)
			}
		}
		oldFlow.ip = other
		for _, kind := range []string{"packet", "transport", "connect", "accept"} {
			if permits(filters, kind+family, oldFlow) {
				t.Fatalf("existing physical-interface flow bypassed %s", kind)
			}
		}
	}
}

func TestIPv4TransportHasNoIPv6ControlException(t *testing.T) {
	filters := guardFilters(testSpec("192.0.2.1"))
	for _, ip := range []string{"fe80::1", "ff02::1", "2001:db8::1"} {
		p := packet{ip: netip.MustParseAddr(ip), luid: 77, protocol: 58, local: 135}
		for _, kind := range []string{"packet", "transport", "connect", "accept", "forward"} {
			if permits(filters, kind+"6", p) {
				t.Fatalf("IPv4 transport unnecessarily permitted IPv6 at %s", kind)
			}
		}
	}
}

func TestObjectKeysStableUniqueAndOwnerScoped(t *testing.T) {
	seen := map[string]bool{}
	for _, owner := range []string{"profile-a", "profile-b"} {
		for index := -2; index < maxGuardFilters; index++ {
			key := objectKey(owner, index)
			if seen[key] || len(key) != 36 || objectKey(owner, index) != key {
				t.Fatalf("unstable/colliding key %q", key)
			}
			seen[key] = true
		}
	}
}

func TestEndpointValidation(t *testing.T) {
	for _, addr := range []net.Addr{
		nil,
		&net.TCPAddr{IP: net.IPv4zero, Port: 443},
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1")},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 853},
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 443, Zone: "7"},
	} {
		if _, err := parseEndpoint(addr); err == nil {
			t.Fatalf("accepted unsafe endpoint %v", addr)
		}
	}
}
