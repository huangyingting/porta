import NetworkExtension
import XCTest
@testable import PortaKit

final class ProfileTests: XCTestCase {
    func testParsesSetupLinks() throws {
        let profile = try Profile(setupLink: "porta://profile?v=1&server=https%3A%2F%2Fporta.example.com%3A8443&token=example-not-a-secret&name=My+Phone")
        XCTAssertEqual(profile, Profile(server: "https://porta.example.com:8443", token: "example-not-a-secret", name: "My Phone"))
        let minimal = try Profile(setupLink: "porta://profile?token=t0ken&v=1&server=https%3A%2F%2Fvpn.example.com")
        XCTAssertNil(minimal.name)
    }

    func testRejectsMalformedSetupLinks() {
        for link in [
            "porta://profile?v=2&server=https%3A%2F%2Fa.example&token=t",
            "porta://profile?v=1&server=http%3A%2F%2Fa.example&token=t",
            "porta://profile?v=1&server=https%3A%2F%2Fa.example%2Fpath&token=t",
            "porta://profile?v=1&server=https%3A%2F%2Fa.example&token=t&token=u",
            "porta://profile?v=1&server=https%3A%2F%2Fa.example&token=t&extra=1",
            "porta://profile?v=1&server=https%3A%2F%2Fa.example&token=has+space",
            "porta://profile?v=1&server=https%3A%2F%2Fa.example&token=%ZZ",
            " porta://profile?v=1&server=https%3A%2F%2Fa.example&token=t",
            "https://profile?v=1&server=https%3A%2F%2Fa.example&token=t",
        ] {
            XCTAssertThrowsError(try Profile(setupLink: link), link)
        }
    }

    func testSettingsFollowTheSession() {
        let split = SessionInfo(
            address: "10.66.0.2/32", gateway: "10.66.0.1", address6: "fd66::2/128",
            dns: "10.66.0.1", mtu: 1400, transport: "h3",
            routes: ["10.20.0.0/16", "10.66.0.0/24"], routes6: ["fd66::/64"],
            dnsDomains: ["corp.example"], fullTunnel: false,
            account: .init(expiresAt: nil, quotaBytes: nil, quotaUsedBytes: nil, rateLimitKbps: nil)
        )
        let settings = TunnelSettings.make(info: split, remoteAddress: "192.0.2.1")
        XCTAssertEqual(settings.mtu, 1400)
        XCTAssertEqual(settings.ipv4Settings?.addresses, ["10.66.0.2"])
        XCTAssertEqual(settings.ipv4Settings?.includedRoutes?.map(\.destinationAddress), ["10.20.0.0", "10.66.0.0", "10.66.0.1"])
        XCTAssertEqual(settings.ipv4Settings?.includedRoutes?.first?.destinationSubnetMask, "255.255.0.0")
        XCTAssertEqual(settings.ipv6Settings?.addresses, ["fd66::2"])
        XCTAssertEqual(settings.ipv6Settings?.includedRoutes?.map(\.destinationAddress), ["fd66::"])
        XCTAssertEqual(settings.dnsSettings?.matchDomains, ["corp.example"])

        var full = split
        full.fullTunnel = true
        full.routes = []
        full.address6 = nil
        let fullSettings = TunnelSettings.make(info: full, remoteAddress: "192.0.2.1")
        XCTAssertEqual(fullSettings.ipv4Settings?.includedRoutes?.first?.destinationAddress, NEIPv4Route.default().destinationAddress)
        XCTAssertNil(fullSettings.ipv6Settings)
        XCTAssertEqual(fullSettings.dnsSettings?.matchDomains, [""])
    }

    func testMasksAndKeyEncoding() {
        XCTAssertEqual(TunnelSettings.ipv4Mask(prefixLength: 0), "0.0.0.0")
        XCTAssertEqual(TunnelSettings.ipv4Mask(prefixLength: 20), "255.255.240.0")
        XCTAssertEqual(TunnelSettings.ipv4Mask(prefixLength: 32), "255.255.255.255")
        XCTAssertNil(TunnelSettings.ipv4Mask(prefixLength: 33))
        let spki = DeviceIdentity.subjectPublicKeyInfo(point: Data([0x04] + [UInt8](repeating: 1, count: 64)))
        XCTAssertEqual(spki.count, 91)
        XCTAssertEqual(spki.prefix(2), Data([0x30, 0x59]))
    }

    func testRelayHostsDropThePort() {
        XCTAssertEqual(PortaPacketTunnelProvider.relayHost("203.0.113.7:8443"), "203.0.113.7")
        XCTAssertEqual(PortaPacketTunnelProvider.relayHost("203.0.113.7"), "203.0.113.7")
        XCTAssertEqual(PortaPacketTunnelProvider.relayHost("[2001:db8::7]:443"), "2001:db8::7")
        XCTAssertEqual(PortaPacketTunnelProvider.relayHost("2001:db8::7"), "2001:db8::7")
    }

    func testDenialsCarryTheirCode() {
        XCTAssertEqual(
            PortaError(status: -3, message: "account-denied:device-pending: Waiting for approval"),
            .denied(code: "device-pending", message: "Waiting for approval")
        )
        XCTAssertEqual(PortaError(status: -1, message: "timeout"), .retryable("timeout"))
    }

    func testReportedErrorsKeepTheirMeaning() {
        let denied = PortaError.denied(code: "device-pending", message: "Waiting for approval")
        // The system passes the extension's error to the app as an NSError.
        let reported = denied as NSError
        XCTAssertEqual(reported.domain, PortaError.errorDomain)
        XCTAssertEqual(reported.localizedDescription, "Waiting for approval")
        XCTAssertEqual(PortaError(reported: reported), denied)
        XCTAssertEqual(PortaError(reported: PortaError.retryable("timeout") as NSError), .retryable("timeout"))
        XCTAssertNil(PortaError(reported: NSError(domain: NSPOSIXErrorDomain, code: 1)))
    }

    func testReportsRoundTrip() throws {
        var log = EventLog(capacity: 2)
        for message in ["one", "two", "three"] {
            log.append(message, at: Date(timeIntervalSince1970: 1_700_000_000))
        }
        XCTAssertEqual(log.entries.map(\.message), ["two", "three"])
        let report = TunnelReport(
            info: SessionInfo(
                address: "10.66.0.2/32", gateway: nil, address6: nil, dns: "10.66.0.1", mtu: 1400,
                transport: "h3", routes: [], routes6: [], dnsDomains: [], fullTunnel: true,
                account: .init(expiresAt: 1_800_000_000, quotaBytes: nil, quotaUsedBytes: nil, rateLimitKbps: nil)
            ),
            connectedAt: Date(timeIntervalSince1970: 1_700_000_000),
            bytesSent: 1200,
            bytesReceived: 3400,
            log: log.entries
        )
        XCTAssertEqual(TunnelReport.decode(report.encoded()), report)
        XCTAssertNil(TunnelReport.decode(Data("not json".utf8)))
    }
}
