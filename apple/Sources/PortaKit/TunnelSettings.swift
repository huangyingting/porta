import Foundation
import NetworkExtension

/// The packet tunnel's network settings for a connected session.
public enum TunnelSettings {
    /// Settings that route the session's prefixes (everything for a full
    /// tunnel) and DNS into the tunnel. `remoteAddress` is the gateway's
    /// public address, which the system keeps outside the tunnel.
    public static func make(info: SessionInfo, remoteAddress: String) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        settings.mtu = NSNumber(value: info.mtu)

        let ipv4 = NEIPv4Settings(addresses: [host(info.address)], subnetMasks: ["255.255.255.255"])
        if info.fullTunnel {
            ipv4.includedRoutes = [NEIPv4Route.default()]
        } else {
            ipv4.includedRoutes = info.routes.compactMap { prefix in
                guard let (address, length) = split(prefix), let mask = ipv4Mask(prefixLength: length) else {
                    return nil
                }
                return NEIPv4Route(destinationAddress: address, subnetMask: mask)
            } + (info.dns.map { [NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")] } ?? [])
        }
        settings.ipv4Settings = ipv4

        if let address6 = info.address6 {
            let ipv6 = NEIPv6Settings(addresses: [host(address6)], networkPrefixLengths: [128])
            if info.fullTunnel {
                ipv6.includedRoutes = [NEIPv6Route.default()]
            } else {
                ipv6.includedRoutes = info.routes6.compactMap { prefix in
                    guard let (address, length) = split(prefix) else { return nil }
                    return NEIPv6Route(destinationAddress: address, networkPrefixLength: NSNumber(value: length))
                }
            }
            settings.ipv6Settings = ipv6
        }

        if let dns = info.dns, info.fullTunnel || !info.dnsDomains.isEmpty {
            let resolver = NEDNSSettings(servers: [dns])
            // A full tunnel resolves every name through the tunnel; a split
            // tunnel only its domains.
            resolver.matchDomains = info.fullTunnel ? [""] : info.dnsDomains
            settings.dnsSettings = resolver
        }
        return settings
    }

    /// The address of `a.b.c.d/len`.
    static func host(_ prefix: String) -> String {
        String(prefix.split(separator: "/").first ?? Substring(prefix))
    }

    static func split(_ prefix: String) -> (String, Int)? {
        let parts = prefix.split(separator: "/")
        guard parts.count == 2, let length = Int(parts[1]) else { return nil }
        return (String(parts[0]), length)
    }

    /// The dotted mask of an IPv4 prefix length.
    static func ipv4Mask(prefixLength: Int) -> String? {
        guard (0 ... 32).contains(prefixLength) else { return nil }
        let mask: UInt32 = prefixLength == 0 ? 0 : UInt32.max << UInt32(32 - prefixLength)
        return [24, 16, 8, 0].map { String((mask >> UInt32($0)) & 0xFF) }.joined(separator: ".")
    }
}
