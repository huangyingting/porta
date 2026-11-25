import Foundation
import Network
import PortaKit

/// A saved profile. Each one is a VPN configuration in the system's
/// settings, with its token in the keychain.
struct VPNProfile: Identifiable, Equatable {
    var id: String
    var name: String
    var server: String
    var backupServers: [String]
    var relayAddress: String
    var allowLocalNetwork: Bool
    var connectAutomatically: Bool

    /// The gateway as the profile list shows it, such as vpn.example.com:8443.
    var displayServer: String {
        guard let components = URLComponents(string: server), let host = components.host else { return server }
        return components.port.map { "\(host):\($0)" } ?? host
    }

    var initial: String {
        name.first.map { String($0).uppercased() } ?? "P"
    }
}

/// The profile editor's fields. A nil `profileID` is a new profile.
struct ProfileDraft: Identifiable, Equatable {
    var profileID: String?
    var name = ""
    var server = "https://"
    var backupServers = ""
    var relayAddress = ""
    var token = ""
    var allowLocalNetwork = false
    var connectAutomatically = false

    var id: String { profileID ?? "new" }

    init() {}

    init(profile: VPNProfile) {
        profileID = profile.id
        name = profile.name
        server = profile.server
        backupServers = profile.backupServers.joined(separator: "\n")
        relayAddress = profile.relayAddress
        allowLocalNetwork = profile.allowLocalNetwork
        connectAutomatically = profile.connectAutomatically
    }

    /// A new profile from a setup link or profile QR code. It is not saved
    /// until the user reviews it.
    init(setup: Profile) {
        name = setup.name ?? URLComponents(string: setup.server)?.host ?? ""
        server = setup.server
        token = setup.token
    }

    var trimmedName: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }
    var trimmedServer: String { Self.origin(server) }
    var trimmedRelay: String { relayAddress.trimmingCharacters(in: .whitespacesAndNewlines) }
    var trimmedToken: String { token.trimmingCharacters(in: .whitespacesAndNewlines) }
    var backupList: [String] {
        backupServers.split(whereSeparator: \.isNewline)
            .map { Self.origin(String($0)) }
            .filter { !$0.isEmpty }
    }

    /// Why the draft cannot be saved, or nil.
    func problem() -> String? {
        if trimmedName.isEmpty || trimmedName.count > 80 {
            return String(localized: "Enter a profile name.")
        }
        if !Profile.isHTTPSOrigin(trimmedServer) || backupList.contains(where: { !Profile.isHTTPSOrigin($0) }) {
            return String(localized: "Enter the gateway as an HTTPS address, such as https://vpn.example.com.")
        }
        if !trimmedRelay.isEmpty {
            if !Self.isRelayAddress(trimmedRelay) {
                return String(localized: "Enter the relay as an IP address and port, such as 203.0.113.7:8443.")
            }
            if !backupList.isEmpty {
                return String(localized: "A relay forwards to one gateway. Remove the backup gateways or the relay.")
            }
        }
        // A new profile needs a token; an edited one keeps its own when blank.
        if (profileID == nil || !trimmedToken.isEmpty) && !Self.isToken(trimmedToken) {
            return String(localized: "Enter a valid access token.")
        }
        return nil
    }

    /// The origin without surrounding space or a trailing slash.
    static func origin(_ value: String) -> String {
        var value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        while value.hasSuffix("/") { value.removeLast() }
        return value
    }

    static func isToken(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 512
            && value.unicodeScalars.allSatisfy { $0.value > 0x20 && $0.value < 0x7F }
    }

    /// `IP`, `IP:PORT` or `[IPv6]:PORT`, as the other clients accept.
    static func isRelayAddress(_ value: String) -> Bool {
        func isPort(_ text: Substring) -> Bool {
            guard let port = Int(text) else { return false }
            return (1 ... 65535).contains(port)
        }
        if value.hasPrefix("[") {
            guard let end = value.firstIndex(of: "]") else { return false }
            let host = value[value.index(after: value.startIndex) ..< end]
            let rest = value[value.index(after: end)...]
            return IPv6Address(String(host)) != nil && rest.hasPrefix(":") && isPort(rest.dropFirst())
        }
        if IPv6Address(value) != nil || IPv4Address(value) != nil {
            return true
        }
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        return parts.count == 2 && IPv4Address(String(parts[0])) != nil && isPort(parts[1])
    }
}

/// Live traffic for the chart, in bytes per second.
struct TrafficSample: Identifiable, Equatable {
    var id: Int
    var download: Double
    var upload: Double
}
