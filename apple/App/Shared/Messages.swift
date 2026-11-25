import Foundation
import NetworkExtension
import PortaKit

/// The words the app shows for tunnel states, sessions and errors, matching
/// the other Porta clients.
enum Messages {
    static func state(_ status: NEVPNStatus) -> String {
        switch status {
        case .connected: return String(localized: "Connected")
        case .connecting: return String(localized: "Connecting")
        case .reasserting: return String(localized: "Reconnecting")
        case .disconnecting: return String(localized: "Disconnecting")
        default: return String(localized: "Disconnected")
        }
    }

    /// What a gateway's refusal means for the user.
    static func denial(code: String) -> String? {
        switch code {
        case "account-expired":
            return String(localized: "This account has expired. Ask your administrator to renew it.")
        case "quota-exceeded":
            return String(localized: "This account has used its monthly data allowance. Access resumes next month or when your administrator raises it.")
        case "device-pending":
            return String(localized: "This device is waiting for administrator approval. Connect again once it is approved.")
        case "enrollment-closed":
            return String(localized: "This account accepts no new devices. Ask your administrator to allow enrollment.")
        case "device-denied":
            return String(localized: "Your administrator has not allowed this device to connect.")
        case "client-outdated":
            return String(localized: "This version of Porta is too old for the gateway. Install the latest version.")
        case "hardware-required":
            return String(localized: "This account accepts only devices whose key is protected by secure hardware, which Apple devices cannot prove yet. Ask your administrator.")
        default:
            return nil
        }
    }

    /// The message for an error the tunnel reported, or a system error.
    static func describe(_ error: Error) -> String {
        if let error = PortaError(reported: error) {
            if case let .denied(code, message) = error {
                return denial(code: code) ?? message
            }
            return error.description
        }
        return error.localizedDescription
    }

    static func transport(_ info: SessionInfo) -> String {
        let transport = info.transport == "h3"
            ? String(localized: "HTTP/3 MASQUE · fast and resilient")
            : String(localized: "HTTP/2 fallback · encrypted")
        return String(localized: "\(transport) · MTU \(info.mtu)")
    }

    static func routing(_ info: SessionInfo) -> String {
        if info.fullTunnel {
            return String(localized: "All traffic goes through the gateway")
        }
        let count = info.routes.count + info.routes6.count
        return String(localized: "Split tunnel · \(count) networks via the gateway")
    }

    /// The account's limits, or nil when it has none.
    static func account(_ account: SessionInfo.Account, now: Date = Date()) -> String? {
        var parts: [String] = []
        if let expiresAt = account.expiresAt {
            let date = Date(timeIntervalSince1970: TimeInterval(expiresAt))
            let text = date.formatted(date: .abbreviated, time: .omitted)
            parts.append(date.timeIntervalSince(now) < 7 * 86400
                ? String(localized: "Access ends \(text)")
                : String(localized: "Access until \(text)"))
        }
        if let quota = account.quotaBytes {
            if let used = account.quotaUsedBytes {
                parts.append(String(localized: "\(bytes(used)) of \(bytes(quota)) used this month"))
            } else {
                parts.append(String(localized: "\(bytes(quota)) monthly allowance"))
            }
        }
        if let rate = account.rateLimitKbps {
            let mbps = (Double(rate) / 1000).formatted(.number.precision(.fractionLength(0 ... 1)))
            parts.append(String(localized: "Speed limited to \(mbps) Mbit/s"))
        }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// Whether the account line deserves attention: access ends within a
    /// week or 90% of the quota is used.
    static func accountNeedsAttention(_ account: SessionInfo.Account, now: Date = Date()) -> Bool {
        if let expiresAt = account.expiresAt, Double(expiresAt) - now.timeIntervalSince1970 < 7 * 86400 {
            return true
        }
        if let quota = account.quotaBytes, let used = account.quotaUsedBytes, quota > 0 {
            return Double(used) >= Double(quota) * 0.9
        }
        return false
    }

    static func bytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .binary)
    }

    static func rate(_ bytesPerSecond: Double) -> String {
        "\(bytes(UInt64(max(0, bytesPerSecond))))/s"
    }
}
