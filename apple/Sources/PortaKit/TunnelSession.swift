import CPorta
import Foundation

/// The network settings of a connected tunnel, as the gateway assigned them.
public struct SessionInfo: Codable, Equatable {
    public struct Account: Codable, Equatable {
        public var expiresAt: Int64?
        public var quotaBytes: UInt64?
        public var quotaUsedBytes: UInt64?
        public var rateLimitKbps: UInt32?
    }

    /// IPv4 address as `a.b.c.d/32`.
    public var address: String
    public var gateway: String?
    /// IPv6 address as `x::y/128`, when the gateway is dual-stack.
    public var address6: String?
    public var dns: String?
    public var mtu: Int
    /// `h3` or `h2`.
    public var transport: String
    /// Split-tunnel prefixes; empty for a full tunnel.
    public var routes: [String]
    public var routes6: [String]
    public var dnsDomains: [String]
    public var fullTunnel: Bool
    public var account: Account
}

/// Which protocol carries the tunnel.
public enum TunnelTransport: UInt32 {
    case automatic = 0
    case http2 = 2
    case http3 = 3
}

/// A connected tunnel. `send` and `receive` may run on different threads;
/// `cancel` ends a blocked `receive`.
public final class TunnelSession {
    let handle: OpaquePointer
    /// Keeps the signing key alive while the tunnel re-proves the device.
    private let identity: DeviceIdentity
    public let info: SessionInfo

    /// Connects, blocking until the tunnel is up or fails.
    public static func connect(
        server: String,
        token: String,
        identity: DeviceIdentity,
        remoteAddress: String? = nil,
        caPath: String? = nil,
        thumbprint: String? = nil,
        transport: TunnelTransport = .automatic,
        timeout: TimeInterval = 15
    ) throws -> TunnelSession {
        let strings = [server, token, remoteAddress, caPath, thumbprint].map { value in
            value.map { strdup($0) } ?? nil
        }
        defer { strings.forEach { free($0) } }
        var config = PortaConfig(
            server: strings[0],
            token: strings[1],
            remote_address: strings[2],
            ca_path: strings[3],
            thumbprint: strings[4],
            transport: transport.rawValue,
            timeout_ms: UInt32(max(1, timeout * 1000))
        )
        var status: Int32 = 0
        let (handle, message) = withErrorBuffer { error, capacity in
            porta_connect(&config, identity.handle, &status, error, capacity)
        }
        guard let handle else {
            throw PortaError(status: status, message: message)
        }
        do {
            return try TunnelSession(handle: handle, identity: identity)
        } catch {
            porta_close(handle)
            throw error
        }
    }

    private init(handle: OpaquePointer, identity: DeviceIdentity) throws {
        let length = porta_session_info(handle, nil, 0)
        guard length > 0 else {
            throw PortaError.permanent("the tunnel has no network settings")
        }
        var buffer = [CChar](repeating: 0, count: Int(length) + 1)
        _ = porta_session_info(handle, &buffer, buffer.count)
        let json = buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        self.info = try JSONDecoder().decode(SessionInfo.self, from: Data(json.utf8))
        self.handle = handle
        self.identity = identity
    }

    deinit {
        porta_close(handle)
    }

    /// Sends one IP packet from the device into the tunnel.
    public func send(_ packet: Data) throws {
        let (status, message) = withErrorBuffer { error, capacity in
            packet.withUnsafeBytes { bytes in
                porta_send(handle, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, error, capacity)
            }
        }
        if status != PORTA_OK {
            throw PortaError(status: status, message: message)
        }
    }

    /// The next IP packet for the device, or nil after `timeout`.
    public func receive(timeout: TimeInterval) throws -> Data? {
        var buffer = [UInt8](repeating: 0, count: 65_536)
        let capacity = buffer.count
        let (length, message) = withErrorBuffer { error, errorCapacity in
            buffer.withUnsafeMutableBufferPointer { pointer in
                porta_receive(handle, pointer.baseAddress, capacity, UInt32(max(0, timeout * 1000)), error, errorCapacity)
            }
        }
        if length < 0 {
            throw PortaError(status: Int32(length), message: message)
        }
        return length == 0 ? nil : Data(buffer[0 ..< Int(length)])
    }

    /// Ends the tunnel; blocked and later calls fail.
    public func cancel() {
        porta_cancel(handle)
    }
}
