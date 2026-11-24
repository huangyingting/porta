import Foundation
import NetworkExtension
import Security

/// The packet tunnel extension's provider. Use it as the extension's
/// principal class (or subclass it). The app saves a
/// `NETunnelProviderProtocol` whose `serverAddress` is the gateway origin,
/// whose `passwordReference` is a keychain item holding the account token,
/// and whose `providerConfiguration` may hold:
///
/// - `backupServers`: further gateway origins sharing the account;
/// - `transport`: `auto`, `h3` or `h2`;
/// - `identityTag` and `accessGroup`: where the device key lives, shared
///   with the app so both show the same device ID.
///
/// Set `includeAllNetworks` on the protocol for a fail-closed full tunnel,
/// and `excludeLocalNetworks` to keep the local network reachable beside it.
open class PortaPacketTunnelProvider: NEPacketTunnelProvider {
    private let lock = NSLock()
    private var session: TunnelSession?
    private var running = false
    private let connectQueue = DispatchQueue(label: "dev.porta.tunnel.connect")

    open override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        connectQueue.async {
            do {
                let session = try self.connect()
                let settings = TunnelSettings.make(info: session.session.info, remoteAddress: session.remoteAddress)
                self.setTunnelNetworkSettings(settings) { error in
                    if let error {
                        completionHandler(error)
                        return
                    }
                    self.lock.withLock {
                        self.session = session.session
                        self.running = true
                    }
                    self.readPackets()
                    self.startReceiving()
                    completionHandler(nil)
                }
            } catch {
                completionHandler(error)
            }
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let session = lock.withLock { () -> TunnelSession? in
            running = false
            return self.session
        }
        session?.cancel()
        connectQueue.async {
            self.lock.withLock { self.session = nil }
            completionHandler()
        }
    }

    private struct Connected {
        let session: TunnelSession
        let remoteAddress: String
    }

    /// Connects to the first gateway that accepts the device, trying the
    /// backups in order on failures that another gateway may not have.
    private func connect() throws -> Connected {
        guard let configuration = protocolConfiguration as? NETunnelProviderProtocol,
              let server = configuration.serverAddress
        else {
            throw PortaError.permanent("the VPN configuration has no gateway")
        }
        let options = configuration.providerConfiguration ?? [:]
        let token = try Self.token(reference: configuration.passwordReference)
        let identity = try DeviceIdentity.loadOrCreate(
            tag: options["identityTag"] as? String ?? "dev.porta.device-key",
            accessGroup: options["accessGroup"] as? String,
            deviceName: Self.deviceName()
        )
        let transport: TunnelTransport
        switch options["transport"] as? String {
        case "h3": transport = .http3
        case "h2": transport = .http2
        default: transport = .automatic
        }
        var lastError: Error = PortaError.retryable("no gateway answered")
        for gateway in [server] + (options["backupServers"] as? [String] ?? []) {
            guard let host = URLComponents(string: gateway)?.host,
                  let address = Self.resolve(host: host)
            else {
                lastError = PortaError.retryable("cannot resolve \(gateway)")
                continue
            }
            do {
                let session = try TunnelSession.connect(
                    server: gateway,
                    token: token,
                    identity: identity,
                    remoteAddress: address,
                    transport: transport
                )
                return Connected(session: session, remoteAddress: address)
            } catch let error as PortaError {
                lastError = error
                if case .retryable = error { continue }
                throw error
            }
        }
        throw lastError
    }

    /// Moves packets from the system into the tunnel.
    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            let (session, running) = self.lock.withLock { (self.session, self.running) }
            guard running, let session else { return }
            for packet in packets {
                // Packets the tunnel does not carry are dropped.
                try? session.send(packet)
            }
            self.readPackets()
        }
    }

    /// Moves packets from the tunnel to the system, and reconnects when the
    /// tunnel drops.
    private func startReceiving() {
        let thread = Thread { [weak self] in
            while let self {
                let (session, running) = self.lock.withLock { (self.session, self.running) }
                guard running, let session else { return }
                do {
                    guard let packet = try session.receive(timeout: 1) else { continue }
                    let family = packet.first.map { $0 >> 4 } == 6 ? AF_INET6 : AF_INET
                    self.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: family)])
                } catch PortaError.retryable {
                    self.reconnect()
                    return
                } catch {
                    self.cancelTunnelWithError(error)
                    return
                }
            }
        }
        thread.name = "dev.porta.tunnel.receive"
        thread.start()
    }

    private func reconnect() {
        reasserting = true
        connectQueue.async {
            var delay: TimeInterval = 0.25
            while self.lock.withLock({ self.running }) {
                do {
                    let connected = try self.connect()
                    let settings = TunnelSettings.make(info: connected.session.info, remoteAddress: connected.remoteAddress)
                    self.setTunnelNetworkSettings(settings) { _ in
                        self.lock.withLock { self.session = connected.session }
                        self.reasserting = false
                        self.startReceiving()
                    }
                    return
                } catch PortaError.retryable {
                    Thread.sleep(forTimeInterval: delay)
                    delay = min(delay * 2, 30)
                } catch {
                    self.cancelTunnelWithError(error)
                    return
                }
            }
        }
    }

    /// The account token the app stored in the keychain.
    static func token(reference: Data?) throws -> String {
        guard let reference else {
            throw PortaError.permanent("the VPN configuration has no token")
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecValuePersistentRef as String: reference,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let token = String(data: data, encoding: .utf8)
        else {
            throw PortaError.permanent("cannot read the account token from the keychain")
        }
        return token
    }

    static func deviceName() -> String {
        #if os(macOS)
        return Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        #else
        return ProcessInfo.processInfo.hostName
        #endif
    }

    /// A numeric address of `host`, IPv4 first.
    static func resolve(host: String) -> String? {
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_DGRAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return nil }
        defer { freeaddrinfo(first) }
        var addresses: [(Int32, String)] = []
        var entry: UnsafeMutablePointer<addrinfo>? = first
        while let current = entry {
            var name = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(current.pointee.ai_addr, current.pointee.ai_addrlen, &name, socklen_t(name.count), nil, 0, NI_NUMERICHOST) == 0 {
                addresses.append((current.pointee.ai_family, String(cString: name)))
            }
            entry = current.pointee.ai_next
        }
        return addresses.first(where: { $0.0 == AF_INET })?.1 ?? addresses.first?.1
    }
}
