import Foundation

/// What the tunnel extension tells the app about a running tunnel, in answer
/// to `TunnelReport.request` sent with `NETunnelProviderSession`'s
/// `sendProviderMessage`.
public struct TunnelReport: Codable, Equatable {
    /// The current session's settings; nil while connecting or reconnecting.
    public var info: SessionInfo?
    /// When the current session connected.
    public var connectedAt: Date?
    /// Bytes from the device into the tunnel and from the tunnel to the
    /// device, since the extension started.
    public var bytesSent: UInt64
    public var bytesReceived: UInt64
    /// The extension's recent events, oldest first.
    public var log: [LogEntry]

    public init(info: SessionInfo? = nil, connectedAt: Date? = nil, bytesSent: UInt64 = 0, bytesReceived: UInt64 = 0, log: [LogEntry] = []) {
        self.info = info
        self.connectedAt = connectedAt
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.log = log
    }

    /// The message that asks the extension for a report.
    public static let request = Data("report".utf8)

    public func encoded() -> Data {
        (try? JSONEncoder.porta.encode(self)) ?? Data()
    }

    public static func decode(_ data: Data) -> TunnelReport? {
        try? JSONDecoder.porta.decode(TunnelReport.self, from: data)
    }
}

/// One line of a connection log.
public struct LogEntry: Codable, Equatable, Identifiable {
    public var id: UUID
    public var time: Date
    public var message: String

    public init(time: Date = Date(), message: String) {
        self.id = UUID()
        self.time = time
        self.message = message
    }
}

/// A bounded log, newest last. Tokens and authorization headers never go in.
public struct EventLog: Equatable {
    public private(set) var entries: [LogEntry] = []
    public let capacity: Int

    public init(capacity: Int = 200) {
        self.capacity = capacity
    }

    public mutating func append(_ message: String, at time: Date = Date()) {
        entries.append(LogEntry(time: time, message: message))
        if entries.count > capacity {
            entries.removeFirst(entries.count - capacity)
        }
    }

    public mutating func removeAll() {
        entries.removeAll()
    }
}

extension JSONEncoder {
    static let porta: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return encoder
    }()
}

extension JSONDecoder {
    static let porta: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }()
}
