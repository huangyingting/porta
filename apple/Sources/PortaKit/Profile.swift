import Foundation

/// A gateway profile imported from the `porta://profile` setup link that
/// the download page shows as a QR code (see docs/endpoints.md).
public struct Profile: Equatable {
    public var server: String
    public var token: String
    public var name: String?

    public init(server: String, token: String, name: String? = nil) {
        self.server = server
        self.token = token
        self.name = name
    }

    /// Parses a setup link, rejecting anything the Android app rejects.
    public init(setupLink: String) throws {
        func invalid(_ reason: String) -> PortaError {
            .permanent("invalid setup link: \(reason)")
        }
        guard setupLink.utf8.count <= 2048 else { throw invalid("too long") }
        guard setupLink == setupLink.trimmingCharacters(in: .whitespacesAndNewlines),
              !setupLink.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { throw invalid("surrounding whitespace or control characters") }
        let prefix = "porta://profile?"
        guard setupLink.hasPrefix(prefix) else { throw invalid("not a Porta profile") }
        var fields: [String: String] = [:]
        for pair in setupLink.dropFirst(prefix.count).split(separator: "&", omittingEmptySubsequences: false) {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let key = Profile.formDecode(String(parts[0])),
                  let value = Profile.formDecode(String(parts[1]))
            else { throw invalid("malformed encoding") }
            guard ["v", "server", "token", "name"].contains(key) else { throw invalid("unknown field \(key)") }
            guard fields[key] == nil else { throw invalid("duplicate field \(key)") }
            fields[key] = value
        }
        guard fields["v"] == "1" else { throw invalid("unsupported version") }
        guard let server = fields["server"], let token = fields["token"] else {
            throw invalid("server and token are required")
        }
        guard server.utf8.count <= 512, Profile.isHTTPSOrigin(server) else {
            throw invalid("the server must be an HTTPS origin")
        }
        guard !token.isEmpty, token.utf8.count <= 512,
              token.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7F })
        else { throw invalid("the token must be printable ASCII") }
        if let name = fields["name"], name.utf8.count > 80 {
            throw invalid("the name is too long")
        }
        self.init(server: server, token: token, name: fields["name"])
    }

    /// Form decoding: `+` is a space, then percent escapes.
    static func formDecode(_ value: String) -> String? {
        value.replacingOccurrences(of: "+", with: " ").removingPercentEncoding
    }

    public static func isHTTPSOrigin(_ value: String) -> Bool {
        guard let components = URLComponents(string: value),
              components.scheme == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.path.isEmpty || components.path == "/"
        else { return false }
        if let port = components.port, !(1 ... 65535).contains(port) {
            return false
        }
        return true
    }
}
