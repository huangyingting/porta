import CPorta
import Foundation
import Security

/// Why a tunnel call failed, and whether reconnecting can help.
public enum PortaError: Error, Equatable, CustomStringConvertible {
    /// Reconnecting may succeed, for example after a network change.
    case retryable(String)
    /// Reconnecting with the same settings fails again.
    case permanent(String)
    /// The gateway refused the account or device: `code` is
    /// `account-expired`, `quota-exceeded`, `device-pending`,
    /// `enrollment-closed` or `device-denied`.
    case denied(code: String, message: String)

    public var description: String {
        switch self {
        case let .retryable(message), let .permanent(message): return message
        case let .denied(_, message): return message
        }
    }

    init(status: Int32, message: String) {
        switch status {
        case PORTA_RETRYABLE:
            self = .retryable(message)
        case PORTA_DENIED:
            // "account-denied:CODE: message"
            let parts = message.split(separator: ":", maxSplits: 2).map(String.init)
            if parts.count == 3, parts[0] == "account-denied" {
                self = .denied(code: parts[1], message: parts[2].trimmingCharacters(in: .whitespaces))
            } else {
                self = .denied(code: "", message: message)
            }
        default:
            self = .permanent(message)
        }
    }
}

let errorCapacity = 512

/// Calls `body` with a C error buffer and returns its text.
func withErrorBuffer<T>(_ body: (UnsafeMutablePointer<CChar>, Int) -> T) -> (T, String) {
    var buffer = [CChar](repeating: 0, count: errorCapacity)
    let result = buffer.withUnsafeMutableBufferPointer { pointer in
        body(pointer.baseAddress!, errorCapacity)
    }
    let message = buffer.withUnsafeBufferPointer { pointer in
        String(cString: pointer.baseAddress!)
    }
    return (result, message)
}

/// The device's key, which proves the device to the gateway. On devices with
/// a Secure Enclave the private key never leaves it; elsewhere (the iOS
/// simulator, Macs without one) it is a keychain key.
public final class DeviceIdentity {
    let handle: OpaquePointer
    /// Passed to the signing callback; kept alive as long as the identity
    /// and, through `TunnelSession`, its sessions.
    let signer: Signer

    final class Signer {
        let key: SecKey

        init(key: SecKey) {
            self.key = key
        }
    }

    /// The immutable device ID (`d-...`) the gateway shows.
    public var deviceID: String {
        String(cString: porta_identity_device_id(handle))
    }

    /// Loads the key tagged `tag` from the keychain, or creates it.
    /// `accessGroup` shares it between the app and its tunnel extension.
    public static func loadOrCreate(tag: String, accessGroup: String?, deviceName: String) throws -> DeviceIdentity {
        let key = try existingKey(tag: tag, accessGroup: accessGroup)
            ?? createKey(tag: tag, accessGroup: accessGroup, secureEnclave: true)
            ?? createKey(tag: tag, accessGroup: accessGroup, secureEnclave: false)
        guard let key else {
            throw PortaError.permanent("could not create the device key")
        }
        return try DeviceIdentity(key: key, deviceName: deviceName)
    }

    init(key: SecKey, deviceName: String) throws {
        guard let publicKey = SecKeyCopyPublicKey(key),
              let point = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else {
            throw PortaError.permanent("could not read the device public key")
        }
        let spki = DeviceIdentity.subjectPublicKeyInfo(point: point)
        let signer = Signer(key: key)
        let context = Unmanaged.passUnretained(signer).toOpaque()
        let (handle, message) = withErrorBuffer { error, capacity in
            spki.withUnsafeBytes { bytes in
                porta_identity_external(
                    bytes.bindMemory(to: UInt8.self).baseAddress,
                    bytes.count,
                    deviceName,
                    signCallback,
                    context,
                    error,
                    capacity
                )
            }
        }
        guard let handle else {
            throw PortaError.permanent(message)
        }
        self.handle = handle
        self.signer = signer
    }

    deinit {
        porta_identity_free(handle)
    }

    /// DER SubjectPublicKeyInfo of an uncompressed P-256 point.
    static func subjectPublicKeyInfo(point: Data) -> Data {
        let prefix: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ]
        return Data(prefix) + point
    }

    private static func query(tag: String, accessGroup: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    private static func existingKey(tag: String, accessGroup: String?) throws -> SecKey? {
        var query = query(tag: tag, accessGroup: accessGroup)
        query[kSecReturnRef as String] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let item else {
            throw PortaError.permanent("could not read the device key (\(status))")
        }
        return (item as! SecKey)
    }

    private static func createKey(tag: String, accessGroup: String?, secureEnclave: Bool) -> SecKey? {
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            secureEnclave ? .privateKeyUsage : [],
            nil
        ) else {
            return nil
        }
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrAccessControl as String: access,
        ]
        if let accessGroup {
            privateAttributes[kSecAttrAccessGroup as String] = accessGroup
        }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]
        if secureEnclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        return SecKeyCreateRandomKey(attributes as CFDictionary, nil)
    }
}

/// Signs device proofs for the Rust tunnel with the identity's key.
private let signCallback: PortaSignCallback = { context, message, length, signature, capacity, written in
    guard let context, let message, let signature, let written else {
        return 1
    }
    let signer = Unmanaged<DeviceIdentity.Signer>.fromOpaque(context).takeUnretainedValue()
    let data = Data(bytes: message, count: length)
    guard let der = SecKeyCreateSignature(
        signer.key,
        .ecdsaSignatureMessageX962SHA256,
        data as CFData,
        nil
    ) as Data?, der.count <= capacity else {
        return 1
    }
    der.copyBytes(to: signature, count: der.count)
    written.pointee = der.count
    return 0
}
