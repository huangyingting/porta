import Foundation
import Security

/// Account tokens, in the keychain group the tunnel extension shares. The
/// VPN configuration holds only a persistent reference to the item.
enum TokenStore {
    private static let service = "dev.porta.token"

    /// Stores `token` for `profileID`, replacing any earlier one, and
    /// returns the persistent reference for the VPN configuration.
    static func save(token: String, profileID: String, accessGroup: String?) throws -> Data {
        delete(profileID: profileID, accessGroup: accessGroup)
        var attributes = query(profileID: profileID, accessGroup: accessGroup)
        attributes[kSecValueData as String] = Data(token.utf8)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        attributes[kSecReturnPersistentRef as String] = true
        var reference: CFTypeRef?
        let status = SecItemAdd(attributes as CFDictionary, &reference)
        guard status == errSecSuccess, let data = reference as? Data else {
            throw TokenStoreError(status: status)
        }
        return data
    }

    static func delete(profileID: String, accessGroup: String?) {
        SecItemDelete(query(profileID: profileID, accessGroup: accessGroup) as CFDictionary)
    }

    private static func query(profileID: String, accessGroup: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: profileID,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

struct TokenStoreError: LocalizedError {
    var status: OSStatus

    var errorDescription: String? {
        String(localized: "Could not store the token securely (\(Int(status))).")
    }
}
