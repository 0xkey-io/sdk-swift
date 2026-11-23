import Foundation
import Security
import ZeroXKeyCrypto
import ZeroXKeyStamper

/// Storage for session API key pairs (P-256), indexed by compressed public key hex.
/// sdk-js counterpart: the api-key stamper's key storage (`createKeyPair`,
/// `listKeyPairs`, `deleteKeyPair`).
public protocol ZeroXKeyKeyManager: Sendable {
    /// Generates and stores a key pair; returns the compressed public key hex.
    func createKeyPair() throws -> String
    /// Stores an externally generated private key (hex); returns its compressed public key.
    func importPrivateKey(_ privateKeyHex: String) throws -> String
    func privateKey(forPublicKey publicKey: String) throws -> String?
    func listPublicKeys() throws -> [String]
    func deleteKeyPair(publicKey: String) throws
    /// API key stamper for a stored key pair. Throws `ZeroXKeyError.keyPairNotFound`
    /// when the key is unknown. Implementations whose keys cannot be exported
    /// (Secure Enclave) override this; the default builds the stamper from
    /// `privateKey(forPublicKey:)`.
    func stamper(forPublicKey publicKey: String) throws -> ApiKeyStamper
}

extension ZeroXKeyKeyManager {
    /// Default: software stamper from the exported private key.
    public func stamper(forPublicKey publicKey: String) throws -> ApiKeyStamper {
        guard let priv = try privateKey(forPublicKey: publicKey) else {
            throw ZeroXKeyError.keyPairNotFound(publicKey: publicKey)
        }
        return try ApiKeyStamper(apiPublicKey: publicKey, apiPrivateKey: priv)
    }
}

/// Process-local key storage. Used by tests and by apps that do not persist sessions.
public final class InMemoryKeyManager: ZeroXKeyKeyManager, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: String] = [:]
    private var order: [String] = []

    public init() {}

    public func createKeyPair() throws -> String {
        try importPrivateKey(generateP256KeyPair().privateKey)
    }

    public func importPrivateKey(_ privateKeyHex: String) throws -> String {
        let pair = try P256KeyPair(privateKey: privateKeyHex)
        lock.withLock {
            if keys[pair.publicKey] == nil { order.append(pair.publicKey) }
            keys[pair.publicKey] = pair.privateKey
        }
        return pair.publicKey
    }

    public func privateKey(forPublicKey publicKey: String) throws -> String? {
        lock.withLock { keys[publicKey] }
    }

    public func listPublicKeys() throws -> [String] {
        lock.withLock { order }
    }

    public func deleteKeyPair(publicKey: String) throws {
        lock.withLock {
            keys[publicKey] = nil
            order.removeAll { $0 == publicKey }
        }
    }
}

/// Keychain-backed key storage (`kSecClassGenericPassword`, this device only,
/// accessible after first unlock). Items are scoped by `service`.
public struct KeychainKeyManager: ZeroXKeyKeyManager {
    public let service: String
    public let accessGroup: String?

    /// Keychain service used when none is given.
    public static let defaultService = "io.0xkey.sdk.keys"

    public init(service: String = KeychainKeyManager.defaultService, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func createKeyPair() throws -> String {
        try importPrivateKey(generateP256KeyPair().privateKey)
    }

    public func importPrivateKey(_ privateKeyHex: String) throws -> String {
        let pair = try P256KeyPair(privateKey: privateKeyHex)
        try Keychain.set(Data(pair.privateKey.utf8), service: service, account: pair.publicKey, accessGroup: accessGroup)
        return pair.publicKey
    }

    public func privateKey(forPublicKey publicKey: String) throws -> String? {
        try Keychain.get(service: service, account: publicKey, accessGroup: accessGroup).map { String(decoding: $0, as: UTF8.self) }
    }

    public func listPublicKeys() throws -> [String] {
        try Keychain.accounts(service: service, accessGroup: accessGroup)
    }

    public func deleteKeyPair(publicKey: String) throws {
        try Keychain.delete(service: service, account: publicKey, accessGroup: accessGroup)
    }
}

/// Minimal generic-password Keychain wrapper.
enum Keychain {
    static func base(service: String, account: String?, accessGroup: String?) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    static func set(_ data: Data, service: String, account: String, accessGroup: String?) throws {
        let query = base(service: service, account: account, accessGroup: accessGroup)
        let update: [String: Any] = [kSecValueData as String: data]
        var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw ZeroXKeyError.keychain(status: status) }
    }

    static func get(service: String, account: String, accessGroup: String?) throws -> Data? {
        var query = base(service: service, account: account, accessGroup: accessGroup)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw ZeroXKeyError.keychain(status: status) }
        return out as? Data
    }

    static func accounts(service: String, accessGroup: String?) throws -> [String] {
        var query = base(service: service, account: nil, accessGroup: accessGroup)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw ZeroXKeyError.keychain(status: status) }
        let items = out as? [[String: Any]] ?? []
        return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }

    static func delete(service: String, account: String?, accessGroup: String?) throws {
        let status = SecItemDelete(base(service: service, account: account, accessGroup: accessGroup) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ZeroXKeyError.keychain(status: status) }
    }
}
