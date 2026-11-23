import CryptoKit
import Foundation
import Security
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyStamper

/// Extra user-verification requirement attached to a Secure Enclave key, on top of the
/// always-present `.privateKeyUsage` flag and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
///
/// With anything other than `.none`, every signature (i.e. every stamped request) prompts
/// the user, so choose deliberately for session keys.
public enum SecureEnclaveAccessPolicy: Sendable, Equatable {
    /// No additional authentication (default): the key is usable while the device is unlocked.
    case none
    /// `.userPresence`: biometry or device passcode.
    case userPresence
    /// `.biometryAny`: any enrolled biometry (survives enrollment changes).
    case biometryAny
    /// `.biometryCurrentSet`: the currently enrolled biometry only; invalidated when it changes.
    case biometryCurrentSet

    fileprivate var flags: SecAccessControlCreateFlags {
        switch self {
        case .none: return [.privateKeyUsage]
        case .userPresence: return [.privateKeyUsage, .userPresence]
        case .biometryAny: return [.privateKeyUsage, .biometryAny]
        case .biometryCurrentSet: return [.privateKeyUsage, .biometryCurrentSet]
        }
    }
}

/// Persistence for opaque key blobs, indexed by account (compressed public key hex).
/// Injectable so tests can run on hosts without a data-protection keychain
/// (`swift test` binaries lack the keychain entitlement).
package protocol KeyBlobStore: Sendable {
    func set(_ data: Data, account: String) throws
    func get(account: String) throws -> Data?
    func list() throws -> [String]
    func delete(account: String) throws
}

/// Default `KeyBlobStore`: generic-password Keychain items scoped by `service`.
package struct KeychainBlobStore: KeyBlobStore {
    package let service: String
    package let accessGroup: String?

    package init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    package func set(_ data: Data, account: String) throws {
        try Keychain.set(data, service: service, account: account, accessGroup: accessGroup)
    }

    package func get(account: String) throws -> Data? {
        try Keychain.get(service: service, account: account, accessGroup: accessGroup)
    }

    package func list() throws -> [String] {
        try Keychain.accounts(service: service, accessGroup: accessGroup)
    }

    package func delete(account: String) throws {
        try Keychain.delete(service: service, account: account, accessGroup: accessGroup)
    }
}

/// Session key storage backed by the Secure Enclave where available.
///
/// - `createKeyPair()` generates a P-256 key inside the Secure Enclave when
///   `SecureEnclave.isAvailable` (and hardware use was not disabled); the private scalar never
///   leaves the chip. Only the encrypted `dataRepresentation` blob is persisted, which is
///   useless on any other device. Where the Secure Enclave is unavailable (simulator, Intel Macs
///   without T2) it falls back to a software key stored like `KeychainKeyManager` does.
///   Failures of an *available* Secure Enclave are propagated, never silently downgraded.
/// - `importPrivateKey(_:)` always stores a software key (the Secure Enclave cannot import
///   external keys). Used for short-lived bootstrap keys such as the passkey registration key.
/// - `stamper(forPublicKey:)` looks in **both** backends: Secure Enclave blobs first, then
///   software keys. SE signatures are `ECDSA-SHA256`, converted to low-S DER, identical in
///   shape to `P256Signer.signDER`.
/// - `privateKey(forPublicKey:)` returns `nil` for Secure Enclave keys (non-exportable) and the
///   hex scalar for software keys.
///
/// Keychain layout (distinct services so the two backends never shadow each other, and so this
/// manager does not collide with a `KeychainKeyManager` using its default service):
/// - Secure Enclave blobs: `io.0xkey.sdk.se-keys`
/// - Software keys: `io.0xkey.sdk.se-soft-keys`
///
/// Migration: keys created by `KeychainKeyManager` (the default before this manager, service
/// `io.0xkey.sdk.keys`) are still found for signing, listing and deletion, so sessions stored
/// before the switch keep working. That legacy store is never written to. Pass
/// `legacyKeychainService: nil` to turn this off, or your own service name if you used one.
public struct SecureEnclaveKeyManager: ZeroXKeyKeyManager {
    public static let secureEnclaveService = "io.0xkey.sdk.se-keys"
    public static let softwareService = "io.0xkey.sdk.se-soft-keys"

    public let accessPolicy: SecureEnclaveAccessPolicy

    private let blobStore: any KeyBlobStore
    private let softwareStore: any KeyBlobStore
    private let hardwareAvailable: Bool
    /// Read-only (plus delete) fallback for keys of the previous default manager.
    private let legacyStore: (any KeyBlobStore)?

    /// - Parameters:
    ///   - accessPolicy: extra authentication required to use newly created SE keys.
    ///   - accessGroup: optional Keychain access group for all stores.
    ///   - legacyKeychainService: `KeychainKeyManager` service whose keys are still used
    ///     (read and delete only); `nil` disables the fallback.
    public init(accessPolicy: SecureEnclaveAccessPolicy = .none, accessGroup: String? = nil,
                legacyKeychainService: String? = KeychainKeyManager.defaultService) {
        self.init(
            accessPolicy: accessPolicy,
            blobStore: KeychainBlobStore(service: Self.secureEnclaveService, accessGroup: accessGroup),
            softwareStore: KeychainBlobStore(service: Self.softwareService, accessGroup: accessGroup),
            legacyStore: legacyKeychainService.map { KeychainBlobStore(service: $0, accessGroup: accessGroup) },
            hardwareAvailable: SecureEnclave.isAvailable)
    }

    /// Injects the persistence layers and forces hardware availability (tests).
    package init(
        accessPolicy: SecureEnclaveAccessPolicy = .none,
        blobStore: any KeyBlobStore,
        softwareStore: any KeyBlobStore,
        legacyStore: (any KeyBlobStore)? = nil,
        hardwareAvailable: Bool = SecureEnclave.isAvailable
    ) {
        self.accessPolicy = accessPolicy
        self.blobStore = blobStore
        self.softwareStore = softwareStore
        self.legacyStore = legacyStore
        self.hardwareAvailable = hardwareAvailable
    }

    // MARK: ZeroXKeyKeyManager

    public func createKeyPair() throws -> String {
        guard hardwareAvailable else {
            return try importPrivateKey(generateP256KeyPair().privateKey)
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: makeAccessControl())
        let publicKey = Hex.encode(key.publicKey.compressedRepresentation)
        try blobStore.set(key.dataRepresentation, account: publicKey)
        return publicKey
    }

    public func importPrivateKey(_ privateKeyHex: String) throws -> String {
        let pair = try P256KeyPair(privateKey: privateKeyHex)
        try softwareStore.set(Data(pair.privateKey.utf8), account: pair.publicKey)
        return pair.publicKey
    }

    public func privateKey(forPublicKey publicKey: String) throws -> String? {
        let data = try softwareStore.get(account: publicKey) ?? legacyStore?.get(account: publicKey)
        return data.map { String(decoding: $0, as: UTF8.self) }
    }

    public func listPublicKeys() throws -> [String] {
        Array(Set(try blobStore.list()).union(try softwareStore.list()).union(try legacyStore?.list() ?? [])).sorted()
    }

    public func deleteKeyPair(publicKey: String) throws {
        try blobStore.delete(account: publicKey)
        try softwareStore.delete(account: publicKey)
        try legacyStore?.delete(account: publicKey)
    }

    public func stamper(forPublicKey publicKey: String) throws -> ApiKeyStamper {
        if let blob = try blobStore.get(account: publicKey) {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
            let derived = Hex.encode(key.publicKey.compressedRepresentation)
            guard derived == publicKey else {
                throw ZeroXKeyStamperError.publicKeyMismatch(expected: publicKey, derived: derived)
            }
            return ApiKeyStamper(apiPublicKey: publicKey) { message in
                // CryptoKit hashes with SHA-256 internally; SE output is not low-S normalized.
                let raw = try key.signature(for: message).rawRepresentation
                return try ECDSASignatureCodec.toDER(ECDSASignatureCodec.normalizeLowS(raw))
            }
        }
        guard let priv = try privateKey(forPublicKey: publicKey) else {
            throw ZeroXKeyError.keyPairNotFound(publicKey: publicKey)
        }
        return try ApiKeyStamper(apiPublicKey: publicKey, apiPrivateKey: priv)
    }

    // MARK: Hardware backing

    /// Whether `publicKey` is held in the Secure Enclave (as opposed to a software key or unknown).
    /// Store errors are reported as `false`.
    public func isHardwareBacked(publicKey: String) -> Bool {
        ((try? blobStore.get(account: publicKey)) ?? nil) != nil
    }

    // MARK: Helpers

    private func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, accessPolicy.flags, &error)
        else {
            let status = (error?.takeRetainedValue()).map { Int32(CFErrorGetCode($0)) } ?? errSecParam
            throw ZeroXKeyError.keychain(status: status)
        }
        return control
    }
}
