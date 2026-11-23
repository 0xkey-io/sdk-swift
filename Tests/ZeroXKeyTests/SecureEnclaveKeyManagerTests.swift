import CryptoKit
import Foundation
import Testing
import ZeroXKey
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyStamper

/// In-memory `KeyBlobStore`: `swift test` hosts have no data-protection keychain.
private final class MemoryBlobStore: KeyBlobStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    func set(_ data: Data, account: String) throws { lock.withLock { items[account] = data } }
    func get(account: String) throws -> Data? { lock.withLock { items[account] } }
    func list() throws -> [String] { lock.withLock { items.keys.sorted() } }
    func delete(account: String) throws { lock.withLock { items[account] = nil } }
}

private let payload = #"{"type":"ACTIVITY_TYPE_TEST","timestampMs":"1763500000000","organizationId":"org","parameters":{}}"#

/// Builds a manager over fresh in-memory stores.
private func makeManager(hardware: Bool) -> SecureEnclaveKeyManager {
    SecureEnclaveKeyManager(blobStore: MemoryBlobStore(), softwareStore: MemoryBlobStore(), hardwareAvailable: hardware)
}

/// Creates a key with the host's best backend. When the Secure Enclave reports itself available
/// but key creation fails (e.g. a test host without the needed entitlements), that environment is
/// treated as not supporting hardware keys and a software-mode manager is used instead.
private func createDefaultKey() throws -> (manager: SecureEnclaveKeyManager, publicKey: String, hardware: Bool) {
    if SecureEnclave.isAvailable {
        let m = makeManager(hardware: true)
        do {
            let pub = try m.createKeyPair()
            return (m, pub, true)
        } catch {
            print("[SecureEnclaveKeyManagerTests] SE key creation failed (\(error)); using software fallback")
        }
    }
    let m = makeManager(hardware: false)
    return (m, try m.createKeyPair(), false)
}

/// Independent check of a DER hex signature over `message` (no code from the manager involved).
private func verifies(publicKey: String, derHex: String, message: String) throws -> Bool {
    try P256Signer.verifyDER(signature: Hex.decode(derHex), message: Data(message.utf8), publicKey: Hex.decode(publicKey))
}

@Suite("SecureEnclaveKeyManager")
struct SecureEnclaveKeyManagerTests {
    @Test func defaultBackendCreatesKeyAndStampsVerifiably() throws {
        let (m, pub, hardware) = try createDefaultKey()
        print("[SecureEnclaveKeyManagerTests] default backend: \(hardware ? "hardware (Secure Enclave)" : "software fallback")")

        // Compressed P-256 public key hex: 33 bytes, 02/03 prefix.
        #expect(pub.count == 66)
        #expect(pub.hasPrefix("02") || pub.hasPrefix("03"))
        #expect(try m.listPublicKeys() == [pub])
        #expect(m.isHardwareBacked(publicKey: pub) == hardware)
        let exported = try m.privateKey(forPublicKey: pub)
        if hardware {
            #expect(exported == nil)
        } else {
            #expect(exported?.count == 64)
        }

        let stamper = try m.stamper(forPublicKey: pub)
        #expect(stamper.apiPublicKey == pub)

        // Stamp header: base64url JSON { publicKey, scheme, signature(DER hex) }.
        let stamp = try stamper.stampSync(payload: payload)
        #expect(stamp.stampHeaderName == "X-Stamp")
        let json = try #require(
            JSONSerialization.jsonObject(with: Base64URL.decode(stamp.stampHeaderValue)) as? [String: String])
        #expect(json["publicKey"] == pub)
        #expect(json["scheme"] == "SIGNATURE_SCHEME_TK_API_P256")
        let derHex = try #require(json["signature"])
        #expect(try verifyStampSignature(publicKey: pub, signature: derHex, signedData: payload))
        #expect(try verifies(publicKey: pub, derHex: derHex, message: payload))

        // Low-S: ECDSA signatures are randomized, so sample several.
        for i in 0..<8 {
            let message = payload + String(i)
            let der = try stamper.sign(payload: message, format: .der)
            let raw = try stamper.sign(payload: message, format: .raw)
            #expect(try verifies(publicKey: pub, derHex: der, message: message))
            let rawBytes = try Hex.decode(raw)
            #expect(rawBytes.count == 64)
            #expect(ECDSASignatureCodec.isLowS(rawBytes))
            // raw and DER are encodings of valid signatures over the same message.
            let sig = try P256.Signing.ECDSASignature(rawRepresentation: rawBytes)
            let verifier = try P256.Signing.PublicKey(compressedRepresentation: Hex.decode(pub))
            #expect(verifier.isValidSignature(sig, for: Data(message.utf8)))
        }
    }

    @Test func tamperedPayloadFailsVerification() throws {
        let (m, pub, _) = try createDefaultKey()
        let stamper = try m.stamper(forPublicKey: pub)
        let der = try stamper.sign(payload: payload, format: .der)
        #expect(try verifies(publicKey: pub, derHex: der, message: payload))
        #expect(try !verifies(publicKey: pub, derHex: der, message: payload + " "))
        #expect(try !verifyStampSignature(publicKey: pub, signature: der, signedData: payload.replacingOccurrences(of: "org", with: "ogr")))
        // Signature from one key does not verify under another.
        let other = P256.Signing.PrivateKey().publicKey.compressedRepresentation
        #expect(try !P256Signer.verifyDER(signature: Hex.decode(der), message: Data(payload.utf8), publicKey: other))
    }

    @Test func forcedSoftwareModeFallsBack() throws {
        let m = makeManager(hardware: false)
        let pub = try m.createKeyPair()
        #expect(!m.isHardwareBacked(publicKey: pub))

        let priv = try #require(try m.privateKey(forPublicKey: pub))
        #expect(priv.count == 64)
        // The exported scalar really is the key behind `pub` (derived by CryptoKit directly).
        let derived = try P256.Signing.PrivateKey(rawRepresentation: Hex.decode(priv))
        #expect(Hex.encode(derived.publicKey.compressedRepresentation) == pub)

        let stamper = try m.stamper(forPublicKey: pub)
        for i in 0..<8 {
            let message = payload + String(i)
            let der = try stamper.sign(payload: message, format: .der)
            #expect(try verifies(publicKey: pub, derHex: der, message: message))
            #expect(ECDSASignatureCodec.isLowS(try Hex.decode(stamper.sign(payload: message, format: .raw))))
        }
        let stamp = try stamper.stampSync(payload: payload)
        let json = try #require(
            JSONSerialization.jsonObject(with: Base64URL.decode(stamp.stampHeaderValue)) as? [String: String])
        #expect(try verifyStampSignature(publicKey: pub, signature: #require(json["signature"]), signedData: payload))
    }

    @Test func importedSoftwareKeyCoexistsWithSecureEnclaveKey() throws {
        let hardwareWanted = SecureEnclave.isAvailable
        var m = makeManager(hardware: hardwareWanted)
        var seKey: String
        var seIsHardware = hardwareWanted
        do {
            seKey = try m.createKeyPair()
        } catch {
            // Environment cannot create SE keys: exercise the same coexistence over the software path.
            m = makeManager(hardware: false)
            seKey = try m.createKeyPair()
            seIsHardware = false
        }
        print("[SecureEnclaveKeyManagerTests] coexistence test ran on: \(seIsHardware ? "hardware (Secure Enclave)" : "software fallback")")

        // Import a software key from a raw CryptoKit scalar (bootstrap-key scenario).
        let imported = P256.Signing.PrivateKey()
        let importedPub = Hex.encode(imported.publicKey.compressedRepresentation)
        let returned = try m.importPrivateKey(Hex.encode(imported.rawRepresentation))
        #expect(returned == importedPub)

        #expect(try m.listPublicKeys() == [seKey, importedPub].sorted())
        #expect(m.isHardwareBacked(publicKey: seKey) == seIsHardware)
        #expect(!m.isHardwareBacked(publicKey: importedPub))
        #expect(try m.privateKey(forPublicKey: importedPub) == Hex.encode(imported.rawRepresentation))
        if seIsHardware { #expect(try m.privateKey(forPublicKey: seKey) == nil) }

        // Both backends are consulted by stamper(forPublicKey:).
        for pub in [seKey, importedPub] {
            let der = try m.stamper(forPublicKey: pub).sign(payload: payload, format: .der)
            #expect(try verifies(publicKey: pub, derHex: der, message: payload))
        }

        // Delete the software key: SE key stays.
        try m.deleteKeyPair(publicKey: importedPub)
        #expect(try m.listPublicKeys() == [seKey])
        #expect(throws: ZeroXKeyError.keyPairNotFound(publicKey: importedPub)) { try m.stamper(forPublicKey: importedPub) }
        _ = try m.stamper(forPublicKey: seKey)

        // Re-import, then delete the SE key: software key stays.
        _ = try m.importPrivateKey(Hex.encode(imported.rawRepresentation))
        try m.deleteKeyPair(publicKey: seKey)
        #expect(try m.listPublicKeys() == [importedPub])
        #expect(!m.isHardwareBacked(publicKey: seKey))
        #expect(throws: ZeroXKeyError.keyPairNotFound(publicKey: seKey)) { try m.stamper(forPublicKey: seKey) }
        _ = try m.stamper(forPublicKey: importedPub)

        try m.deleteKeyPair(publicKey: importedPub)
        #expect(try m.listPublicKeys().isEmpty)
        // Deleting an unknown key is a no-op.
        try m.deleteKeyPair(publicKey: importedPub)
    }

    @Test func listIsSortedAndDeduplicated() throws {
        let blobs = MemoryBlobStore()
        let soft = MemoryBlobStore()
        let m = SecureEnclaveKeyManager(blobStore: blobs, softwareStore: soft, hardwareAvailable: false)
        let keys = try (0..<4).map { _ in try m.createKeyPair() }
        #expect(try m.listPublicKeys() == keys.sorted())
        // The same account in both stores is reported once.
        try blobs.set(Data([1]), account: keys[0])
        #expect(try m.listPublicKeys() == keys.sorted())
        // Importing the same key twice does not duplicate it.
        let priv = try #require(try m.privateKey(forPublicKey: keys[1]))
        _ = try m.importPrivateKey(priv)
        #expect(try m.listPublicKeys().count == 4)
    }

    @Test func unknownPublicKeyThrowsKeyPairNotFound() throws {
        let m = makeManager(hardware: SecureEnclave.isAvailable)
        let unknown = "02" + String(repeating: "ab", count: 32)
        #expect(throws: ZeroXKeyError.keyPairNotFound(publicKey: unknown)) { try m.stamper(forPublicKey: unknown) }
        #expect(try m.privateKey(forPublicKey: unknown) == nil)
        #expect(!m.isHardwareBacked(publicKey: unknown))
        #expect(try m.listPublicKeys().isEmpty)
    }

    @Test func importRejectsInvalidPrivateKey() throws {
        let m = makeManager(hardware: false)
        #expect(throws: (any Error).self) { try m.importPrivateKey("zz") }
        #expect(throws: (any Error).self) { try m.importPrivateKey(String(repeating: "0", count: 64)) }
        #expect(try m.listPublicKeys().isEmpty)
    }

    @Test func customSignerInitializerSignsRawMessageBytes() throws {
        // The public ApiKeyStamper.init(apiPublicKey:signer:) hands the signer the UTF-8 payload bytes.
        let key = P256.Signing.PrivateKey()
        let pub = Hex.encode(key.publicKey.compressedRepresentation)
        let stamper = ApiKeyStamper(apiPublicKey: pub) { message in
            try ECDSASignatureCodec.toDER(ECDSASignatureCodec.normalizeLowS(key.signature(for: message).rawRepresentation))
        }
        let der = try stamper.sign(payload: payload, format: .der)
        #expect(try verifies(publicKey: pub, derHex: der, message: payload))
        #expect(try Hex.decode(stamper.sign(payload: payload, format: .raw)).count == 64)
    }

    @Test func accessPolicyDefaultsToNone() {
        #expect(makeManager(hardware: false).accessPolicy == .none)
        let m = SecureEnclaveKeyManager(
            accessPolicy: .biometryCurrentSet, blobStore: MemoryBlobStore(), softwareStore: MemoryBlobStore(),
            hardwareAvailable: false)
        #expect(m.accessPolicy == .biometryCurrentSet)
    }

    @Test func legacyKeychainKeysStayUsableButAreNeverWritten() throws {
        let legacy = MemoryBlobStore()
        // A key stored by the previous default manager (hex scalar under the public key).
        let old = P256.Signing.PrivateKey()
        let oldPub = Hex.encode(old.publicKey.compressedRepresentation)
        try legacy.set(Data(Hex.encode(old.rawRepresentation).utf8), account: oldPub)
        let soft = MemoryBlobStore()
        let m = SecureEnclaveKeyManager(blobStore: MemoryBlobStore(), softwareStore: soft, legacyStore: legacy, hardwareAvailable: false)

        #expect(try m.listPublicKeys() == [oldPub])
        let stamp = try m.stamper(forPublicKey: oldPub).stampSync(payload: payload)
        let json = try #require(JSONSerialization.jsonObject(with: Base64URL.decode(stamp.stampHeaderValue)) as? [String: String])
        #expect(try verifyStampSignature(publicKey: oldPub, signature: #require(json["signature"]), signedData: payload))

        let fresh = try m.createKeyPair()
        _ = try m.importPrivateKey(Hex.encode(P256.Signing.PrivateKey().rawRepresentation))
        #expect(try legacy.list() == [oldPub])           // nothing new written to the legacy store
        #expect(try soft.list().count == 2 && !(try soft.list().contains(oldPub)))
        #expect(try m.listPublicKeys().contains(fresh))

        try m.deleteKeyPair(publicKey: oldPub)            // logout cleans the legacy key up
        #expect(try legacy.list().isEmpty)
        #expect(throws: ZeroXKeyError.keyPairNotFound(publicKey: oldPub)) { try m.stamper(forPublicKey: oldPub) }
    }

    @Test func legacyFallbackCanBeDisabled() throws {
        let legacy = MemoryBlobStore()
        let old = P256.Signing.PrivateKey()
        let oldPub = Hex.encode(old.publicKey.compressedRepresentation)
        try legacy.set(Data(Hex.encode(old.rawRepresentation).utf8), account: oldPub)
        let m = SecureEnclaveKeyManager(blobStore: MemoryBlobStore(), softwareStore: MemoryBlobStore(), legacyStore: nil, hardwareAvailable: false)
        #expect(try m.listPublicKeys().isEmpty)
        #expect(throws: ZeroXKeyError.keyPairNotFound(publicKey: oldPub)) { try m.stamper(forPublicKey: oldPub) }
        #expect(KeychainKeyManager.defaultService == "io.0xkey.sdk.keys")
    }
}
