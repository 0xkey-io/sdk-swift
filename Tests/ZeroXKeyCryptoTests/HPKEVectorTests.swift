import CryptoKit
import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyTestSupport

private struct HPKEFixture: Decodable {
    struct Case: Decodable {
        let label: String
        let plaintextHex: String
        let ephemeralPrivateKey: String
        let sealedHex: String
        let formatted: String
        let legacySealedHex: String
    }
    struct Random: Decodable { let plaintext: String; let sealedHex: String }
    let _meta: FixtureMeta
    let receiver: KeyPairFixture
    let cases: [Case]
    let randomEncrypt: Random
}

private func bytes(_ hex: String) -> Data { hex.isEmpty ? Data() : try! Hex.decode(hex) }

@Suite("HPKE vectors (sdk-js hpkeEncrypt/hpkeDecrypt, info 0xkey_hpke)")
struct HPKEVectorTests {
    private let f: HPKEFixture = try! Fixtures.load("hpke")

    @Test func encryptMatchesSdkJsByteForByte() throws {
        #expect(f.cases.count == 5)
        for c in f.cases {
            let eph = try P256.KeyAgreement.PrivateKey(rawRepresentation: Hex.decode(c.ephemeralPrivateKey))
            let sealed = try ZeroXKeyHPKE.encrypt(
                plaintext: bytes(c.plaintextHex), recipientPublicKey: Hex.decode(f.receiver.publicKeyUncompressed),
                ephemeralPrivateKey: eph, info: Data("0xkey_hpke".utf8))
            #expect(Hex.encode(sealed) == c.sealedHex, "case \(c.label)")
            #expect(try ZeroXKeyHPKE.formatBundle(sealed) == c.formatted, "case \(c.label)")
        }
    }

    @Test func compressedRecipientKeyGivesSameOutput() throws {
        let c = f.cases[1]
        let eph = try P256.KeyAgreement.PrivateKey(rawRepresentation: Hex.decode(c.ephemeralPrivateKey))
        let sealed = try ZeroXKeyHPKE.encrypt(
            plaintext: bytes(c.plaintextHex), recipientPublicKey: Hex.decode(f.receiver.publicKey),
            ephemeralPrivateKey: eph, info: Data("0xkey_hpke".utf8))
        #expect(Hex.encode(sealed) == c.sealedHex)
    }

    @Test func decryptSdkJsCiphertext() throws {
        let priv = try Hex.decode(f.receiver.privateKey)
        for c in f.cases {
            #expect(try ZeroXKeyHPKE.decrypt(sealed: Hex.decode(c.sealedHex), recipientPrivateKey: priv) == bytes(c.plaintextHex))
        }
        let random = try ZeroXKeyHPKE.decrypt(sealed: Hex.decode(f.randomEncrypt.sealedHex), recipientPrivateKey: priv)
        #expect(String(decoding: random, as: UTF8.self) == f.randomEncrypt.plaintext)
    }

    /// Independent oracle: CryptoKit's own RFC 9180 implementation with the same suite,
    /// info and AAD must open what ZeroXKeyHPKE seals (and vice versa).
    @Test func interoperatesWithCryptoKitHPKE() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let pkR = recipient.publicKey.x963Representation
        let message = Data("cryptokit oracle".utf8)
        let sealed = try ZeroXKeyHPKE.encrypt(plaintext: message, recipientPublicKey: pkR)
        let enc = try P256PublicKeyCodec.uncompress(sealed.prefix(33))
        var receiver = try HPKE.Recipient(
            privateKey: recipient, ciphersuite: .P256_SHA256_AES_GCM_256,
            info: Data("0xkey_hpke".utf8), encapsulatedKey: enc)
        #expect(try receiver.open(sealed.dropFirst(33), authenticating: enc + pkR) == message)

        var sender = try HPKE.Sender(recipientKey: recipient.publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: Data("0xkey_hpke".utf8))
        let ct = try sender.seal(message, authenticating: sender.encapsulatedKey + pkR)
        let opened = try ZeroXKeyHPKE.decrypt(ciphertext: ct, encappedPublicKey: sender.encapsulatedKey, recipientPrivateKey: recipient.rawRepresentation)
        #expect(opened == message)
    }

    // MARK: negative

    @Test func legacyUpstreamScheduleCiphertextIsRejected() throws {
        let priv = try Hex.decode(f.receiver.privateKey)
        for c in f.cases {
            #expect(c.legacySealedHex != c.sealedHex)
            #expect(throws: ZeroXKeyCryptoError.hpkeDecryptionFailed) {
                try ZeroXKeyHPKE.decrypt(sealed: Hex.decode(c.legacySealedHex), recipientPrivateKey: priv)
            }
        }
    }

    @Test func wrongInfoFails() throws {
        let c = f.cases[2]
        let sealed = try Hex.decode(c.sealedHex)
        #expect(throws: ZeroXKeyCryptoError.hpkeDecryptionFailed) {
            try ZeroXKeyHPKE.decrypt(
                ciphertext: sealed.dropFirst(33), encappedPublicKey: sealed.prefix(33),
                recipientPrivateKey: Hex.decode(f.receiver.privateKey), info: Data("wrong_hpke_info".utf8))
        }
    }

    @Test func tamperedCiphertextFails() throws {
        let priv = try Hex.decode(f.receiver.privateKey)
        var sealed = try Hex.decode(f.cases[3].sealedHex)
        sealed[40] ^= 0x01
        #expect(throws: ZeroXKeyCryptoError.hpkeDecryptionFailed) { try ZeroXKeyHPKE.decrypt(sealed: sealed, recipientPrivateKey: priv) }
        var tag = try Hex.decode(f.cases[3].sealedHex)
        tag[tag.count - 1] ^= 0x80
        #expect(throws: ZeroXKeyCryptoError.hpkeDecryptionFailed) { try ZeroXKeyHPKE.decrypt(sealed: tag, recipientPrivateKey: priv) }
    }

    @Test func wrongRecipientFails() throws {
        let other = generateP256KeyPair()
        #expect(throws: ZeroXKeyCryptoError.hpkeDecryptionFailed) {
            try ZeroXKeyHPKE.decrypt(sealed: Hex.decode(f.cases[1].sealedHex), recipientPrivateKey: Hex.decode(other.privateKey))
        }
    }
}
