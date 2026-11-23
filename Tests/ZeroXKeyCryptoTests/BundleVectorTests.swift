import CryptoKit
import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyTestSupport

private struct CredentialFixture: Decodable {
    let _meta: FixtureMeta
    let embedded: KeyPairFixture
    let credentialBundle: String
    let expectedDecryptedHex: String
}

private struct ExportFixture: Decodable {
    struct Case: Decodable { let label: String; let bundle: String; let keyFormat: String; let returnMnemonic: Bool; let expected: String }
    struct Negative: Decodable { let label: String; let bundle: String }
    let _meta: FixtureMeta
    let organizationId: String
    let embedded: KeyPairFixture
    let signerPublicKey: String
    let cases: [Case]
    let negatives: [Negative]
}

private struct ImportFixture: Decodable {
    struct Case: Decodable {
        let label: String; let kind: String; let keyFormat: String?; let input: String
        let plaintextHex: String; let ephemeralPrivateKey: String; let expectedBundle: String; let sdkJsRandomBundle: String
    }
    struct Negative: Decodable { let label: String; let importBundle: String }
    let _meta: FixtureMeta
    let organizationId: String
    let userId: String
    let target: KeyPairFixture
    let signerPublicKey: String
    let importBundle: String
    let cases: [Case]
    let negatives: [Negative]
}

private struct OTPFixture: Decodable {
    let _meta: FixtureMeta
    let target: KeyPairFixture
    let signerPublicKey: String
    let otpEncryptionTargetBundle: String
    let otpCode: String
    let publicKey: String
    let ephemeralPrivateKey: String
    let plaintext: String
    let expectedBundle: String
}

private struct JWTFixture: Decodable {
    let _meta: FixtureMeta
    let notarizerPublicKey: String
    let jwt: String
    let tamperedJwt: String
}

private func eph(_ hex: String) throws -> P256.KeyAgreement.PrivateKey {
    try P256.KeyAgreement.PrivateKey(rawRepresentation: Hex.decode(hex))
}

private func openFormatted(_ json: String, privateKey: String) throws -> Data {
    let obj = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: String]
    return try ZeroXKeyHPKE.decrypt(
        ciphertext: Hex.decode(obj["ciphertext"]!), encappedPublicKey: Hex.decode(obj["encappedPublic"]!),
        recipientPrivateKey: Hex.decode(privateKey))
}

@Suite("Credential bundle (decryptCredentialBundle)")
struct CredentialBundleTests {
    private let f: CredentialFixture = try! Fixtures.load("credential-bundle")

    @Test func decryptsSdkJsBundle() throws {
        #expect(try decryptCredentialBundle(f.credentialBundle, embeddedPrivateKey: f.embedded.privateKey) == f.expectedDecryptedHex)
    }

    @Test func rejectsWrongKeyAndCorruption() throws {
        #expect(throws: ZeroXKeyCryptoError.self) {
            try decryptCredentialBundle(f.credentialBundle, embeddedPrivateKey: generateP256KeyPair().privateKey)
        }
        #expect(throws: ZeroXKeyCryptoError.self) {
            try decryptCredentialBundle(String(f.credentialBundle.dropLast()) + "1", embeddedPrivateKey: f.embedded.privateKey)
        }
    }
}

@Suite("Export bundle (decryptExportBundle)")
struct ExportBundleTests {
    private let f: ExportFixture = try! Fixtures.load("export-bundle")

    @Test func decryptsAllFormatsLikeSdkJs() throws {
        #expect(f.cases.map(\.label) == ["mnemonic", "mnemonic-as-hex", "hex-private-key", "solana-private-key"])
        for c in f.cases {
            let out = try decryptExportBundle(
                exportBundle: c.bundle, organizationId: f.organizationId, embeddedPrivateKey: f.embedded.privateKey,
                keyFormat: KeyFormat(rawValue: c.keyFormat)!, returnMnemonic: c.returnMnemonic,
                dangerouslyOverrideSignerPublicKey: f.signerPublicKey)
            #expect(out == c.expected, "case \(c.label)")
        }
    }

    @Test func defaultTrustAnchorRejectsNonProductionSigner() throws {
        #expect(f.signerPublicKey != ZeroXKeyTrustAnchors.productionSignerSignPublicKey)
        let c = f.cases[0]
        #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(
            expected: ZeroXKeyTrustAnchors.productionSignerSignPublicKey, found: f.signerPublicKey)) {
            try decryptExportBundle(exportBundle: c.bundle, organizationId: f.organizationId,
                                    embeddedPrivateKey: f.embedded.privateKey, returnMnemonic: true)
        }
    }

    @Test func wrongOverrideAnchorRejected() throws {
        #expect(throws: ZeroXKeyCryptoError.self) {
            try decryptExportBundle(exportBundle: f.cases[0].bundle, organizationId: f.organizationId,
                                    embeddedPrivateKey: f.embedded.privateKey, returnMnemonic: true,
                                    dangerouslyOverrideSignerPublicKey: generateP256KeyPair().publicKeyUncompressed)
        }
    }

    @Test func negativesRejectedLikeSdkJs() throws {
        #expect(f.negatives.count == 4)
        for n in f.negatives {
            #expect(throws: ZeroXKeyCryptoError.self, "negative \(n.label)") {
                try decryptExportBundle(exportBundle: n.bundle, organizationId: f.organizationId,
                                        embeddedPrivateKey: f.embedded.privateKey, returnMnemonic: true,
                                        dangerouslyOverrideSignerPublicKey: f.signerPublicKey)
            }
        }
    }

    @Test func wrongEmbeddedKeyFails() {
        #expect(throws: ZeroXKeyCryptoError.hpkeDecryptionFailed) {
            try decryptExportBundle(exportBundle: f.cases[0].bundle, organizationId: f.organizationId,
                                    embeddedPrivateKey: generateP256KeyPair().privateKey, returnMnemonic: true,
                                    dangerouslyOverrideSignerPublicKey: f.signerPublicKey)
        }
    }
}

@Suite("Import bundle (encryptWalletToBundle / encryptPrivateKeyToBundle)")
struct ImportBundleTests {
    private let f: ImportFixture = try! Fixtures.load("import-bundle")

    @Test func deterministicOutputMatchesSdkJsByteForByte() throws {
        #expect(f.cases.count == 4)
        for c in f.cases {
            let plaintext = c.kind == "wallet"
                ? Data(c.input.utf8)
                : try decodeImportKey(c.input, keyFormat: KeyFormat(rawValue: c.keyFormat!)!)
            #expect(Hex.encode(plaintext) == c.plaintextHex, "decodeKey \(c.label)")
            let out = try encryptToImportBundle(
                plaintext: plaintext, importBundle: f.importBundle, userId: f.userId, organizationId: f.organizationId,
                dangerouslyOverrideSignerPublicKey: f.signerPublicKey, ephemeralPrivateKey: eph(c.ephemeralPrivateKey))
            #expect(out == c.expectedBundle, "case \(c.label)")
        }
    }

    @Test func publicApiProducesDecryptableBundles() throws {
        for c in f.cases {
            let out = c.kind == "wallet"
                ? try encryptWalletToBundle(mnemonic: c.input, importBundle: f.importBundle, userId: f.userId,
                                            organizationId: f.organizationId, dangerouslyOverrideSignerPublicKey: f.signerPublicKey)
                : try encryptPrivateKeyToBundle(privateKey: c.input, keyFormat: KeyFormat(rawValue: c.keyFormat!)!,
                                                importBundle: f.importBundle, userId: f.userId, organizationId: f.organizationId,
                                                dangerouslyOverrideSignerPublicKey: f.signerPublicKey)
            #expect(out.hasPrefix(#"{"encappedPublic":"04"#))
            #expect(Hex.encode(try openFormatted(out, privateKey: f.target.privateKey)) == c.plaintextHex)
            // sdk-js's own (randomized) output for the same input decrypts to the same plaintext.
            #expect(Hex.encode(try openFormatted(c.sdkJsRandomBundle, privateKey: f.target.privateKey)) == c.plaintextHex)
        }
    }

    @Test func negativesRejected() throws {
        for n in f.negatives {
            #expect(throws: ZeroXKeyCryptoError.self, "negative \(n.label)") {
                try encryptWalletToBundle(mnemonic: "x", importBundle: n.importBundle, userId: f.userId,
                                          organizationId: f.organizationId, dangerouslyOverrideSignerPublicKey: f.signerPublicKey)
            }
        }
        #expect(throws: ZeroXKeyCryptoError.self) {
            try encryptWalletToBundle(mnemonic: "x", importBundle: f.importBundle, userId: f.userId, organizationId: f.organizationId)
        }
    }
}

@Suite("OTP attempt bundle (core.ts encryptOtpAttemptBundle)")
struct OTPBundleTests {
    private let f: OTPFixture = try! Fixtures.load("otp-bundle")

    @Test func matchesSdkJsComposition() throws {
        let out = try encryptOtpAttemptBundle(
            otpCode: f.otpCode, publicKey: f.publicKey, otpEncryptionTargetBundle: f.otpEncryptionTargetBundle,
            dangerouslyOverrideSignerPublicKey: f.signerPublicKey, ephemeralPrivateKey: eph(f.ephemeralPrivateKey))
        #expect(out == f.expectedBundle)
        let random = try encryptOtpAttemptBundle(
            otpCode: f.otpCode, publicKey: f.publicKey, otpEncryptionTargetBundle: f.otpEncryptionTargetBundle,
            dangerouslyOverrideSignerPublicKey: f.signerPublicKey)
        #expect(String(decoding: try openFormatted(random, privateKey: f.target.privateKey), as: UTF8.self) == f.plaintext)
    }

    @Test func fixtureIsNotSignedByTheProductionSigner() {
        #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(
            expected: ZeroXKeyTrustAnchors.productionSignerSignPublicKey, found: f.signerPublicKey)) {
            try encryptOtpAttemptBundle(otpCode: f.otpCode, publicKey: f.publicKey, otpEncryptionTargetBundle: f.otpEncryptionTargetBundle)
        }
    }

    @Test func rejectsMalformedTargetBundle() {
        #expect(throws: ZeroXKeyCryptoError.self) {
            try encryptOtpAttemptBundle(otpCode: "1", publicKey: "02", otpEncryptionTargetBundle: #"{"data":"zz"}"#)
        }
    }
}

@Suite("Session JWT signature")
struct SessionJWTTests {
    private let f: JWTFixture = try! Fixtures.load("session-jwt")

    @Test func verifiesSdkJsCompatibleJwt() throws {
        #expect(try verifySessionJwtSignature(f.jwt, dangerouslyOverrideNotarizerPublicKey: f.notarizerPublicKey))
        #expect(try !verifySessionJwtSignature(f.tamperedJwt, dangerouslyOverrideNotarizerPublicKey: f.notarizerPublicKey))
        // Not signed by the production notarizer.
        #expect(try !verifySessionJwtSignature(f.jwt))
        #expect(throws: ZeroXKeyCryptoError.invalidJWT) { try verifySessionJwtSignature("a.b") }
    }
}
