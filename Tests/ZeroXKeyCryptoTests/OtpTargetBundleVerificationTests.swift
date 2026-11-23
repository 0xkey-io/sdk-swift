import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyEncoding

/// Signature checks on the OTP encryption target bundle. The bundles are signed here with
/// throwaway keys in the enclave's envelope (`version`, `data`, `dataSignature`, `enclaveQuorumPublic`).
@Suite("OTP target bundle verification")
struct OtpTargetBundleVerificationTests {
    let signer = generateP256KeyPair()
    let target = generateP256KeyPair()

    func innerJSON(targetPublic: String? = nil) -> Data {
        var fields = [("organizationId", "org-otp"), ("userId", "")]
        if let targetPublic { fields.insert(("targetPublic", targetPublic), at: 0) }
        return Data(OrderedJSON.stringify(fields).utf8)
    }

    func envelope(data: Data, signedData: Data? = nil, signedBy: P256KeyPair? = nil, quorumPublic: String? = nil,
                  omit: Set<String> = []) throws -> String {
        let key = signedBy ?? signer
        let signature = try P256Signer.signDER(message: signedData ?? data, privateKey: Hex.decode(key.privateKey))
        var fields = [("version", "v1.0.0"), ("data", Hex.encode(data)), ("dataSignature", Hex.encode(signature)),
                      ("enclaveQuorumPublic", quorumPublic ?? signer.publicKeyUncompressed)]
        fields.removeAll { omit.contains($0.0) }
        return OrderedJSON.stringify(fields)
    }

    func encrypt(_ bundle: String, expecting key: String?) throws -> String {
        try encryptOtpAttemptBundle(otpCode: "123456", publicKey: "02ab", otpEncryptionTargetBundle: bundle,
                                    dangerouslyOverrideSignerPublicKey: key)
    }

    @Test func encryptsToTheSignedTargetKey() throws {
        let bundle = try envelope(data: innerJSON(targetPublic: target.publicKeyUncompressed))
        let sealed = try encrypt(bundle, expecting: signer.publicKeyUncompressed)
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(sealed.utf8)) as? [String: String])
        let plaintext = try ZeroXKeyHPKE.decrypt(
            ciphertext: Hex.decode(obj["ciphertext"]!), encappedPublicKey: Hex.decode(obj["encappedPublic"]!),
            recipientPrivateKey: Hex.decode(target.privateKey))
        #expect(String(decoding: plaintext, as: UTF8.self) == #"{"otp_code":"123456","public_key":"02ab"}"#)
    }

    @Test func defaultsToTheProductionSignerKey() throws {
        let bundle = try envelope(data: innerJSON(targetPublic: target.publicKeyUncompressed))
        #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(
            expected: ZeroXKeyTrustAnchors.productionSignerSignPublicKey, found: signer.publicKeyUncompressed)) {
            try encryptOtpAttemptBundle(otpCode: "1", publicKey: "02ab", otpEncryptionTargetBundle: bundle)
        }
        #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(
            expected: ZeroXKeyTrustAnchors.productionSignerSignPublicKey, found: signer.publicKeyUncompressed)) {
            try encrypt(bundle, expecting: nil)
        }
    }

    @Test func rejectsTamperedData() throws {
        let signed = innerJSON(targetPublic: target.publicKeyUncompressed)
        let swapped = innerJSON(targetPublic: generateP256KeyPair().publicKeyUncompressed)
        let bundle = try envelope(data: swapped, signedData: signed)
        #expect(throws: ZeroXKeyCryptoError.enclaveSignatureInvalid) {
            try encrypt(bundle, expecting: signer.publicKeyUncompressed)
        }
    }

    @Test func rejectsASignatureByAnotherKey() throws {
        let bundle = try envelope(data: innerJSON(targetPublic: target.publicKeyUncompressed), signedBy: generateP256KeyPair())
        #expect(throws: ZeroXKeyCryptoError.enclaveSignatureInvalid) {
            try encrypt(bundle, expecting: signer.publicKeyUncompressed)
        }
    }

    /// The TLS fetcher encryption key is not a signing anchor: neither as the expected key nor as
    /// the bundle's claimed quorum key.
    @Test func theEncryptionKeyIsNotASignerKey() throws {
        let encryptionKey = ZeroXKeyTrustAnchors.productionTlsFetcherEncryptPublicKey
        let bySigner = try envelope(data: innerJSON(targetPublic: target.publicKeyUncompressed))
        #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(expected: encryptionKey, found: signer.publicKeyUncompressed)) {
            try encrypt(bySigner, expecting: encryptionKey)
        }
        let claimsEncryptionKey = try envelope(
            data: innerJSON(targetPublic: target.publicKeyUncompressed), quorumPublic: encryptionKey)
        #expect(throws: ZeroXKeyCryptoError.enclaveSignatureInvalid) {
            try encrypt(claimsEncryptionKey, expecting: encryptionKey)
        }
        #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(
            expected: ZeroXKeyTrustAnchors.productionSignerSignPublicKey, found: encryptionKey)) {
            try encrypt(claimsEncryptionKey, expecting: nil)
        }
    }

    @Test func rejectsAQuorumKeyOtherThanTheExpectedOne() throws {
        let other = generateP256KeyPair()
        let bundle = try envelope(data: innerJSON(targetPublic: target.publicKeyUncompressed), signedBy: other,
                                  quorumPublic: other.publicKeyUncompressed)
        #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(
            expected: signer.publicKeyUncompressed, found: other.publicKeyUncompressed)) {
            try encrypt(bundle, expecting: signer.publicKeyUncompressed)
        }
    }

    @Test func rejectsMissingSignatureFields() throws {
        let data = innerJSON(targetPublic: target.publicKeyUncompressed)
        for field in ["dataSignature", "enclaveQuorumPublic", "data"] {
            let bundle = try envelope(data: data, omit: [field])
            #expect(throws: ZeroXKeyCryptoError.self, "without \(field)") {
                try encrypt(bundle, expecting: signer.publicKeyUncompressed)
            }
        }
        let emptySignature = OrderedJSON.stringify([
            ("version", "v1.0.0"), ("data", Hex.encode(data)), ("dataSignature", ""),
            ("enclaveQuorumPublic", signer.publicKeyUncompressed)])
        #expect(throws: ZeroXKeyCryptoError.self) { try encrypt(emptySignature, expecting: signer.publicKeyUncompressed) }
    }

    /// The pre-verification shape (`{"data": hex}` only) is no longer accepted.
    @Test func rejectsAnUnsignedBundle() throws {
        let unsigned = OrderedJSON.stringify([("data", Hex.encode(innerJSON(targetPublic: target.publicKeyUncompressed)))])
        #expect(throws: ZeroXKeyCryptoError.self) { try encrypt(unsigned, expecting: signer.publicKeyUncompressed) }
    }

    @Test func rejectsSignedDataWithoutTargetKey() throws {
        let bundle = try envelope(data: innerJSON())
        #expect(throws: ZeroXKeyCryptoError.invalidBundle(
            "missing \"targetPublic\" in otpEncryptionTargetBundle signed data")) {
            try encrypt(bundle, expecting: signer.publicKeyUncompressed)
        }
    }
}
