import CryptoKit
import Foundation
import ZeroXKeyEncoding

/// Key format of an exported / imported private key.
/// Mirrors the `keyFormat` parameter of sdk-js `decryptExportBundle` /
/// `encryptPrivateKeyToBundle` (sdk-js `packages/crypto/src/0xkey.ts`).
public enum KeyFormat: String, Sendable, CaseIterable {
    case hexadecimal = "HEXADECIMAL"
    case solana = "SOLANA"
}

// MARK: - Credential bundle

/// Decrypts an email-auth / recovery / OAuth credential bundle and returns the
/// decrypted payload (the session API private key) as lowercase hex.
///
/// Port of `decryptCredentialBundle` (`0xkey.ts` lines 79-105): base58check decode,
/// split `compressed enc (33) || ciphertext`, HPKE-open with `0xkey_hpke`.
public func decryptCredentialBundle(_ credentialBundle: String, embeddedPrivateKey: String) throws -> String {
    let bytes: Data
    do { bytes = try Base58Check.decode(credentialBundle) } catch {
        throw ZeroXKeyCryptoError.invalidBundle("credential bundle is not valid base58check")
    }
    guard bytes.count > 33 else {
        throw ZeroXKeyCryptoError.invalidBundle("bundle size \(bytes.count) is too low")
    }
    let plaintext = try ZeroXKeyHPKE.decrypt(sealed: bytes, recipientPrivateKey: Hex.decode(embeddedPrivateKey))
    return Hex.encode(plaintext)
}

// MARK: - Enclave-signed bundles

/// Parsed outer envelope `{version, data, dataSignature, enclaveQuorumPublic}`.
struct EnclaveSignedBundle: Decodable {
    let data: String
    let dataSignature: String
    let enclaveQuorumPublic: String
}

/// Verifies the outer envelope and returns the decoded inner JSON object.
///
/// Port of `verifyEnclaveSignature` (`0xkey.ts` lines 243-273): the bundle's
/// `enclaveQuorumPublic` must equal the pinned signer key (string equality), and
/// `dataSignature` must be a valid ECDSA-SHA256 signature over the hex-decoded `data`.
func openEnclaveSignedBundle(_ json: String, dangerouslyOverrideSignerPublicKey: String?) throws -> [String: Any] {
    let envelope: EnclaveSignedBundle
    do {
        envelope = try JSONDecoder().decode(EnclaveSignedBundle.self, from: Data(json.utf8))
    } catch {
        throw ZeroXKeyCryptoError.invalidBundle("bundle is not valid JSON: \(error)")
    }
    let expected = dangerouslyOverrideSignerPublicKey ?? ZeroXKeyTrustAnchors.productionSignerSignPublicKey
    guard envelope.enclaveQuorumPublic == expected else {
        throw ZeroXKeyCryptoError.signerKeyMismatch(expected: expected, found: envelope.enclaveQuorumPublic)
    }
    guard let signedData = try? Hex.decode(envelope.data),
          let signature = try? Hex.decode(envelope.dataSignature), !signature.isEmpty,
          let quorumPublic = try? Hex.decode(envelope.enclaveQuorumPublic)
    else { throw ZeroXKeyCryptoError.invalidBundle("bundle data, dataSignature or enclaveQuorumPublic is empty or not hex") }
    guard try P256Signer.verifyDER(signature: signature, message: signedData, publicKey: quorumPublic)
    else { throw ZeroXKeyCryptoError.enclaveSignatureInvalid }
    guard let inner = try? JSONSerialization.jsonObject(with: signedData) as? [String: Any] else {
        throw ZeroXKeyCryptoError.invalidBundle("signed data is not a JSON object")
    }
    return inner
}

/// Decrypts an export bundle (wallet mnemonic or private key).
///
/// Port of `decryptExportBundle` (`0xkey.ts` lines 124-196). The enclave signature is
/// verified against `ZeroXKeyTrustAnchors.productionSignerSignPublicKey` unless
/// `dangerouslyOverrideSignerPublicKey` is given (tests / non-production enclaves only).
///
/// - Returns: the mnemonic when `returnMnemonic` is true; for `.solana` keys the
///   base58 `secret || public` 64-byte key; otherwise the lowercase hex payload.
public func decryptExportBundle(
    exportBundle: String,
    organizationId: String,
    embeddedPrivateKey: String,
    keyFormat: KeyFormat = .hexadecimal,
    returnMnemonic: Bool,
    dangerouslyOverrideSignerPublicKey: String? = nil
) throws -> String {
    let inner = try openEnclaveSignedBundle(exportBundle, dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey)
    let foundOrg = inner["organizationId"] as? String
    guard let foundOrg, !foundOrg.isEmpty, foundOrg == organizationId else {
        throw ZeroXKeyCryptoError.organizationIdMismatch(expected: organizationId, found: foundOrg)
    }
    guard let encapped = inner["encappedPublic"] as? String, !encapped.isEmpty else {
        throw ZeroXKeyCryptoError.invalidBundle("missing \"encappedPublic\" in bundle signed data")
    }
    guard let ciphertext = inner["ciphertext"] as? String else {
        throw ZeroXKeyCryptoError.invalidBundle("missing \"ciphertext\" in bundle signed data")
    }
    let plaintext = try ZeroXKeyHPKE.decrypt(
        ciphertext: Hex.decode(ciphertext),
        encappedPublicKey: Hex.decode(encapped),
        recipientPrivateKey: Hex.decode(embeddedPrivateKey))

    if keyFormat == .solana && !returnMnemonic {
        guard plaintext.count == 32 else {
            throw ZeroXKeyCryptoError.invalidKeyLength(expected: 32, actual: plaintext.count)
        }
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: plaintext).publicKey.rawRepresentation
        return Base58.encode(plaintext + publicKey)
    }
    if returnMnemonic {
        // sdk-js `hexToAscii` maps each byte to one UTF-16 code unit (Latin-1).
        return String(plaintext.map { Character(Unicode.Scalar($0)) })
    }
    return Hex.encode(plaintext)
}

/// Encrypts a BIP-39 mnemonic to an import bundle. Port of `encryptWalletToBundle`
/// (`0xkey.ts` lines 386-435). Returns the `formatHpkeBuf` JSON string.
public func encryptWalletToBundle(
    mnemonic: String,
    importBundle: String,
    userId: String,
    organizationId: String,
    dangerouslyOverrideSignerPublicKey: String? = nil
) throws -> String {
    try encryptToImportBundle(
        plaintext: Data(mnemonic.utf8), importBundle: importBundle, userId: userId,
        organizationId: organizationId, dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey())
}

/// Encrypts a private key to an import bundle. Port of `encryptPrivateKeyToBundle`
/// (`0xkey.ts` lines 326-376) including `decodeKey` (lines 293-317).
public func encryptPrivateKeyToBundle(
    privateKey: String,
    keyFormat: KeyFormat,
    importBundle: String,
    userId: String,
    organizationId: String,
    dangerouslyOverrideSignerPublicKey: String? = nil
) throws -> String {
    try encryptToImportBundle(
        plaintext: decodeImportKey(privateKey, keyFormat: keyFormat), importBundle: importBundle, userId: userId,
        organizationId: organizationId, dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey())
}

package func decodeImportKey(_ privateKey: String, keyFormat: KeyFormat) throws -> Data {
    switch keyFormat {
    case .solana:
        let bytes = try Base58.decode(privateKey)
        guard bytes.count == 64 else { throw ZeroXKeyCryptoError.invalidKeyLength(expected: 64, actual: bytes.count) }
        return Data(bytes.prefix(32))
    case .hexadecimal:
        return try Hex.decode(privateKey, allowPrefix: true)
    }
}

package func encryptToImportBundle(
    plaintext: Data,
    importBundle: String,
    userId: String,
    organizationId: String,
    dangerouslyOverrideSignerPublicKey: String?,
    ephemeralPrivateKey: P256.KeyAgreement.PrivateKey
) throws -> String {
    let inner = try openEnclaveSignedBundle(importBundle, dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey)
    let foundOrg = inner["organizationId"] as? String
    guard let foundOrg, !foundOrg.isEmpty, foundOrg == organizationId else {
        throw ZeroXKeyCryptoError.organizationIdMismatch(expected: organizationId, found: foundOrg)
    }
    let foundUser = inner["userId"] as? String
    guard let foundUser, !foundUser.isEmpty, foundUser == userId else {
        throw ZeroXKeyCryptoError.userIdMismatch(expected: userId, found: foundUser)
    }
    guard let target = inner["targetPublic"] as? String, !target.isEmpty else {
        throw ZeroXKeyCryptoError.invalidBundle("missing \"targetPublic\" in bundle signed data")
    }
    let sealed = try ZeroXKeyHPKE.encrypt(
        plaintext: plaintext, recipientPublicKey: Hex.decode(target),
        ephemeralPrivateKey: ephemeralPrivateKey, info: Data(ZeroXKeyHPKEConstants.info.utf8))
    return try ZeroXKeyHPKE.formatBundle(sealed)
}

// MARK: - OTP

/// Encrypts an OTP attempt for Auth Proxy `otp_verify_v2`, after verifying that the target bundle
/// was signed by the 0xkey signer enclave.
///
/// Composition as `encryptOtpAttemptBundle` (sdk-js `packages/core/src/__clients__/core.ts`
/// lines 254-281): plaintext `{"otp_code":…,"public_key":…}`, HPKE (`0xkey_hpke`) to
/// `targetPublic` from the signed `data` of `otpEncryptionTargetBundle`.
///
/// The enclave returns the target bundle in the same envelope as export / import bundles
/// (`version`, `data`, `dataSignature`, `enclaveQuorumPublic`), signed with the quorum signing
/// key. `enclaveQuorumPublic` must equal ``ZeroXKeyTrustAnchors/productionSignerSignPublicKey``
/// and `dataSignature` must verify over `data`; otherwise this throws
/// ``ZeroXKeyCryptoError/signerKeyMismatch(expected:found:)``,
/// ``ZeroXKeyCryptoError/enclaveSignatureInvalid`` or ``ZeroXKeyCryptoError/invalidBundle(_:)``
/// and nothing is encrypted. sdk-js skips this check; without it whoever can alter the Auth Proxy
/// response chooses the key the OTP code and session public key are encrypted to.
public func encryptOtpAttemptBundle(otpCode: String, publicKey: String, otpEncryptionTargetBundle: String) throws -> String {
    try encryptOtpAttemptBundle(
        otpCode: otpCode, publicKey: publicKey, otpEncryptionTargetBundle: otpEncryptionTargetBundle,
        dangerouslyOverrideSignerPublicKey: nil)
}

/// ``encryptOtpAttemptBundle(otpCode:publicKey:otpEncryptionTargetBundle:)`` with a different
/// expected signer key.
///
/// - Parameter dangerouslyOverrideSignerPublicKey: uncompressed P-256 signing key (hex) of a
///   non-production enclave, used instead of
///   ``ZeroXKeyTrustAnchors/productionSignerSignPublicKey``; `nil` keeps the production key. The
///   signature is verified either way.
public func encryptOtpAttemptBundle(
    otpCode: String, publicKey: String, otpEncryptionTargetBundle: String,
    dangerouslyOverrideSignerPublicKey: String?
) throws -> String {
    try encryptOtpAttemptBundle(
        otpCode: otpCode, publicKey: publicKey, otpEncryptionTargetBundle: otpEncryptionTargetBundle,
        dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey())
}

package func encryptOtpAttemptBundle(
    otpCode: String, publicKey: String, otpEncryptionTargetBundle: String,
    ephemeralPrivateKey: P256.KeyAgreement.PrivateKey
) throws -> String {
    try encryptOtpAttemptBundle(
        otpCode: otpCode, publicKey: publicKey, otpEncryptionTargetBundle: otpEncryptionTargetBundle,
        dangerouslyOverrideSignerPublicKey: nil, ephemeralPrivateKey: ephemeralPrivateKey)
}

package func encryptOtpAttemptBundle(
    otpCode: String, publicKey: String, otpEncryptionTargetBundle: String,
    dangerouslyOverrideSignerPublicKey: String?, ephemeralPrivateKey: P256.KeyAgreement.PrivateKey
) throws -> String {
    let inner = try openEnclaveSignedBundle(
        otpEncryptionTargetBundle, dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey)
    guard let target = inner["targetPublic"] as? String, !target.isEmpty else {
        throw ZeroXKeyCryptoError.invalidBundle("missing \"targetPublic\" in otpEncryptionTargetBundle signed data")
    }
    let plaintext = Data(OrderedJSON.stringify([("otp_code", otpCode), ("public_key", publicKey)]).utf8)
    let sealed = try ZeroXKeyHPKE.encrypt(
        plaintext: plaintext, recipientPublicKey: Hex.decode(target, allowPrefix: true),
        ephemeralPrivateKey: ephemeralPrivateKey, info: Data(ZeroXKeyHPKEConstants.info.utf8))
    return try ZeroXKeyHPKE.formatBundle(sealed)
}

// MARK: - Signature verification helpers

/// Verifies a stamp signature (DER hex) over the UTF-8 `signedData`.
/// Port of `verifyStampSignature` (`0xkey.ts` lines 215-232).
public func verifyStampSignature(publicKey: String, signature: String, signedData: String) throws -> Bool {
    try P256Signer.verifyDER(signature: Hex.decode(signature), message: Data(signedData.utf8), publicKey: Hex.decode(publicKey))
}

/// Verifies a session JWT signed by the 0xkey notarizer: ECDSA over
/// SHA-256(SHA-256("header.payload")), compact 64-byte base64url signature.
/// Port of `verifySessionJwtSignature` (`0xkey.ts` lines 461-495).
public func verifySessionJwtSignature(_ jwt: String, dangerouslyOverrideNotarizerPublicKey: String? = nil) throws -> Bool {
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count >= 3, !parts[2].isEmpty else { throw ZeroXKeyCryptoError.invalidJWT }
    let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
    let digest = SHA256.hash(data: Data(SHA256.hash(data: signingInput)))
    let rawSignature = try Base64URL.decode(String(parts[2]))
    guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: rawSignature) else {
        throw ZeroXKeyCryptoError.invalidSignature("JWT signature must be 64 bytes r||s")
    }
    let key = try P256PublicKeyCodec.signingKey(
        Hex.decode(dangerouslyOverrideNotarizerPublicKey ?? ZeroXKeyTrustAnchors.productionNotarizerSignPublicKey))
    return key.isValidSignature(signature, for: digest)
}
