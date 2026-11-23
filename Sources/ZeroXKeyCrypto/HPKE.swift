import CryptoKit
import Foundation
import ZeroXKeyEncoding

/// HPKE as used by 0xkey: RFC 9180 base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
/// AES-256-GCM, `info = "0xkey_hpke"`.
///
/// Wire format and derivation follow sdk-js `hpkeEncrypt` / `hpkeDecrypt` /
/// `getHpkeScheduleInfo` / `formatHpkeBuf`
/// (sdk-js `internal/crypto-core/src/primitives/crypto.ts` lines 102-162, 303-371, 591-629):
///
/// - KEM context = `enc(65 bytes, uncompressed) || pkR(65 bytes, uncompressed)`.
/// - AES-GCM AAD = `enc(uncompressed) || pkR(uncompressed)` (`buildAdditionalAssociatedData`);
///   this is an sdk-js convention on top of RFC 9180, which leaves AAD to the application.
/// - Sequence number 0, so the nonce is the base nonce.
/// - Output = `compressed enc (33 bytes) || ciphertext || 16-byte tag`.
///
/// Only the 0xkey key schedule (the non-legacy branch of `getHpkeScheduleInfo`) is
/// implemented. The public API always uses `ZeroXKeyHPKEConstants.info`; the `info`
/// and ephemeral-key injection points are `package`-scoped for vectors and tests.
public enum ZeroXKeyHPKE {
    /// Encrypts `plaintext` to `recipientPublicKey` (33- or 65-byte P-256 point).
    /// Returns `compressed enc || ciphertext || tag`.
    public static func encrypt(plaintext: Data, recipientPublicKey: Data) throws -> Data {
        try encrypt(
            plaintext: plaintext,
            recipientPublicKey: recipientPublicKey,
            ephemeralPrivateKey: P256.KeyAgreement.PrivateKey(),
            info: Data(ZeroXKeyHPKEConstants.info.utf8)
        )
    }

    /// Decrypts `ciphertext` (ciphertext || tag) for the encapsulated key `encappedPublicKey`
    /// (33- or 65-byte point) using the recipient's 32-byte private scalar.
    public static func decrypt(ciphertext: Data, encappedPublicKey: Data, recipientPrivateKey: Data) throws -> Data {
        try decrypt(
            ciphertext: ciphertext,
            encappedPublicKey: encappedPublicKey,
            recipientPrivateKey: recipientPrivateKey,
            info: Data(ZeroXKeyHPKEConstants.info.utf8)
        )
    }

    /// Decrypts the concatenated `compressed enc || ciphertext || tag` form.
    public static func decrypt(sealed: Data, recipientPrivateKey: Data) throws -> Data {
        guard sealed.count >= 33 + 16 else { throw ZeroXKeyCryptoError.hpkeDecryptionFailed }
        return try decrypt(
            ciphertext: Data(sealed.dropFirst(33)),
            encappedPublicKey: Data(sealed.prefix(33)),
            recipientPrivateKey: recipientPrivateKey
        )
    }

    /// `formatHpkeBuf`: `{"encappedPublic":"<uncompressed hex>","ciphertext":"<hex>"}`
    /// (key order and compact layout as produced by `JSON.stringify`).
    public static func formatBundle(_ sealed: Data) throws -> String {
        guard sealed.count > 33 else { throw ZeroXKeyCryptoError.invalidBundle("sealed buffer too short") }
        let enc = try P256PublicKeyCodec.uncompress(Data(sealed.prefix(33)))
        return OrderedJSON.stringify([
            ("encappedPublic", Hex.encode(enc)),
            ("ciphertext", Hex.encode(sealed.dropFirst(33))),
        ])
    }

    // MARK: - Package-scoped injection points

    package static func encrypt(
        plaintext: Data,
        recipientPublicKey: Data,
        ephemeralPrivateKey: P256.KeyAgreement.PrivateKey,
        info: Data
    ) throws -> Data {
        let pkR = try P256PublicKeyCodec.uncompressed(recipientPublicKey)
        guard let recipient = try? P256.KeyAgreement.PublicKey(x963Representation: pkR) else {
            throw ZeroXKeyCryptoError.invalidPublicKey
        }
        let enc = ephemeralPrivateKey.publicKey.x963Representation
        let dh = try sharedSecretBytes(ephemeralPrivateKey, recipient)
        let (key, nonce) = keySchedule(dh: dh, enc: enc, pkR: pkR, info: info)
        do {
            let box = try AES.GCM.seal(
                plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: enc + pkR)
            return ephemeralPrivateKey.publicKey.compressedRepresentation + box.ciphertext + box.tag
        } catch {
            throw ZeroXKeyCryptoError.hpkeEncryptionFailed("\(error)")
        }
    }

    package static func decrypt(
        ciphertext: Data,
        encappedPublicKey: Data,
        recipientPrivateKey: Data,
        info: Data
    ) throws -> Data {
        guard let receiver = try? P256.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKey) else {
            throw ZeroXKeyCryptoError.invalidPrivateKey
        }
        let enc = try P256PublicKeyCodec.uncompressed(encappedPublicKey)
        guard let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: enc),
              ciphertext.count >= 16
        else { throw ZeroXKeyCryptoError.hpkeDecryptionFailed }
        let pkR = receiver.publicKey.x963Representation
        let dh = try sharedSecretBytes(receiver, ephemeral)
        let (key, nonce) = keySchedule(dh: dh, enc: enc, pkR: pkR, info: info)
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext.dropLast(16),
                tag: ciphertext.suffix(16))
            return try AES.GCM.open(box, using: key, authenticating: enc + pkR)
        } catch {
            throw ZeroXKeyCryptoError.hpkeDecryptionFailed
        }
    }

    // MARK: - RFC 9180 key schedule

    private static func sharedSecretBytes(
        _ priv: P256.KeyAgreement.PrivateKey, _ pub: P256.KeyAgreement.PublicKey
    ) throws -> Data {
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
        return secret.withUnsafeBytes { Data($0) }  // x-coordinate, 32 bytes
    }

    private static func labeledExtract(salt: Data, suite: Data, label: String, ikm: Data) -> Data {
        let labeled = ZeroXKeyHPKEConstants.version + suite + Data(label.utf8) + ikm
        let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: labeled), salt: salt)
        return Data(prk)
    }

    private static func labeledExpand(prk: Data, suite: Data, label: String, info: Data, length: Int) -> Data {
        let labeled = Data([UInt8(length >> 8), UInt8(length & 0xff)])
            + ZeroXKeyHPKEConstants.version + suite + Data(label.utf8) + info
        let okm = HKDF<SHA256>.expand(pseudoRandomKey: SymmetricKey(data: prk), info: labeled, outputByteCount: length)
        return okm.withUnsafeBytes { Data($0) }
    }

    private static func keySchedule(dh: Data, enc: Data, pkR: Data, info: Data) -> (SymmetricKey, Data) {
        let kem = ZeroXKeyHPKEConstants.kemSuiteID
        let suite = ZeroXKeyHPKEConstants.hpkeSuiteID
        // DHKEM ExtractAndExpand
        let eaePrk = labeledExtract(salt: Data(), suite: kem, label: "eae_prk", ikm: dh)
        let sharedSecret = labeledExpand(prk: eaePrk, suite: kem, label: "shared_secret", info: enc + pkR, length: 32)
        // KeySchedule, mode_base, empty PSK
        let pskIDHash = labeledExtract(salt: Data(), suite: suite, label: "psk_id_hash", ikm: Data())
        let infoHash = labeledExtract(salt: Data(), suite: suite, label: "info_hash", ikm: info)
        let context = Data([0x00]) + pskIDHash + infoHash
        let secret = labeledExtract(salt: sharedSecret, suite: suite, label: "secret", ikm: Data())
        let key = labeledExpand(prk: secret, suite: suite, label: "key", info: context, length: 32)
        let nonce = labeledExpand(prk: secret, suite: suite, label: "base_nonce", info: context, length: 12)
        return (SymmetricKey(data: key), nonce)
    }
}
