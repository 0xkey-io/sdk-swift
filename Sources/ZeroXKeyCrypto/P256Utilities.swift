import CryptoKit
import Foundation
import ZeroXKeyEncoding

/// Errors raised by `ZeroXKeyCrypto`.
public enum ZeroXKeyCryptoError: Error, Equatable, Sendable {
    case invalidPrivateKey
    case invalidPublicKey
    case invalidSignature(String)
    case hpkeDecryptionFailed
    case hpkeEncryptionFailed(String)
    case invalidBundle(String)
    case signerKeyMismatch(expected: String, found: String)
    case enclaveSignatureInvalid
    case organizationIdMismatch(expected: String, found: String?)
    case userIdMismatch(expected: String, found: String?)
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidJWT
}

/// A P-256 key pair encoded the way sdk-js `generateP256KeyPair` returns it
/// (sdk-js `internal/crypto-core/src/primitives/crypto.ts` lines 378-389):
/// lowercase hex private scalar, compressed public key and uncompressed public key.
public struct P256KeyPair: Sendable, Equatable {
    public let privateKey: String
    public let publicKey: String
    public let publicKeyUncompressed: String

    public init(privateKey: String) throws {
        let raw = try Hex.decode(privateKey)
        guard raw.count == 32, let key = try? P256.Signing.PrivateKey(rawRepresentation: raw) else {
            throw ZeroXKeyCryptoError.invalidPrivateKey
        }
        self.privateKey = Hex.encode(raw)
        self.publicKey = Hex.encode(key.publicKey.compressedRepresentation)
        self.publicKeyUncompressed = Hex.encode(key.publicKey.x963Representation)
    }
}

/// Generates a fresh P-256 key pair (`generateP256KeyPair` in sdk-js).
public func generateP256KeyPair() -> P256KeyPair {
    let key = P256.KeyAgreement.PrivateKey()
    // A freshly generated CryptoKit key is always a valid scalar.
    return try! P256KeyPair(privateKey: Hex.encode(key.rawRepresentation))
}

/// Public-key point conversions. Equivalent to `compressRawPublicKey` /
/// `uncompressRawPublicKey` in crypto-core `crypto.ts` lines 426-501, but implemented with
/// CryptoKit's point decoding (which also validates that the point is on the curve).
public enum P256PublicKeyCodec {
    /// 65-byte `04||x||y` → 33-byte `02|03||x`.
    public static func compress(_ uncompressed: Data) throws -> Data {
        guard uncompressed.count == 65, uncompressed.first == 0x04,
              let key = try? P256.KeyAgreement.PublicKey(x963Representation: uncompressed)
        else { throw ZeroXKeyCryptoError.invalidPublicKey }
        return key.compressedRepresentation
    }

    /// 33-byte compressed → 65-byte uncompressed.
    public static func uncompress(_ compressed: Data) throws -> Data {
        guard compressed.count == 33, compressed.first == 0x02 || compressed.first == 0x03,
              let key = try? P256.KeyAgreement.PublicKey(compressedRepresentation: compressed)
        else { throw ZeroXKeyCryptoError.invalidPublicKey }
        return key.x963Representation
    }

    /// Accepts either encoding and returns the uncompressed form.
    public static func uncompressed(_ key: Data) throws -> Data {
        switch key.count {
        case 65: return try uncompress(compress(key))
        case 33: return try uncompress(key)
        default: throw ZeroXKeyCryptoError.invalidPublicKey
        }
    }

    static func signingKey(_ key: Data) throws -> P256.Signing.PublicKey {
        let raw = try uncompressed(key)
        guard let k = try? P256.Signing.PublicKey(x963Representation: raw) else {
            throw ZeroXKeyCryptoError.invalidPublicKey
        }
        return k
    }
}

/// ECDSA P-256 signature encodings.
public enum ECDSASignatureCodec {
    /// Curve order n of P-256 (big-endian).
    static let order: [UInt8] = Array(try! Hex.decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))
    static let halfOrder: [UInt8] = Array(try! Hex.decode("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8"))

    /// DER → 64-byte `r||s`. Mirrors `fromDerSignature` (crypto-core `crypto.ts` 722-816):
    /// short-form lengths only, each integer at most 33 bytes, left-padded to 32.
    public static func fromDER(_ der: Data) throws -> Data {
        let b = [UInt8](der)
        guard b.count >= 2 else { throw ZeroXKeyCryptoError.invalidSignature("insufficient length") }
        guard b[0] == 0x30 else { throw ZeroXKeyCryptoError.invalidSignature("missing SEQUENCE tag") }
        guard b[1] <= 0x7f else { throw ZeroXKeyCryptoError.invalidSignature("long-form length") }
        guard b.count >= 2 + Int(b[1]) else { throw ZeroXKeyCryptoError.invalidSignature("inconsistent length") }
        var i = 2
        func integer() throws -> [UInt8] {
            guard i + 1 < b.count, b[i] == 0x02 else { throw ZeroXKeyCryptoError.invalidSignature("invalid INTEGER tag") }
            let len = Int(b[i + 1])
            guard len <= 33, i + 2 + len <= b.count else { throw ZeroXKeyCryptoError.invalidSignature("invalid INTEGER length") }
            defer { i += 2 + len }
            return Array(b[(i + 2)..<(i + 2 + len)])
        }
        let r = try normalize(integer())
        let s = try normalize(integer())
        return Data(r + s)
    }

    /// 64-byte `r||s` → minimal DER.
    public static func toDER(_ raw: Data) throws -> Data {
        guard raw.count == 64 else { throw ZeroXKeyCryptoError.invalidSignature("raw signature must be 64 bytes") }
        func encode(_ v: ArraySlice<UInt8>) -> [UInt8] {
            var x = Array(v.drop(while: { $0 == 0 }))
            if x.isEmpty { x = [0] }
            if x[0] & 0x80 != 0 { x.insert(0, at: 0) }
            return [0x02, UInt8(x.count)] + x
        }
        let bytes = [UInt8](raw)
        let body = encode(bytes[0..<32]) + encode(bytes[32..<64])
        return Data([0x30, UInt8(body.count)] + body)
    }

    /// Returns `r||s` with `s` replaced by `n - s` when `s > n/2`.
    public static func normalizeLowS(_ raw: Data) throws -> Data {
        guard raw.count == 64 else { throw ZeroXKeyCryptoError.invalidSignature("raw signature must be 64 bytes") }
        let bytes = [UInt8](raw)
        let s = Array(bytes[32..<64])
        guard compare(s, halfOrder) > 0 else { return raw }
        return Data(bytes[0..<32]) + Data(subtract(order, s))
    }

    public static func isLowS(_ raw: Data) -> Bool {
        raw.count == 64 && compare(Array(raw.suffix(32)), halfOrder) <= 0
    }

    private static func normalize(_ v: [UInt8]) throws -> [UInt8] {
        if v.count == 32 { return v }
        if v.count < 32 { return [UInt8](repeating: 0, count: 32 - v.count) + v }
        let extra = v.count - 32
        guard v.prefix(extra).allSatisfy({ $0 == 0 }) else {
            throw ZeroXKeyCryptoError.invalidSignature("invalid number of starting zeroes")
        }
        return Array(v.suffix(32))
    }

    private static func compare(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for (x, y) in zip(a, b) where x != y { return x < y ? -1 : 1 }
        return 0
    }

    private static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: a.count)
        var borrow = 0
        for i in stride(from: a.count - 1, through: 0, by: -1) {
            var d = Int(a[i]) - Int(b[i]) - borrow
            borrow = d < 0 ? 1 : 0
            if d < 0 { d += 256 }
            out[i] = UInt8(d)
        }
        return out
    }
}

/// P-256 ECDSA-SHA256 signing helpers shared by the stampers.
public enum P256Signer {
    /// Signs SHA-256(`message`) and returns a **low-S, minimal DER** signature.
    ///
    /// sdk-js (`purejs.ts`, noble `p256.sign`) produces deterministic RFC 6979 signatures;
    /// CryptoKit signatures are randomized, so byte equality with sdk-js is only possible
    /// for the stamp *assembly*, not the signature itself. Verification is interoperable in
    /// both directions (see the cross-language vectors). S is normalized to the low half
    /// so that strict verifiers also accept it.
    public static func signDER(message: Data, privateKey: Data) throws -> Data {
        guard let key = try? P256.Signing.PrivateKey(rawRepresentation: privateKey) else {
            throw ZeroXKeyCryptoError.invalidPrivateKey
        }
        let signature = try key.signature(for: message)
        let low = try ECDSASignatureCodec.normalizeLowS(signature.rawRepresentation)
        return try ECDSASignatureCodec.toDER(low)
    }

    /// Verifies a DER signature over SHA-256(`message`).
    public static func verifyDER(signature der: Data, message: Data, publicKey: Data) throws -> Bool {
        let key = try P256PublicKeyCodec.signingKey(publicKey)
        let raw = try ECDSASignatureCodec.fromDER(der)
        guard let sig = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else {
            throw ZeroXKeyCryptoError.invalidSignature("not a valid r||s")
        }
        return key.isValidSignature(sig, for: message)
    }
}
