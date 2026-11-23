import CryptoKit
import Foundation
import ZeroXKeyCrypto
import ZeroXKeyEncoding

/// Signature output format for `ApiKeyStamper.sign(payload:format:)`
/// (sdk-js `SignatureFormat`).
public enum SignatureFormat: String, Sendable {
    case der
    case raw
}

/// Stamps requests with a P-256 API key (`X-Stamp`).
///
/// Wire format (sdk-js `packages/api-key-stamper/src/_kernel/stamper.ts` lines 80-100):
/// `base64url( JSON.stringify({ publicKey, scheme: "SIGNATURE_SCHEME_TK_API_P256", signature }) )`
/// where `publicKey` is the compressed public key hex, `signature` is the lowercase DER hex
/// ECDSA-SHA256 signature over the UTF-8 payload, and base64url is unpadded.
///
/// The constructor checks that the public key matches the private key, as sdk-js
/// `purejs.ts` (lines 10-19) does.
public struct ApiKeyStamper: Stamper {
    public static let scheme = "SIGNATURE_SCHEME_TK_API_P256"

    public let apiPublicKey: String
    private let signer: @Sendable (Data) throws -> Data

    public init(apiPublicKey: String, apiPrivateKey: String) throws {
        let raw = try Hex.decode(apiPrivateKey, length: 32)
        guard let key = try? P256.Signing.PrivateKey(rawRepresentation: raw) else {
            throw ZeroXKeyStamperError.invalidPrivateKey
        }
        let derived = Hex.encode(key.publicKey.compressedRepresentation)
        guard derived == apiPublicKey else {
            throw ZeroXKeyStamperError.publicKeyMismatch(expected: apiPublicKey, derived: derived)
        }
        self.init(apiPublicKey: apiPublicKey) { message in
            try P256Signer.signDER(message: message, privateKey: raw)
        }
    }

    /// Stamper backed by a custom signer, e.g. a Secure Enclave key whose private
    /// scalar is not exportable.
    ///
    /// - Parameters:
    ///   - apiPublicKey: compressed P-256 public key hex (33 bytes) sent in the stamp.
    ///   - signer: receives the **raw message bytes** (the UTF-8 request body) and returns an
    ///     ECDSA P-256 signature in **DER**. The caller is responsible for the SHA-256 hashing
    ///     and for low-S normalization (see `P256Signer.signDER`); the stamper does neither,
    ///     and it does not verify that the signature matches `apiPublicKey`.
    public init(apiPublicKey: String, signer: @escaping @Sendable (Data) throws -> Data) {
        self.apiPublicKey = apiPublicKey
        self.signer = signer
    }

    /// Package-scoped: lets tests inject a fixed DER signature to compare stamp
    /// assembly byte-for-byte with sdk-js (whose RFC 6979 signatures CryptoKit cannot reproduce).
    /// `privateKey` is ignored; the parameter is kept so existing call sites compile.
    package init(apiPublicKey: String, privateKey: Data, signer: @escaping @Sendable (Data) throws -> Data) {
        self.init(apiPublicKey: apiPublicKey, signer: signer)
    }

    public func stamp(payload: String) async throws -> Stamp {
        try stampSync(payload: payload)
    }

    /// Synchronous variant of `stamp(payload:)`.
    public func stampSync(payload: String) throws -> Stamp {
        let signature = try Hex.encode(signer(Data(payload.utf8)))
        let json = OrderedJSON.stringify([
            ("publicKey", apiPublicKey),
            ("scheme", Self.scheme),
            ("signature", signature),
        ])
        return Stamp(stampHeaderName: StampHeader.apiKey, stampHeaderValue: Base64URL.encode(string: json))
    }

    /// Signs `payload` and returns the signature as hex in the requested format
    /// (sdk-js `ApiKeyStamper.sign`).
    public func sign(payload: String, format: SignatureFormat) throws -> String {
        Hex.encode(try sign(data: Data(payload.utf8), format: format))
    }

    /// Signs raw bytes (ECDSA P-256 over SHA-256, low-S); returns DER or 64-byte r‖s.
    public func sign(data: Data, format: SignatureFormat) throws -> Data {
        let der = try signer(data)
        switch format {
        case .der: return der
        case .raw: return try ECDSASignatureCodec.fromDER(der)
        }
    }
}
