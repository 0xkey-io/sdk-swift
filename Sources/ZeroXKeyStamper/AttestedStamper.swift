import Foundation
import ZeroXKeyEncoding

/// Attested stamp schemes (sdk-js `packages/attested-stamper/src/attested-stamper.ts:5-8`).
public enum AttestedScheme: String, Sendable {
    case p256OIDC = "STAMP_ATTESTED_SCHEME_P256_OIDC"
    case p256VerificationToken = "STAMP_ATTESTED_SCHEME_P256_VERIFICATION_TOKEN"
}

/// Stamps with an API key whose public key is attested by a verification token or OIDC
/// token (`X-Stamp-Attested`). Used by OTP login: `stamp_login` is authorized by the
/// verification token that binds the client key.
///
/// Wire format (attested-stamper.ts:51-82):
/// `base64url(JSON.stringify({publicKeyAttestation, scheme, publicKey, signature}))`,
/// `signature` = low-S DER hex over the UTF-8 payload.
///
/// `attestedIdentity` is the verification token (or OIDC token) itself, which is a credential:
/// `description`, `debugDescription` and reflection (`dump`) redact it.
public struct AttestedStamper: Stamper, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let attestedIdentity: String
    public let scheme: AttestedScheme
    private let apiKey: ApiKeyStamper

    public init(attestedIdentity: String, scheme: AttestedScheme = .p256VerificationToken, apiKey: ApiKeyStamper) {
        self.attestedIdentity = attestedIdentity
        self.scheme = scheme
        self.apiKey = apiKey
    }

    public var publicKey: String { apiKey.apiPublicKey }

    public var description: String {
        "AttestedStamper(scheme: \(scheme.rawValue), publicKey: \(apiKey.apiPublicKey), attestedIdentity: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["scheme": scheme.rawValue, "publicKey": apiKey.apiPublicKey, "attestedIdentity": "<redacted>"],
               displayStyle: .struct)
    }

    public func stamp(payload: String) async throws -> Stamp {
        // ApiKeyStamper already emits low-S DER (sdk-js normalizes with normalizeS()).
        let signature = try apiKey.sign(payload: payload, format: .der)
        let json = OrderedJSON.stringify([
            ("publicKeyAttestation", attestedIdentity),
            ("scheme", scheme.rawValue),
            ("publicKey", apiKey.apiPublicKey),
            ("signature", signature),
        ])
        return Stamp(stampHeaderName: StampHeader.attested, stampHeaderValue: Base64URL.encode(string: json))
    }
}
