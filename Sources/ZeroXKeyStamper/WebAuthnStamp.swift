import CryptoKit
import Foundation
import ZeroXKeyEncoding

/// Raw output of a WebAuthn assertion, as returned by a platform authenticator.
public struct PasskeyAssertion: Sendable, Equatable {
    public let credentialId: Data
    public let authenticatorData: Data
    public let clientDataJSON: Data
    public let signature: Data
    public let userHandle: Data?

    public init(credentialId: Data, authenticatorData: Data, clientDataJSON: Data, signature: Data, userHandle: Data? = nil) {
        self.credentialId = credentialId
        self.authenticatorData = authenticatorData
        self.clientDataJSON = clientDataJSON
        self.signature = signature
        self.userHandle = userHandle
    }
}

/// Request handed to a `PasskeyAssertionProvider`.
public struct PasskeyAssertionRequest: Sendable, Equatable {
    /// Relying party ID, passed through unchanged. Tenants may use their own domain
    /// (e.g. `login.example.org`); nothing in the SDK rewrites or defaults it.
    public let rpId: String
    /// WebAuthn challenge bytes (see `WebAuthnStamp.challenge(for:)`).
    public let challenge: Data
    /// Credential IDs allowed for this assertion; empty means any discoverable credential.
    public let allowCredentials: [Data]

    public init(rpId: String, challenge: Data, allowCredentials: [Data]) {
        self.rpId = rpId
        self.challenge = challenge
        self.allowCredentials = allowCredentials
    }
}

/// Abstraction over the platform authenticator so that stamping can be unit tested.
/// `ZeroXKeyPasskeys` provides the AuthenticationServices-backed implementation.
public protocol PasskeyAssertionProvider: Sendable {
    func assert(_ request: PasskeyAssertionRequest) async throws -> PasskeyAssertion
}

/// `X-Stamp-Webauthn` encoding helpers
/// (sdk-js `packages/webauthn-stamper/src/index.ts`).
public enum WebAuthnStamp {
    /// The challenge is the UTF-8 bytes of the lowercase hex SHA-256 of the payload
    /// (`getChallengeFromPayload`, index.ts lines 68-71). The authenticator then puts
    /// `base64url(challenge)` into `clientDataJSON`; the gateway checks
    /// `base64url(hex(sha256(body)))`.
    public static func challenge(for payload: String) -> Data {
        Data(Hex.encode(Data(SHA256.hash(data: Data(payload.utf8)))).utf8)
    }

    /// The `challenge` value expected inside `clientDataJSON` for `payload`.
    public static func clientDataChallenge(for payload: String) -> String {
        Base64URL.encode(challenge(for: payload))
    }

    /// Header value: compact JSON (not base64) with base64url fields in the order
    /// `authenticatorData, clientDataJson, credentialId, signature` (index.ts lines 57-64).
    /// `credentialId` is the base64url of the raw credential ID, which equals
    /// `PublicKeyCredential.id` in browsers.
    public static func headerValue(for assertion: PasskeyAssertion) -> String {
        OrderedJSON.stringify([
            ("authenticatorData", Base64URL.encode(assertion.authenticatorData)),
            ("clientDataJson", Base64URL.encode(assertion.clientDataJSON)),
            ("credentialId", Base64URL.encode(assertion.credentialId)),
            ("signature", Base64URL.encode(assertion.signature)),
        ])
    }
}

/// Stamps requests with a passkey (`X-Stamp-Webauthn`) using an injected authenticator.
public struct WebAuthnStamper: Stamper {
    public let rpId: String
    public let allowCredentials: [Data]
    private let provider: any PasskeyAssertionProvider

    public init(rpId: String, allowCredentials: [Data] = [], provider: any PasskeyAssertionProvider) {
        self.rpId = rpId
        self.allowCredentials = allowCredentials
        self.provider = provider
    }

    public func stamp(payload: String) async throws -> Stamp {
        let request = PasskeyAssertionRequest(
            rpId: rpId, challenge: WebAuthnStamp.challenge(for: payload), allowCredentials: allowCredentials)
        let assertion = try await provider.assert(request)
        return Stamp(stampHeaderName: StampHeader.webAuthn, stampHeaderValue: WebAuthnStamp.headerValue(for: assertion))
    }
}
