import Foundation
import ZeroXKeyEncoding

/// Request handed to a `PasskeyRegistrationProvider` (WebAuthn `create()`).
///
/// Mirrors the options sdk-js builds in `createWebPasskey`
/// (sdk-js `packages/core/src/__stampers__/passkey/base.ts:77-141`): ES256 (-7) and
/// RS256 (-257), resident key required, user verification preferred. The RP ID is the
/// caller's value, passed through unchanged (tenant domains such as `login.example.org` work).
public struct PasskeyRegistrationRequest: Sendable, Equatable {
    public let rpId: String
    public let rpName: String
    public let challenge: Data
    public let userId: Data
    public let userName: String
    public let displayName: String

    public init(rpId: String, rpName: String, challenge: Data, userId: Data, userName: String, displayName: String) {
        self.rpId = rpId
        self.rpName = rpName
        self.challenge = challenge
        self.userId = userId
        self.userName = userName
        self.displayName = displayName
    }
}

/// Raw output of a passkey registration.
public struct PasskeyRegistration: Sendable, Equatable {
    public let credentialId: Data
    public let clientDataJSON: Data
    public let attestationObject: Data
    /// `AUTHENTICATOR_TRANSPORT_*` values (0xkey `v1AuthenticatorTransport`).
    public let transports: [String]

    public init(credentialId: Data, clientDataJSON: Data, attestationObject: Data, transports: [String]) {
        self.credentialId = credentialId
        self.clientDataJSON = clientDataJSON
        self.attestationObject = attestationObject
        self.transports = transports
    }
}

/// Abstraction over passkey creation; `ZeroXKeyPasskeys` provides the
/// AuthenticationServices implementation, tests inject a fake.
public protocol PasskeyRegistrationProvider: Sendable {
    func register(_ request: PasskeyRegistrationRequest) async throws -> PasskeyRegistration
}

/// What 0xkey's `v1AuthenticatorParamsV2` needs from a registration:
/// `challenge` is base64url of the challenge bytes; attestation fields are base64url.
public struct EncodedPasskeyRegistration: Sendable, Equatable {
    public let encodedChallenge: String
    public let credentialId: String
    public let clientDataJson: String
    public let attestationObject: String
    public let transports: [String]

    public init(request: PasskeyRegistrationRequest, registration: PasskeyRegistration) {
        encodedChallenge = Base64URL.encode(request.challenge)
        credentialId = Base64URL.encode(registration.credentialId)
        clientDataJson = Base64URL.encode(registration.clientDataJSON)
        attestationObject = Base64URL.encode(registration.attestationObject)
        transports = registration.transports
    }
}
