import AuthenticationServices
import Foundation
import ZeroXKeyStamper

/// Passkey errors from the platform authenticator.
public enum ZeroXKeyPasskeyError: Error, Sendable, Equatable {
    /// The user dismissed the sheet (`ASAuthorizationError.canceled`).
    case canceled
    /// No credential for this RP ID on the device / iCloud Keychain.
    case noCredentials
    /// The app is not associated with the RP ID (Associated Domains `webcredentials:<rpId>`
    /// missing, or the domain's `apple-app-site-association` does not list the app).
    case notAssociated(String)
    case unexpectedCredential
    case missingAttestationObject
    case failed(code: Int, message: String)
}

/// Supplies the window that hosts the passkey sheet.
public typealias PresentationAnchorProvider = @MainActor @Sendable () -> ASPresentationAnchor

/// Platform passkeys through `ASAuthorizationPlatformPublicKeyCredentialProvider`.
///
/// Behaviour follows sdk-js's React Native passkey stamper
/// (sdk-js `packages/react-native-passkey-stamper/src/index.ts:134-259`):
/// user verification "preferred", attestation "none", transports reported as
/// `AUTHENTICATOR_TRANSPORT_HYBRID`. The RP ID is the caller's value, unchanged; any domain
/// listed under the app's `webcredentials:` Associated Domains works (e.g. `wallet.example.com`,
/// `login.example.org`), subject to the 0xkey gateway's RP ID policy.
public struct PlatformPasskeyProvider: PasskeyAssertionProvider, PasskeyRegistrationProvider {
    public let anchor: PresentationAnchorProvider
    /// Prefer credentials already on the device without showing the QR/hybrid option.
    public let preferImmediatelyAvailableCredentials: Bool

    public init(preferImmediatelyAvailableCredentials: Bool = false, anchor: @escaping PresentationAnchorProvider) {
        self.anchor = anchor
        self.preferImmediatelyAvailableCredentials = preferImmediatelyAvailableCredentials
    }

    public func assert(_ request: PasskeyAssertionRequest) async throws -> PasskeyAssertion {
        try await AuthorizationRunner.run(preferImmediatelyAvailable: preferImmediatelyAvailableCredentials, build: { [anchor] in
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: request.rpId)
            let r = provider.createCredentialAssertionRequest(challenge: request.challenge)
            r.userVerificationPreference = .preferred
            r.allowedCredentials = request.allowCredentials.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
            return ([r], anchor())
        }, convert: { credential in
            guard let assertion = credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
                throw ZeroXKeyPasskeyError.unexpectedCredential
            }
            return PasskeyAssertion(
                credentialId: assertion.credentialID, authenticatorData: assertion.rawAuthenticatorData,
                clientDataJSON: assertion.rawClientDataJSON, signature: assertion.signature, userHandle: assertion.userID)
        })
    }

    public func register(_ request: PasskeyRegistrationRequest) async throws -> PasskeyRegistration {
        try await AuthorizationRunner.run(preferImmediatelyAvailable: false, build: { [anchor] in
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: request.rpId)
            let r = provider.createCredentialRegistrationRequest(
                challenge: request.challenge, name: request.userName, userID: request.userId)
            r.displayName = request.displayName
            r.userVerificationPreference = .preferred
            r.attestationPreference = .none
            return ([r], anchor())
        }, convert: { credential in
            guard let registration = credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
                throw ZeroXKeyPasskeyError.unexpectedCredential
            }
            guard let attestation = registration.rawAttestationObject else { throw ZeroXKeyPasskeyError.missingAttestationObject }
            return PasskeyRegistration(
                credentialId: registration.credentialID, clientDataJSON: registration.rawClientDataJSON,
                attestationObject: attestation, transports: Self.reportedTransports)
        })
    }

    /// sdk-js RN stamper reports `["AUTHENTICATOR_TRANSPORT_HYBRID"]` for every platform passkey.
    public static let reportedTransports = ["AUTHENTICATOR_TRANSPORT_HYBRID"]
}

/// Runs one `ASAuthorizationController` request and bridges its delegate to async/await.
@MainActor
package final class AuthorizationRunner<Output: Sendable>: NSObject, ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding {
    private var continuation: CheckedContinuation<Output, any Error>?
    private let anchor: ASPresentationAnchor
    private let convert: @MainActor (any ASAuthorizationCredential) throws -> Output
    private var keepAlive: AuthorizationRunner?

    private init(anchor: ASPresentationAnchor, convert: @escaping @MainActor (any ASAuthorizationCredential) throws -> Output) {
        self.anchor = anchor
        self.convert = convert
    }

    package static func run(
        preferImmediatelyAvailable: Bool,
        build: @MainActor () -> ([ASAuthorizationRequest], ASPresentationAnchor),
        convert: @escaping @MainActor (any ASAuthorizationCredential) throws -> Output
    ) async throws -> Output {
        let (requests, anchor) = build()
        let runner = AuthorizationRunner(anchor: anchor, convert: convert)
        let controller = ASAuthorizationController(authorizationRequests: requests)
        controller.delegate = runner
        controller.presentationContextProvider = runner
        return try await withCheckedThrowingContinuation { cont in
            runner.continuation = cont
            runner.keepAlive = runner
            #if os(iOS)
            if preferImmediatelyAvailable {
                controller.performRequests(options: .preferImmediatelyAvailableCredentials)
                return
            }
            #endif
            controller.performRequests()
        }
    }

    package func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }

    package func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        finish(Result { try convert(authorization.credential) })
    }

    package func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
        finish(.failure(PasskeyErrorMapping.map(error)))
    }

    private func finish(_ result: Result<Output, any Error>) {
        continuation?.resume(with: result)
        continuation = nil
        keepAlive = nil
    }
}

package enum PasskeyErrorMapping {
    package static func map(_ error: any Error) -> any Error {
        let ns = error as NSError
        guard ns.domain == ASAuthorizationError.errorDomain else {
            return ZeroXKeyPasskeyError.failed(code: ns.code, message: ns.localizedDescription)
        }
        switch ASAuthorizationError.Code(rawValue: ns.code) {
        case .canceled: return ZeroXKeyPasskeyError.canceled
        case .failed where ns.localizedDescription.localizedCaseInsensitiveContains("not associated"),
             .failed where (ns.userInfo[NSLocalizedFailureReasonErrorKey] as? String)?.localizedCaseInsensitiveContains("associated") == true:
            return ZeroXKeyPasskeyError.notAssociated(ns.localizedDescription)
        default:
            if ns.code == 1001 { return ZeroXKeyPasskeyError.canceled }
            return ZeroXKeyPasskeyError.failed(code: ns.code, message: ns.localizedDescription)
        }
    }
}

/// Convenience: a passkey `Stamper` backed by the platform authenticator (`Stamper` is the
/// protocol, `PasskeyStamper` the concrete type).
public struct PasskeyStamper: Stamper {
    private let inner: WebAuthnStamper

    public init(rpId: String, allowCredentials: [Data] = [], presentationAnchor: @escaping PresentationAnchorProvider) {
        inner = WebAuthnStamper(rpId: rpId, allowCredentials: allowCredentials,
                                provider: PlatformPasskeyProvider(anchor: presentationAnchor))
    }

    public var rpId: String { inner.rpId }

    public func stamp(payload: String) async throws -> Stamp {
        try await inner.stamp(payload: payload)
    }
}
