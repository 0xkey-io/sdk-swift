import AuthenticationServices
import Foundation
import ZeroXKeyPasskeys
import ZeroXKeyStamper

/// Native Sign in with Apple ID-token provider (`ASAuthorizationAppleIDProvider`).
/// The nonce passed by `handleAppleOAuth` (`oidcNonce(forPublicKey:)`) is set on the request
/// verbatim, so Apple echoes it in the ID token's `nonce` claim, which 0xkey checks against the
/// session public key. Requires the "Sign in with Apple" capability.
public struct AppleIDTokenProvider: OIDCTokenProvider {
    public let anchor: PresentationAnchorProvider
    public let scopes: [ASAuthorization.Scope]

    public init(scopes: [ASAuthorization.Scope] = [.email], anchor: @escaping PresentationAnchorProvider) {
        self.anchor = anchor
        self.scopes = scopes
    }

    public func idToken(nonce: String) async throws -> String {
        let scopes = self.scopes
        return try await AuthorizationRunner.run(preferImmediatelyAvailable: false, build: { [anchor] in
            let request = ASAuthorizationAppleIDProvider().createRequest()
            request.requestedScopes = scopes
            request.nonce = nonce
            return ([request], anchor())
        }, convert: { credential in
            guard let apple = credential as? ASAuthorizationAppleIDCredential,
                  let data = apple.identityToken, let token = String(data: data, encoding: .utf8) else {
                throw ZeroXKeyPasskeyError.unexpectedCredential
            }
            return token
        })
    }
}

/// `WebAuthenticator` backed by `ASWebAuthenticationSession` (shares the system browser's
/// cookies unless `ephemeral` is set).
public struct ASWebAuthenticator: WebAuthenticator {
    public let anchor: PresentationAnchorProvider
    public let ephemeral: Bool

    public init(ephemeral: Bool = false, anchor: @escaping PresentationAnchorProvider) {
        self.anchor = anchor
        self.ephemeral = ephemeral
    }

    public func authenticate(url: URL, callbackURLScheme: String) async throws -> URL {
        try await WebAuthRunner.run(url: url, scheme: callbackURLScheme, ephemeral: ephemeral, anchor: anchor)
    }
}

@MainActor
final class WebAuthRunner: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let anchorWindow: ASPresentationAnchor
    private var session: ASWebAuthenticationSession?

    private init(anchor: ASPresentationAnchor) { anchorWindow = anchor }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { anchorWindow }

    static func run(url: URL, scheme: String, ephemeral: Bool, anchor: @escaping PresentationAnchorProvider) async throws -> URL {
        let runner = WebAuthRunner(anchor: anchor())
        return try await withCheckedThrowingContinuation { cont in
            let session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme) { callback, error in
                if let callback {
                    cont.resume(returning: callback)
                } else if let e = error as? ASWebAuthenticationSessionError, e.code == .canceledLogin {
                    cont.resume(throwing: ZeroXKeyOAuthError.canceled)
                } else {
                    cont.resume(throwing: error ?? ZeroXKeyOAuthError.invalidCallback("no callback URL"))
                }
                Task { @MainActor in runner.session = nil }
            }
            session.presentationContextProvider = runner
            session.prefersEphemeralWebBrowserSession = ephemeral
            runner.session = session
            if !session.start() {
                runner.session = nil
                cont.resume(throwing: ZeroXKeyOAuthError.invalidCallback("ASWebAuthenticationSession failed to start"))
            }
        }
    }
}

/// Overloads that take an `ASPresentationAnchor` and use the platform authenticators.
extension ZeroXKeyContext {
    /// Passkey login with the platform authenticator and `config.rpId`.
    @discardableResult
    public func loginWithPasskey(
        anchor: ASPresentationAnchor, organizationId: String? = nil, expirationSeconds: String? = nil,
        sessionKey: String = ZeroXKeySessionKey.default, publicKey: String? = nil
    ) async throws -> String {
        try await withPlatformProviders(anchor).loginWithPasskey(
            organizationId: organizationId, expirationSeconds: expirationSeconds, sessionKey: sessionKey, publicKey: publicKey)
    }

    /// `signUpWithPasskey(anchor:…)` that also reports the new passkey's credential ID.
    package func signUpWithPasskeyDetailed(
        anchor: ASPresentationAnchor, passkeyDisplayName: String? = nil, createSubOrgParams: CreateSubOrgParams? = nil,
        expirationSeconds: String? = nil, sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> (session: String, credentialId: String) {
        try await withPlatformProviders(anchor).signUpWithPasskeyDetailed(
            passkeyDisplayName: passkeyDisplayName, createSubOrgParams: createSubOrgParams,
            expirationSeconds: expirationSeconds, sessionKey: sessionKey)
    }

    /// Passkey sign-up with the platform authenticator and `config.rpId`.
    @discardableResult
    public func signUpWithPasskey(
        anchor: ASPresentationAnchor, passkeyDisplayName: String? = nil, createSubOrgParams: CreateSubOrgParams? = nil,
        expirationSeconds: String? = nil, sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> String {
        try await withPlatformProviders(anchor).signUpWithPasskey(
            passkeyDisplayName: passkeyDisplayName, createSubOrgParams: createSubOrgParams,
            expirationSeconds: expirationSeconds, sessionKey: sessionKey)
    }

    /// Adds a platform passkey to the signed-in user (see `addPasskey(name:userId:organizationId:)`).
    @discardableResult
    public func addPasskey(
        anchor: ASPresentationAnchor, name: String? = nil, userId: String? = nil, organizationId: String? = nil
    ) async throws -> String {
        try await withPlatformProviders(anchor).addPasskey(name: name, userId: userId, organizationId: organizationId)
    }

    /// Native Sign in with Apple → `completeOAuth`.
    public func handleAppleOAuth(
        anchor: ASPresentationAnchor, createSubOrgParams: CreateSubOrgParams? = nil,
        sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> AuthResult {
        let box = AnchorBox(anchor)
        return try await handleAppleOAuth(
            tokenProvider: AppleIDTokenProvider(anchor: { box.anchor }), createSubOrgParams: createSubOrgParams, sessionKey: sessionKey)
    }

    /// Google sign-in in an in-app browser.
    ///
    /// **Default (`client` is `nil`): 0xkey's hosted pages.** `ASWebAuthenticationSession` opens
    /// `https://oauth-origin.0xkey.io`, which forwards to Google with a *web* client ID; the hosted
    /// redirect page `https://oauth-redirect.0xkey.io/?scheme=<appScheme>` returns the ID token to
    /// `<appScheme>://` (the same page and contract as sdk-kotlin and sdk-js). Configure
    /// `ZeroXKeyConfig.auth.oauth.appScheme` (register it as a URL type of the app) and the web client ID in
    /// `auth.oauth.googleWebClientId`, or in the Dashboard (`oauthClientIds.google`, used when the config has
    /// none). Register the redirect URI with the web client in Google Cloud. Errors: `missingClient(.google)`
    /// without any web client ID, `missingAppScheme` without `appScheme`.
    ///
    /// **Explicit `client:` (an iOS `OAuthClient` with a custom-scheme redirect): installed-app
    /// code + PKCE** straight against Google, no hosted page. This is the only way to choose PKCE.
    public func handleGoogleOAuth(
        anchor: ASPresentationAnchor, client: OAuthClient? = nil, createSubOrgParams: CreateSubOrgParams? = nil,
        sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> AuthResult {
        try await handleOAuth(.google, client: client, authenticator: webAuthenticator(anchor),
                              createSubOrgParams: createSubOrgParams, sessionKey: sessionKey)
    }

    /// Discord sign-in (code + PKCE, exchanged through Auth Proxy `oauth2_authenticate`).
    public func handleDiscordOAuth(
        anchor: ASPresentationAnchor, client: OAuthClient? = nil, createSubOrgParams: CreateSubOrgParams? = nil,
        sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> AuthResult {
        try await handleOAuth(.discord, client: client, authenticator: webAuthenticator(anchor),
                              createSubOrgParams: createSubOrgParams, sessionKey: sessionKey)
    }

    /// X sign-in (code + PKCE, exchanged through Auth Proxy `oauth2_authenticate`).
    public func handleXOAuth(
        anchor: ASPresentationAnchor, client: OAuthClient? = nil, createSubOrgParams: CreateSubOrgParams? = nil,
        sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> AuthResult {
        try await handleOAuth(.x, client: client, authenticator: webAuthenticator(anchor),
                              createSubOrgParams: createSubOrgParams, sessionKey: sessionKey)
    }

    private func webAuthenticator(_ anchor: ASPresentationAnchor) -> ASWebAuthenticator {
        let box = AnchorBox(anchor)
        return ASWebAuthenticator(anchor: { box.anchor })
    }

    /// Installs platform passkey providers bound to `anchor` (used when the config does not
    /// inject its own providers) and returns `self`.
    private func withPlatformProviders(_ anchor: ASPresentationAnchor) -> ZeroXKeyContext {
        let box = AnchorBox(anchor)
        platformPasskeyProvider = PlatformPasskeyProvider(anchor: { box.anchor })
        return self
    }
}

/// `ASPresentationAnchor` is main-actor bound; this box lets a `@Sendable` closure return it.
final class AnchorBox: @unchecked Sendable {
    private let _anchor: ASPresentationAnchor
    init(_ anchor: ASPresentationAnchor) { _anchor = anchor }
    @MainActor var anchor: ASPresentationAnchor { _anchor }
}
