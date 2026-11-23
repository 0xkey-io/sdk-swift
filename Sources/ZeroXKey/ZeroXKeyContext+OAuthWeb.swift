import CryptoKit
import Foundation
import ZeroXKeyEncoding
import ZeroXKeyHttp

/// In-app browser OAuth providers (`ASWebAuthenticationSession`).
///
/// - **Google, default: 0xkey's hosted pages.** The session opens the hosted origin page
///   (`https://oauth-origin.0xkey.io`), which forwards to Google with a *web* client ID; Google returns
///   to the hosted redirect page (`https://oauth-redirect.0xkey.io/?scheme=<appScheme>`), which hands
///   the ID token back to `<appScheme>://?id_token=…&state=…`. The same page and contract as sdk-kotlin
///   and sdk-js. The web client ID is `ZeroXKeyConfig.OAuthConfig.googleWebClientId`, else the
///   Dashboard's `oauthClientIds.google`.
/// - **Google, explicit `client:` only: installed-app PKCE.** Authorization Code + PKCE (RFC 7636 S256)
///   straight against Google with an *iOS* `OAuthClient` and a custom-scheme redirect, code exchanged at
///   Google's token endpoint (no secret). No hosted page is involved.
/// - **Discord / X:** always installed-app Authorization Code + PKCE with a custom-scheme redirect
///   registered by the app; the code is exchanged through the Auth Proxy.
///
/// Sources:
/// - Google hosted page, sdk-kotlin `packages/sdk-kotlin/src/main/kotlin/io/zeroxkey/core/ZeroXKeyContext.kt:1773-1811`
///   (origin URL parameters `provider`, `clientId`, `redirectUri`, `nonce`; `id_token` in the redirect),
///   sdk-kotlin `packages/sdk-kotlin/src/main/kotlin/io/zeroxkey/core/models/Constants.kt:21-25` (page URLs) and
///   sdk-kotlin `packages/sdk-kotlin/src/main/kotlin/io/zeroxkey/core/internal/utils/OAuthRelay.kt:7-17`
///   (default redirect `https://oauth-redirect.0xkey.io/?scheme=<appScheme>`).
/// - Google hosted page, sdk-js react-native-wallet-kit: `packages/react-native-wallet-kit/src/utils/oauth.ts:52-96`
///   (`state`), `:494-539` (origin URL), `:589-629` (callback checks: no `error`, one matching `state`,
///   `id_token`); `packages/react-native-wallet-kit/src/utils/oauth-routing.ts:57-109, 223-262, 349-380`
///   (app scheme rules, `scheme` parameter of the redirect, callback route);
///   `packages/react-native-wallet-kit/src/utils/oauth-provider-settings.ts:156-238` (client ID and redirect precedence).
/// - Google PKCE (react-native-wallet-kit `native/google-ios.ts`, `native/google-ios-system.ts`): code + PKCE +
///   `nonce`, exchanged directly at Google's token endpoint (public iOS client, no secret).
/// - Discord / X: `utils/oauth.ts:125-170, 494-559` (authorize URLs, scopes, PKCE) and
///   `utils/oauth-provider-flow.ts:305-323` — code exchanged through Auth Proxy
///   `oauth2_authenticate` with the verifier and nonce.
/// - PKCE callback checks: `native/google-ios.ts:42-72` — exact redirect base, no fragment, no `error`,
///   exactly one `state` (must match) and one `code`.
public enum OAuthWebProvider: String, Sendable, CaseIterable {
    case google, discord, x

    /// `providerName` passed to sign-up (sdk-types `OAuthProviders`).
    public var providerName: String { rawValue }

    var authorizationURL: URL {
        switch self {
        case .google: URL(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        case .discord: URL(string: "https://discord.com/oauth2/authorize")!
        case .x: URL(string: "https://x.com/i/oauth2/authorize")!
        }
    }

    var scope: String {
        switch self {
        case .google: "openid email profile"
        case .discord: "identify email"
        case .x: "tweet.read users.read"
        }
    }

    /// Whether the Dashboard's `oauthClientIds[provider]` may stand in for a missing local client.
    /// Yes for every provider, but what it stands in for differs:
    ///
    /// Discord and X: an `OAuthClient` (the Dashboard's client ID with the Dashboard's custom-scheme
    /// redirect URL). Their code is exchanged by the Auth Proxy (`oauth2_authenticate`), which takes the
    /// client ID as given, and their OAuth 2 clients accept a custom-scheme redirect with PKCE.
    ///
    /// Google: the *web* client ID of the hosted flow (`ZeroXKeyRuntimeConfig.OAuth.googleWebClientId`;
    /// sdk-js calls it `webClientId`), which is what 0xkey's hosted origin page expects
    /// (sdk-js `oauth-provider-settings.ts:156-185`). It is never used for the installed-app PKCE path:
    /// Google rejects a web client ID with a custom-scheme redirect and no secret, so that path only
    /// runs with an explicit iOS `client:`.
    var usesRemoteClientId: Bool { true }

    var oauth2Provider: v1Oauth2Provider? {
        switch self {
        case .google: nil
        case .discord: .OAUTH2_PROVIDER_DISCORD
        case .x: .OAUTH2_PROVIDER_X
        }
    }
}

/// An OAuth client registered with a provider for this app.
public struct OAuthClient: Sendable, Equatable {
    public var clientId: String
    /// Must use a custom URL scheme the app owns, e.g.
    /// `com.googleusercontent.apps.<id>:/oauth2redirect` (Google iOS client) or `myapp://oauth`.
    /// An `OAuthClient` always means a direct (PKCE) flow: passing one as `client:` to a Google call
    /// opts out of the hosted page.
    public var redirectUri: String

    public init(clientId: String, redirectUri: String) {
        self.clientId = clientId
        self.redirectUri = redirectUri
    }
}

/// Opens an authorization URL and returns the callback URL (ASWebAuthenticationSession in
/// apps, a stub in tests). Throw `ZeroXKeyOAuthError.canceled` when the user dismisses it.
public protocol WebAuthenticator: Sendable {
    func authenticate(url: URL, callbackURLScheme: String) async throws -> URL
}

public enum ZeroXKeyOAuthError: Error, Sendable, Equatable {
    case canceled
    /// No client for the provider: not passed and not in `config.auth.oauth`, and the Auth Proxy
    /// wallet-kit config has no usable entry or could not be read. For Discord and X the entry is an
    /// `oauthClientIds` ID together with an `oauthRedirectUrl`; for Google's hosted flow it is
    /// `oauthClientIds.google` (the web client ID; no redirect URL needed). See
    /// `OAuthWebProvider.usesRemoteClientId`.
    case missingClient(OAuthWebProvider)
    /// The redirect URI cannot be used: for the custom-scheme flows it is not a custom scheme; for the
    /// hosted Google flow it is not an `https` URL, or its `scheme` parameter disagrees with
    /// `OAuthConfig.appScheme`, or `appScheme` itself is not a usable URL scheme.
    case invalidRedirectUri(String)
    /// The hosted Google flow needs `ZeroXKeyConfig.OAuthConfig.appScheme`, the app's custom URL scheme
    /// that the hosted redirect page returns to (sdk-kotlin `appScheme`, sdk-js `auth.oauth.appScheme`).
    case missingAppScheme
    /// `OAuthConfig.originUri` is not a plain `https` URL (no query, fragment or user info).
    case invalidOriginUri(String)
    /// Callback URL failed validation (wrong base, `error` param, state mismatch, missing code, or for
    /// the hosted Google flow a missing or malformed `id_token`).
    case invalidCallback(String)
    case tokenExchangeFailed(String)
}

/// Result of the browser + code-exchange part of an OAuth flow, before 0xkey login.
public struct OAuthSuccess: Sendable, Equatable {
    public let oidcToken: String
    public let providerName: String
    /// Session public key the token's nonce is bound to.
    public let publicKey: String

    /// Package-level: apps only receive it.
    package init(oidcToken: String, providerName: String, publicKey: String) {
        self.oidcToken = oidcToken
        self.providerName = providerName
        self.publicKey = publicKey
    }
}

/// PKCE + state values for one authorization attempt.
package struct PKCEAttempt: Sendable, Equatable {
    package let verifier: String
    package let challenge: String
    package let state: String

    /// verifier = base64url(32 random bytes); challenge = base64url(SHA-256(ASCII verifier));
    /// state = base64url(16 random bytes) (sdk-js `checkedEntropy`, `generateChallengePair`).
    package init(randomBytes: (Int) -> Data) {
        verifier = Base64URL.encode(randomBytes(32))
        challenge = Self.challenge(for: verifier)
        state = Base64URL.encode(randomBytes(16))
    }

    package static func challenge(for verifier: String) -> String {
        Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8))))
    }
}

extension ZeroXKeyContext {
    /// Google's token endpoint (installed-app code exchange).
    nonisolated static let googleTokenURL = URL(string: "https://oauth2.googleapis.com/token")!

    /// Runs the browser part of an OAuth flow and returns the OIDC token bound to a new session
    /// key. Call `completeOAuth(oidcToken:publicKey:)` with
    /// the result, or use `handleOAuth` to do both.
    ///
    /// Which flow runs:
    /// - **Google without `client:`** (the default): 0xkey's hosted pages with a Google web client ID
    ///   (`config.auth.oauth.googleWebClientId`, else the Dashboard's `oauthClientIds.google`; neither:
    ///   `ZeroXKeyOAuthError.missingClient(.google)`). Needs `config.auth.oauth.appScheme`
    ///   (`ZeroXKeyOAuthError.missingAppScheme`). `authenticator` is asked to open the hosted origin page and
    ///   to end on `<appScheme>://`.
    /// - **Google with `client:`**: installed-app code + PKCE against Google with that iOS client; the hosted
    ///   page is not used. This is the only way to select it.
    /// - **Discord, X**: installed-app code + PKCE with `client:`, else the configured client, else the
    ///   Dashboard's.
    public func authorizeOAuth(
        _ provider: OAuthWebProvider, client: OAuthClient? = nil, authenticator: any WebAuthenticator
    ) async throws -> OAuthSuccess {
        if provider == .google, client == nil {
            return try await authorizeHostedGoogleOAuth(webClientId: nil, authenticator: authenticator)
        }
        let client = try await resolveOAuthClient(provider, explicit: client)
        guard let redirect = URL(string: client.redirectUri), let scheme = redirect.scheme, !scheme.isEmpty,
              scheme != "https", scheme != "http" else {
            throw ZeroXKeyOAuthError.invalidRedirectUri(client.redirectUri)
        }
        let publicKey = try createKeyPair()
        do {
            let nonce = Self.oidcNonce(forPublicKey: publicKey)
            let attempt = PKCEAttempt(randomBytes: oauthRandomBytes)
            let url = Self.authorizationURL(provider, client: client, attempt: attempt, nonce: nonce)
            let callback = try await authenticator.authenticate(url: url, callbackURLScheme: scheme)
            let code = try Self.authorizationCode(from: callback, redirectUri: client.redirectUri, state: attempt.state)
            let token: String
            if let p2 = provider.oauth2Provider {
                token = try await proxyClient().proxyOAuth2Authenticate(ProxyTOAuth2AuthenticateBody(
                    provider: p2, authCode: code, redirectUri: client.redirectUri, codeVerifier: attempt.verifier,
                    clientId: client.clientId, nonce: nonce)).oidcToken
            } else {
                token = try await Self.exchangeGoogleCode(code, client: client, verifier: attempt.verifier,
                                                          session: config.urlSession, tokenURL: googleTokenURL)
            }
            guard !token.isEmpty, token.trimmingCharacters(in: .whitespacesAndNewlines) == token else {
                throw ZeroXKeyOAuthError.tokenExchangeFailed("empty or malformed id token")
            }
            return OAuthSuccess(oidcToken: token, providerName: provider.providerName, publicKey: publicKey)
        } catch {
            try? config.keyManager.deleteKeyPair(publicKey: publicKey)
            throw error
        }
    }

    /// Browser OAuth followed by `completeOAuth` (login, or sign-up for a new subject). Google runs
    /// through the hosted pages unless `client:` is given; see `authorizeOAuth(_:client:authenticator:)`.
    public func handleOAuth(
        _ provider: OAuthWebProvider, client: OAuthClient? = nil, authenticator: any WebAuthenticator,
        createSubOrgParams: CreateSubOrgParams? = nil, sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> AuthResult {
        let success = try await authorizeOAuth(provider, client: client, authenticator: authenticator)
        do {
            return try await completeOAuth(oidcToken: success.oidcToken, publicKey: success.publicKey,
                                           providerName: success.providerName, createSubOrgParams: createSubOrgParams,
                                           sessionKey: sessionKey)
        } catch {
            try? config.keyManager.deleteKeyPair(publicKey: success.publicKey)
            throw error
        }
    }

    // MARK: Google through 0xkey's hosted pages

    /// Hosted origin page (sdk-kotlin `packages/sdk-kotlin/src/main/kotlin/io/zeroxkey/core/models/Constants.kt:21-22`;
    /// sdk-js `packages/react-native-wallet-kit/src/utils/oauth.ts:24`).
    package nonisolated static let hostedOAuthOriginURL = "https://oauth-origin.0xkey.io"
    /// Hosted redirect page (sdk-kotlin `packages/sdk-kotlin/src/main/kotlin/io/zeroxkey/core/models/Constants.kt:24-25`;
    /// sdk-js `packages/react-native-wallet-kit/src/utils/oauth.ts:25`).
    package nonisolated static let hostedOAuthRedirectURL = "https://oauth-redirect.0xkey.io/"

    /// Everything the hosted Google flow needs, resolved from the call and the configuration.
    package struct HostedGoogleOAuthSettings: Sendable, Equatable {
        /// Google *web* client ID.
        package let clientId: String
        /// The app's custom URL scheme, without `://`.
        package let appScheme: String
        /// `redirectUri` sent to the origin page: an `https` URL carrying `scheme=<appScheme>`.
        package let redirectUri: String
        /// The origin page (no query).
        package let originUri: String

        package init(clientId: String, appScheme: String, redirectUri: String, originUri: String) {
            self.clientId = clientId
            self.appScheme = appScheme
            self.redirectUri = redirectUri
            self.originUri = originUri
        }
    }

    /// Google sign-in through 0xkey's hosted pages (the default for Google).
    ///
    /// 1. A key pair is created; the nonce is `oidcNonce(forPublicKey:)`, the same value sdk-kotlin
    ///    (`Helpers.sha256Hex(publicKey)`) and sdk-js (`bytesToHex(sha256(publicKey))`) put into the
    ///    request, so the ID token's `nonce` claim is bound to the session key.
    /// 2. `authenticator` opens `<origin>/?provider=google&clientId=…&redirectUri=…&nonce=…&state=…`; the
    ///    hosted page forwards to Google (implicit `id_token` response with the web client), Google
    ///    returns to `redirectUri` (the hosted redirect page) and that page redirects to
    ///    `<appScheme>://?id_token=…&state=…` (or `?error=…`).
    /// 3. The callback is checked (`hostedIdToken(from:appScheme:state:)`) and the `id_token` returned.
    ///
    /// - Parameters:
    ///   - webClientId: overrides the configured / Dashboard web client ID for this call
    ///     (the `clientId:` argument of `handleGoogleOAuth`).
    ///   - appScheme: overrides `config.auth.oauth.appScheme`.
    ///   - redirectUri: overrides `config.auth.oauth.redirectUri` (same).
    package func authorizeHostedGoogleOAuth(
        webClientId: String?, appScheme: String? = nil, redirectUri: String? = nil,
        authenticator: any WebAuthenticator
    ) async throws -> OAuthSuccess {
        let settings = try await resolveHostedGoogleSettings(
            webClientId: webClientId, appScheme: appScheme, redirectUri: redirectUri)
        let publicKey = try createKeyPair()
        do {
            let nonce = Self.oidcNonce(forPublicKey: publicKey)
            let state = Self.hostedOAuthState(publicKey: publicKey, transactionId: Hex.encode(oauthRandomBytes(16)))
            let url = Self.hostedGoogleURL(settings, nonce: nonce, state: state)
            let callback = try await authenticator.authenticate(url: url, callbackURLScheme: settings.appScheme)
            let token = try Self.hostedIdToken(from: callback, appScheme: settings.appScheme, state: state)
            return OAuthSuccess(oidcToken: token, providerName: OAuthWebProvider.google.providerName, publicKey: publicKey)
        } catch {
            try? config.keyManager.deleteKeyPair(publicKey: publicKey)
            throw error
        }
    }

    /// Client ID, app scheme, redirect and origin of one hosted Google flow.
    ///
    /// Web client ID: `webClientId` (call), then `config.auth.oauth.googleWebClientId`, then the
    /// Dashboard's `oauthClientIds.google`; none: `missingClient(.google)` (checked first, before the
    /// app scheme). The Dashboard is only read when needed.
    ///
    /// Redirect (sdk-js `oauth-provider-settings.ts:204-229`, `oauth-routing.ts:223-252`; sdk-kotlin
    /// `OAuthRelay.kt:15-17`): `config.auth.oauth.redirectUri`, else the Dashboard's `oauthRedirectUrl` if it
    /// is an `https` URL (a custom-scheme one is meant for Discord and X and is skipped), else
    /// `https://oauth-redirect.0xkey.io/`; `scheme=<appScheme>` is appended unless present.
    package func resolveHostedGoogleSettings(
        webClientId: String?, appScheme: String? = nil, redirectUri: String? = nil
    ) async throws -> HostedGoogleOAuthSettings {
        let oauth = config.auth.oauth
        var candidate = webClientId.trimmedNonEmpty ?? oauth?.googleWebClientId.trimmedNonEmpty
        var redirect = redirectUri.trimmedNonEmpty ?? oauth?.redirectUri.trimmedNonEmpty
        if candidate == nil || redirect == nil {
            let remote = await loadRuntimeConfig().auth.oauth
            if candidate == nil, OAuthWebProvider.google.usesRemoteClientId { candidate = remote.googleWebClientId }
            if redirect == nil, let r = remote.redirectUrl.trimmedNonEmpty, Self.isPlainHTTPS(r) { redirect = r }
        }
        guard let clientId = candidate else { throw ZeroXKeyOAuthError.missingClient(.google) }
        let scheme = try Self.validatedAppScheme(appScheme.trimmedNonEmpty ?? oauth?.appScheme)
        return HostedGoogleOAuthSettings(
            clientId: clientId, appScheme: scheme,
            redirectUri: try Self.hostedRedirectUri(configured: redirect, appScheme: scheme),
            originUri: try Self.hostedOriginUri(oauth?.originUri))
    }

    /// The app scheme the hosted redirect page returns to: letters, digits, `+`, `.`, `-`, starting with
    /// a letter, and not a web or system scheme (sdk-js `oauth-routing.ts:57-68, 104-109`).
    package nonisolated static func validatedAppScheme(_ raw: String?) throws -> String {
        guard let scheme = raw.trimmedNonEmpty else { throw ZeroXKeyOAuthError.missingAppScheme }
        let unsafe: Set<String> = ["javascript", "data", "file", "http", "https", "ftp", "about", "blob", "intent", "chrome"]
        guard scheme.range(of: "^[A-Za-z][A-Za-z0-9+.-]*$", options: .regularExpression) != nil,
              !unsafe.contains(scheme.lowercased()) else {
            throw ZeroXKeyOAuthError.invalidRedirectUri("\(scheme)://")
        }
        return scheme
    }

    /// The `redirectUri` sent to the origin page. `configured` (else 0xkey's hosted redirect page) must be
    /// an `https` URL without fragment or user info; `scheme=<appScheme>` is appended (`?`/`&` as needed)
    /// unless it already carries exactly one equal `scheme` parameter (sdk-js `oauth-routing.ts:230-252`).
    /// Providers match redirect URIs exactly, so the default must stay
    /// `https://oauth-redirect.0xkey.io/?scheme=<appScheme>` (sdk-kotlin `OAuthRelay.kt:10-17`).
    package nonisolated static func hostedRedirectUri(configured: String?, appScheme: String) throws -> String {
        let base = configured.trimmedNonEmpty ?? hostedOAuthRedirectURL
        guard isPlainHTTPS(base), let components = URLComponents(string: base) else {
            throw ZeroXKeyOAuthError.invalidRedirectUri(base)
        }
        let schemes = (components.queryItems ?? []).filter { $0.name == "scheme" }
        if schemes.count > 1 || (schemes.count == 1 && schemes[0].value != appScheme) {
            throw ZeroXKeyOAuthError.invalidRedirectUri(base)
        }
        if schemes.count == 1 { return base }
        let separator = !base.contains("?") ? "?" : (base.hasSuffix("?") || base.hasSuffix("&") ? "" : "&")
        return base + separator + "scheme=" + formEncode(appScheme)
    }

    /// The origin page: `configured` (else `https://oauth-origin.0xkey.io`), a plain `https` URL without
    /// query, fragment or user info, since the page receives its parameters as the only query
    /// (sdk-js `oauth-routing.ts:253-262`).
    package nonisolated static func hostedOriginUri(_ configured: String?) throws -> String {
        let origin = configured.trimmedNonEmpty ?? hostedOAuthOriginURL
        guard isPlainHTTPS(origin), !origin.contains("?") else { throw ZeroXKeyOAuthError.invalidOriginUri(origin) }
        return origin
    }

    /// `state` of the hosted flow, the shape sdk-js sends (`oauth.ts:52-96`, nonce in the query rather
    /// than the state for Google): `provider=google&flow=redirect&publicKey=<key>&transactionId=<32 hex>`.
    /// The page and Google return it unchanged; the callback is accepted only with exactly this value.
    package nonisolated static func hostedOAuthState(publicKey: String, transactionId: String) -> String {
        "provider=google&flow=redirect&publicKey=\(formEncode(publicKey))&transactionId=\(transactionId)"
    }

    /// The URL `authenticator` opens, query in sdk-js order (`oauth.ts:527-538`):
    /// `provider=google&clientId=…&redirectUri=…&nonce=…&state=…`, every value percent-encoded; the path of
    /// the origin is at least `/` (as sdk-js's `URL` renders it).
    package nonisolated static func hostedGoogleURL(_ s: HostedGoogleOAuthSettings, nonce: String, state: String) -> URL {
        var c = URLComponents(string: s.originUri)!
        if c.path.isEmpty { c.path = "/" }
        c.percentEncodedQuery = [
            ("provider", OAuthWebProvider.google.providerName), ("clientId", s.clientId),
            ("redirectUri", s.redirectUri), ("nonce", nonce), ("state", state),
        ].map { "\($0.0)=\(formEncode($0.1))" }.joined(separator: "&")
        return c.url!
    }

    /// Validates the callback of the hosted flow and returns its `id_token`
    /// (sdk-js `oauth.ts:589-629`, `oauth-routing.ts:349-380`, `extractOAuthTransactionCallback`;
    /// sdk-kotlin `ZeroXKeyContext.kt:1810-1811`). Accepted: scheme equal to `appScheme`, no host, port or
    /// user info, empty path (`<appScheme>://?…`; one trailing `/` is tolerated), no `state`/`code`/
    /// `id_token`/`error` in a fragment, no `error`, exactly one `state` equal to `state`, exactly one
    /// non-empty `id_token` without whitespace (at most 65 536 bytes, sdk-js `oauth-native-flow.ts`).
    /// `error=access_denied` is the user dismissing the consent screen: `ZeroXKeyOAuthError.canceled`; any
    /// other `error` is `invalidCallback("provider error …")`.
    package nonisolated static func hostedIdToken(from callback: URL, appScheme: String, state: String) throws -> String {
        guard let c = URLComponents(url: callback, resolvingAgainstBaseURL: false) else {
            throw ZeroXKeyOAuthError.invalidCallback("unparseable URL")
        }
        guard c.scheme?.lowercased() == appScheme.lowercased(), (c.host ?? "").isEmpty, c.port == nil,
              c.user == nil, c.password == nil, c.path.isEmpty || c.path == "/" else {
            throw ZeroXKeyOAuthError.invalidCallback("redirect base mismatch")
        }
        let securityFields: Set<String> = ["state", "code", "id_token", "error"]
        if let fragment = c.percentEncodedFragment {
            let names = fragment.split(separator: "&").map { pair -> String in
                let name = String(pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)[0])
                return name.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? name
            }
            if names.contains(where: { securityFields.contains($0) }) { throw ZeroXKeyOAuthError.invalidCallback("unexpected fragment") }
        }
        let items = c.queryItems ?? []
        func values(_ name: String) -> [String] { items.filter { $0.name == name }.map { $0.value ?? "" } }
        let errors = values("error")
        if !errors.isEmpty {
            if errors == ["access_denied"] { throw ZeroXKeyOAuthError.canceled }
            throw ZeroXKeyOAuthError.invalidCallback("provider error \(errors[0])")
        }
        let states = values("state")
        guard states.count == 1, states[0] == state else { throw ZeroXKeyOAuthError.invalidCallback("state mismatch") }
        let tokens = values("id_token")
        guard tokens.count == 1, !tokens[0].isEmpty else { throw ZeroXKeyOAuthError.invalidCallback("missing id_token") }
        let token = tokens[0]
        guard token.rangeOfCharacter(from: .whitespacesAndNewlines) == nil, token.utf8.count <= 65_536 else {
            throw ZeroXKeyOAuthError.invalidCallback("malformed id_token")
        }
        return token
    }

    /// `https` URL with a host, no fragment, no user info, no whitespace or control characters.
    nonisolated static func isPlainHTTPS(_ string: String) -> Bool {
        guard string.rangeOfCharacter(from: CharacterSet.whitespacesAndNewlines.union(.controlCharacters)) == nil,
              !string.contains("#"), !string.contains("\\"),
              let c = URLComponents(string: string), c.scheme?.lowercased() == "https",
              !(c.host ?? "").isEmpty, c.user == nil, c.password == nil else { return false }
        return true
    }

    /// Percent-encodes everything but the RFC 3986 unreserved characters (what `URLSearchParams` does,
    /// except for `~` and `*`); `URLQueryItem` would leave `&` and `=` in a value untouched.
    nonisolated static func formEncode(_ value: String) -> String {
        let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        return value.addingPercentEncoding(withAllowedCharacters: unreserved) ?? value
    }

    // MARK: Internals

    /// The client of one custom-scheme (PKCE) browser flow, in this order:
    ///
    /// 1. `explicit`, the `client:` argument of the call;
    /// 2. the local `config.auth.oauth` client of the provider (client ID and redirect URI together);
    /// 3. the Dashboard's, from `wallet_kit_config` (`oauthClientIds[provider]` with `oauthRedirectUrl`;
    ///    sdk-js `resolveOauthProviderSettings`), for Discord and X.
    ///
    /// Google without `client:` never gets here: it takes the hosted flow (`authorizeHostedGoogleOAuth`),
    /// and its web client ID is not an `OAuthClient` for this path (there is no entry for it in 2 or 3).
    ///
    /// The remote client needs both a client ID and a redirect URL: without a redirect there is no flow
    /// to start, so that case is `missingClient` too. The redirect must use a custom URL scheme the app
    /// owns (`authorizeOAuth` rejects `http(s)` with `invalidRedirectUri`), so the Dashboard's redirect
    /// URL has to be one for this to work in an app.
    func resolveOAuthClient(_ provider: OAuthWebProvider, explicit: OAuthClient?) async throws -> OAuthClient {
        if let explicit { return explicit }
        if let configured = config.auth.oauth?.client(for: provider) { return configured }
        if provider.usesRemoteClientId, let remote = await loadRuntimeConfig().auth.oauth.clients[provider] {
            return remote
        }
        throw ZeroXKeyOAuthError.missingClient(provider)
    }

    nonisolated static func authorizationURL(
        _ provider: OAuthWebProvider, client: OAuthClient, attempt: PKCEAttempt, nonce: String
    ) -> URL {
        var c = URLComponents(url: provider.authorizationURL, resolvingAgainstBaseURL: false)!
        var items = [
            URLQueryItem(name: "client_id", value: client.clientId),
            URLQueryItem(name: "redirect_uri", value: client.redirectUri),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: provider.scope),
            URLQueryItem(name: "state", value: attempt.state),
            URLQueryItem(name: "code_challenge", value: attempt.challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]
        // Google binds the nonce in the ID token; Discord/X get it at the Auth Proxy exchange.
        if provider == .google { items.append(URLQueryItem(name: "nonce", value: nonce)) }
        c.queryItems = items
        // `+` must be escaped or providers read it as a space.
        c.percentEncodedQuery = c.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B")
        return c.url!
    }

    /// Validates the callback (sdk-js google-ios.ts:42-72) and returns the authorization code.
    nonisolated static func authorizationCode(from callback: URL, redirectUri: String, state: String) throws -> String {
        guard let c = URLComponents(url: callback, resolvingAgainstBaseURL: false) else {
            throw ZeroXKeyOAuthError.invalidCallback("unparseable URL")
        }
        var base = c
        base.query = nil
        base.fragment = nil
        guard base.string == redirectUri else { throw ZeroXKeyOAuthError.invalidCallback("redirect base mismatch") }
        guard c.fragment == nil else { throw ZeroXKeyOAuthError.invalidCallback("unexpected fragment") }
        let items = c.queryItems ?? []
        if let err = items.first(where: { $0.name == "error" }) {
            if err.value == "access_denied" { throw ZeroXKeyOAuthError.canceled }
            throw ZeroXKeyOAuthError.invalidCallback("provider error \(err.value ?? "")")
        }
        let states = items.filter { $0.name == "state" }.compactMap(\.value)
        guard states.count == 1, states[0] == state else { throw ZeroXKeyOAuthError.invalidCallback("state mismatch") }
        let codes = items.filter { $0.name == "code" }.compactMap(\.value)
        guard codes.count == 1, !codes[0].isEmpty else { throw ZeroXKeyOAuthError.invalidCallback("missing code") }
        return codes[0]
    }

    nonisolated static func exchangeGoogleCode(
        _ code: String, client: OAuthClient, verifier: String, session: URLSession, tokenURL: URL = googleTokenURL
    ) async throws -> String {
        var form = URLComponents()
        form.queryItems = [
            URLQueryItem(name: "client_id", value: client.clientId),
            URLQueryItem(name: "redirect_uri", value: client.redirectUri),
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "code_verifier", value: verifier),
            URLQueryItem(name: "grant_type", value: "authorization_code"),
        ]
        var req = URLRequest(url: tokenURL)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.httpBody = Data((form.percentEncodedQuery ?? "").replacingOccurrences(of: "+", with: "%2B").utf8)
        let (data, response) = try await session.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw ZeroXKeyOAuthError.tokenExchangeFailed("HTTP \(status)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = json["id_token"] as? String else {
            throw ZeroXKeyOAuthError.tokenExchangeFailed("no id_token")
        }
        return token
    }
}

extension Optional where Wrapped == String {
    /// The string without surrounding whitespace; `nil` when absent or blank.
    var trimmedNonEmpty: String? {
        guard let trimmed = self?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        return trimmed
    }
}
