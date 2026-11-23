import Foundation
import ZeroXKeyCrypto
import ZeroXKeyHttp
import ZeroXKeyStamper

/// Configuration for `ZeroXKeyContext`: endpoints (`apiUrl`, `authProxyUrl`), `authProxyConfigId`,
/// `rpId`, `organizationId` and `auth`; the remaining members are injection points.
public struct ZeroXKeyConfig: Sendable {
    public var apiUrl: String
    public var authProxyUrl: String
    /// Auth Proxy config ID from the 0xkey dashboard. `nil` disables Auth Proxy methods
    /// (OTP, OAuth, passkey sign-up), which then throw `missingAuthProxyConfiguration`. With it,
    /// `ZeroXKeyContext.client` is an unauthenticated Auth Proxy client before login, and the
    /// Dashboard's `wallet_kit_config` is read once after `configure`.
    public var authProxyConfigId: String?
    /// Passkey relying party ID supplied by the app (e.g. `wallet.example.com`, `login.example.org`).
    /// Never defaulted to a 0xkey domain. The RP ID must also be enabled for the organization on
    /// the 0xkey side, otherwise passkey calls fail with `.webAuthnRpIdNotAllowed`.
    public var rpId: String?
    /// Relying party display name used when creating passkeys.
    public var rpName: String
    /// Parent organization ID (needed for passkey login and as the default target).
    public var organizationId: String?
    public var auth: AuthConfig
    public var activityPoller: ActivityPollerConfig
    /// Session lifetime requested by `stamp_login` (passkey login and sign-up, OTP login, refresh),
    /// seconds. Resolved like the sdk-js wallet kits resolve `auth.sessionExpirationSeconds`:
    /// the `expirationSeconds` argument of the call, else the session duration the Auth Proxy
    /// configuration prescribes (Dashboard, `wallet_kit_config`, fetched once per context, started by
    /// `configure`; only with `authProxyConfigId`), else this value, else `"900"`. So with an Auth Proxy
    /// configuration the Dashboard decides and this value only applies where it cannot be read; leave
    /// it `nil` there.
    ///
    /// At every level a value that is `nil`, empty, blank, not an integer or not greater than zero
    /// (`"0"`, `"-5"`, `"abc"`, `"1.5"`) counts as unset and the next level applies. Surrounding
    /// whitespace and a leading `+` are tolerated and removed before the value is sent.
    public var sessionExpirationSeconds: String?
    /// Lifetime used when nothing else is configured (sdk-js `DEFAULT_SESSION_EXPIRATION_IN_SECONDS`).
    public static let defaultSessionExpirationSeconds = "900"
    public var keyManager: any ZeroXKeyKeyManager
    public var sessionStore: any ZeroXKeySessionStore
    public var passkeyAssertionProvider: (any PasskeyAssertionProvider)?
    public var passkeyRegistrationProvider: (any PasskeyRegistrationProvider)?
    public var urlSession: URLSession
    /// Enclave keys that signed data from 0xkey is checked against. Default ``TrustAnchors/production``;
    /// change it only to talk to a non-production 0xkey enclave.
    public var trustAnchors: TrustAnchors = .production
    /// Schemes and hosts `apiUrl` and `authProxyUrl` may use. Default `.requireHTTPS`; a URL it refuses
    /// makes every request throw ``ZeroXKeyHttpError/insecureURL(_:)`` before anything is sent.
    /// `.dangerouslyAllowInsecureLoopback` additionally accepts `http` to `localhost`, `127.0.0.0/8`
    /// and `::1`, for a local development server only.
    public var transportSecurity: ZeroXKeyTransportSecurity = .requireHTTPS

    public init(
        apiUrl: String = ZeroXKeyClient.defaultApiBaseURL.absoluteString,
        authProxyUrl: String = ZeroXKeyClient.defaultAuthProxyBaseURL.absoluteString,
        authProxyConfigId: String? = nil,
        rpId: String? = nil,
        rpName: String = "",
        organizationId: String? = nil,
        auth: AuthConfig = AuthConfig(),
        activityPoller: ActivityPollerConfig = .init(),
        sessionExpirationSeconds: String? = nil,
        keyManager: any ZeroXKeyKeyManager = SecureEnclaveKeyManager(),
        sessionStore: any ZeroXKeySessionStore = KeychainSessionStore(),
        passkeyAssertionProvider: (any PasskeyAssertionProvider)? = nil,
        passkeyRegistrationProvider: (any PasskeyRegistrationProvider)? = nil,
        urlSession: URLSession = .shared
    ) {
        self.apiUrl = apiUrl
        self.authProxyUrl = authProxyUrl
        self.authProxyConfigId = authProxyConfigId
        self.rpId = rpId
        self.rpName = rpName
        self.organizationId = organizationId
        self.auth = auth
        self.activityPoller = activityPoller
        self.sessionExpirationSeconds = sessionExpirationSeconds
        self.keyManager = keyManager
        self.sessionStore = sessionStore
        self.passkeyAssertionProvider = passkeyAssertionProvider
        self.passkeyRegistrationProvider = passkeyRegistrationProvider
        self.urlSession = urlSession
    }

    /// Public keys of the 0xkey enclaves that the SDK verifies signed data against.
    ///
    /// With the defaults (``production``) the SDK uses ``ZeroXKeyTrustAnchors``. An override replaces
    /// the expected key; it never turns a check off.
    /// - Signer key: the OTP encryption target bundle (`verifyOtp`, `completeOtp`) and export / import
    ///   bundles when the call passes no key of its own.
    /// - Notarizer key: every session JWT before it is stored or activated (login, sign-up, refresh,
    ///   `storeSession`, `setActiveSession`, restoring the stored session at `configure`).
    public struct TrustAnchors: Sendable, Equatable {
        /// Uncompressed P-256 signing key (hex) of a non-production signer enclave. `nil`:
        /// ``ZeroXKeyTrustAnchors/productionSignerSignPublicKey``. Do not set it in production apps.
        public var dangerouslyOverrideSignerPublicKey: String?
        /// Uncompressed P-256 key (hex) of a non-production notarizer, which signs session JWTs. `nil`:
        /// ``ZeroXKeyTrustAnchors/productionNotarizerSignPublicKey``. Do not set it in production apps.
        public var dangerouslyOverrideNotarizerPublicKey: String?

        /// The 0xkey production keys.
        public static let production = TrustAnchors()

        public init(dangerouslyOverrideSignerPublicKey: String? = nil, dangerouslyOverrideNotarizerPublicKey: String? = nil) {
            self.dangerouslyOverrideSignerPublicKey = dangerouslyOverrideSignerPublicKey
            self.dangerouslyOverrideNotarizerPublicKey = dangerouslyOverrideNotarizerPublicKey
        }

        /// The signer key bundles are checked against.
        public var signerPublicKey: String {
            dangerouslyOverrideSignerPublicKey ?? ZeroXKeyTrustAnchors.productionSignerSignPublicKey
        }

        /// The notarizer key session JWTs are checked against.
        public var notarizerPublicKey: String {
            dangerouslyOverrideNotarizerPublicKey ?? ZeroXKeyTrustAnchors.productionNotarizerSignPublicKey
        }
    }

    public struct AuthConfig: Sendable {
        public var oauth: OAuthConfig?
        /// Defaults applied to sub-organizations created at sign-up.
        public var createSuborgParams: CreateSubOrgParams?

        /// Re-issue the session (`stamp_login` with a fresh key) shortly before it expires.
        /// Default `true`, as sdk-js wallet kits (`auth.autoRefreshSession ?? true`).
        public var autoRefreshSession: Bool
        /// How long before expiry the refresh runs (sdk-js `SESSION_WARNING_THRESHOLD_MS` = 60 s).
        public var sessionRefreshLeadSeconds: TimeInterval

        public init(oauth: OAuthConfig? = nil, createSuborgParams: CreateSubOrgParams? = nil,
                    autoRefreshSession: Bool = true, sessionRefreshLeadSeconds: TimeInterval = 60) {
            self.oauth = oauth
            self.createSuborgParams = createSuborgParams
            self.autoRefreshSession = autoRefreshSession
            self.sessionRefreshLeadSeconds = sessionRefreshLeadSeconds
        }
    }

    /// Settings for the in-app browser OAuth flows (`handleGoogleOAuth`, `handleDiscordOAuth`,
    /// `handleXOAuth`). Native Sign in with Apple needs none.
    ///
    /// **Google** runs through 0xkey's hosted pages by default (`oauth-origin` starts it, `oauth-redirect`
    /// hands the ID token back to `<appScheme>://`), with a Google *web* client ID, the same as sdk-kotlin
    /// and sdk-js. It needs `googleWebClientId` (else the Dashboard's `oauthClientIds.google`) and
    /// `appScheme`; `redirectUri` / `originUri` only matter for a self-hosted page. Only a call that passes
    /// an explicit `client:` (`OAuthClient`, an iOS client with a custom-scheme redirect) takes the
    /// installed-app PKCE path instead.
    ///
    /// **Discord and X** use `discord` / `x`, a custom-scheme redirect with PKCE. A provider left `nil`
    /// falls back to the Auth Proxy wallet-kit config (`oauthClientIds` with `oauthRedirectUrl`, read once
    /// at `configure`; sdk-js `resolveOauthProviderSettings`). A client set here is used as a whole,
    /// redirect URI included.
    public struct OAuthConfig: Sendable {
        /// Google *web* client ID for the hosted flow. Beats the Dashboard's `oauthClientIds.google`.
        public var googleWebClientId: String?
        public var discord: OAuthClient?
        public var x: OAuthClient?
        /// Custom URL scheme of the app, without `://` (e.g. `myapp`): the hosted redirect page returns
        /// to `<appScheme>://`. Required by the hosted Google flow (sdk-kotlin `appScheme`, sdk-js
        /// `auth.oauth.appScheme`); register it as a URL type of the app.
        public var appScheme: String?
        /// `https` redirect URI registered with Google for the hosted flow. `nil`: the Dashboard's
        /// `oauthRedirectUrl` if it is an `https` URL, else 0xkey's hosted page
        /// (`https://oauth-redirect.0xkey.io/`). `?scheme=<appScheme>` is appended when it is absent.
        public var redirectUri: String?
        /// Hosted origin page for the Google flow. `nil`: `https://oauth-origin.0xkey.io`.
        public var originUri: String?

        public init(
            googleWebClientId: String? = nil, discord: OAuthClient? = nil, x: OAuthClient? = nil,
            appScheme: String? = nil, redirectUri: String? = nil, originUri: String? = nil
        ) {
            self.googleWebClientId = googleWebClientId
            self.discord = discord
            self.x = x
            self.appScheme = appScheme
            self.redirectUri = redirectUri
            self.originUri = originUri
        }

        /// The custom-scheme client of `provider`; always `nil` for Google, whose hosted flow has no
        /// `OAuthClient` (see `googleWebClientId`).
        public func client(for provider: OAuthWebProvider) -> OAuthClient? {
            switch provider {
            case .google: nil
            case .discord: discord
            case .x: x
            }
        }
    }

    var apiBaseURL: URL {
        get throws {
            guard let u = URL(string: apiUrl) else { throw ZeroXKeyHttpError.invalidURL(apiUrl) }
            try transportSecurity.validate(u)
            return u
        }
    }

    var authProxyBaseURL: URL {
        get throws {
            guard let u = URL(string: authProxyUrl) else { throw ZeroXKeyHttpError.invalidURL(authProxyUrl) }
            try transportSecurity.validate(u)
            return u
        }
    }
}
