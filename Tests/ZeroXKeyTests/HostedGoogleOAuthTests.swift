import CryptoKit
import Foundation
import Testing
import ZeroXKey
import ZeroXKeyEncoding
import ZeroXKeyTestSupport

// Google OAuth through 0xkey's hosted pages (the default) versus installed-app PKCE (explicit `client:`).
// Contract: sdk-kotlin `ZeroXKeyContext.handleGoogleOAuth`, sdk-js react-native-wallet-kit `buildOAuthUrl`,
// `parseInAppBrowserResult`; see the documentation of `ZeroXKeyContext.authorizeHostedGoogleOAuth`.

// MARK: - Helpers

private let webClient = "web-client.apps.googleusercontent.com"
private let iosClient = OAuthClient(clientId: "123.apps.googleusercontent.com",
                                    redirectUri: "com.googleusercontent.apps.123:/oauth2redirect")
/// `fixedRandom` bytes 0x00…0x0f as hex: the transaction ID inside `state`.
private let fixedTransactionId = "000102030405060708090a0b0c0d0e0f"

/// What the hosted redirect page sends back: `<scheme>://?state=<state>&id_token=<token>` (+ `extra`).
private func hostedCallbackURL(
    scheme: String = "exampleapp", state: String?, idToken: String? = "google.hosted.id.token", extra: String = ""
) -> URL {
    var query: [String] = []
    if let state { query.append("state=" + state.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!) }
    if let idToken { query.append("id_token=" + idToken) }
    return URL(string: "\(scheme)://?\(query.joined(separator: "&"))\(extra)")!
}

extension StubAuthenticator {
    /// Answers like the hosted redirect page: the `state` of the opened URL and an `id_token`.
    static func hosted(scheme: String = "exampleapp", idToken: String = "google.hosted.id.token") -> StubAuthenticator {
        StubAuthenticator { c in
            hostedCallbackURL(scheme: scheme, state: StubAuthenticator.param(c, "state"), idToken: idToken)
        }
    }
}

private func hex(sha256 text: String) -> String { Hex.encode(Data(SHA256.hash(data: Data(text.utf8)))) }

private func components(_ url: URL?) throws -> URLComponents {
    let url = try #require(url)
    return try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
}

@MainActor
private func hostedContext(
    _ server: MockServer,
    oauth: ZeroXKeyConfig.OAuthConfig? = ZeroXKeyConfig.OAuthConfig(googleWebClientId: webClient, appScheme: "exampleapp"),
    configId: String? = nil, keys: InMemoryKeyManager = InMemoryKeyManager()
) -> ZeroXKeyContext {
    let config = ZeroXKeyConfig(
        apiUrl: server.apiURL.absoluteString, authProxyUrl: server.authProxyURL.absoluteString,
        authProxyConfigId: configId, organizationId: "org-parent",
        auth: .init(oauth: oauth, autoRefreshSession: false), activityPoller: .init(intervalMs: 0, numRetries: 3),
        keyManager: keys, sessionStore: InMemorySessionStore(), urlSession: server.session).trustingFixtures()
    let ctx = ZeroXKeyContext(
        config: config, now: { Date(timeIntervalSince1970: 1_763_500_000) },
        notificationCenter: NotificationCenter(), foregroundNotification: nil)
    ctx.oauthRandomBytes = fixedRandom
    return ctx
}

/// `wallet_kit_config` answer with the given extra fields (`oauthClientIds`, `oauthRedirectUrl`, …).
private func kitConfig(_ extra: [String: Any] = [:]) -> MockResponse {
    var body: [String: Any] = ["enabledProviders": ["email", "google"], "organizationId": "org-parent"]
    for (k, v) in extra { body[k] = v }
    return .json(body)
}

private final class ResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T?
    var value: T? {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}

// MARK: - Hosted URL, nonce, state

@Suite("Hosted Google OAuth: request") @MainActor
struct HostedGoogleRequestTests {
    @Test func hostedPageIsOpenedWithProviderClientRedirectNonceAndState() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = hostedContext(server, keys: keys)
        let auth = StubAuthenticator.hosted(idToken: "hosted.id.token")

        let success = try await ctx.authorizeOAuth(.google, authenticator: auth)
        #expect(success.oidcToken == "hosted.id.token" && success.providerName == "google")
        #expect(try keys.listPublicKeys() == [success.publicKey])
        #expect(auth.schemes == ["exampleapp"], "the session ends on the app scheme")
        #expect(server.requests.isEmpty, "a local web client and no Auth Proxy configuration need no request")

        let url = try #require(auth.urls.first)
        let c = try components(url)
        #expect(c.scheme == "https" && c.host == "oauth-origin.0xkey.io" && c.path == "/")
        #expect(c.queryItems?.map(\.name) == ["provider", "clientId", "redirectUri", "nonce", "state"])
        #expect(StubAuthenticator.param(c, "provider") == "google")
        #expect(StubAuthenticator.param(c, "clientId") == webClient)
        #expect(StubAuthenticator.param(c, "redirectUri") == "https://oauth-redirect.0xkey.io/?scheme=exampleapp")
        #expect(StubAuthenticator.param(c, "nonce") == hex(sha256: success.publicKey))
        #expect(StubAuthenticator.param(c, "state")
                == "provider=google&flow=redirect&publicKey=\(success.publicKey)&transactionId=\(fixedTransactionId)")
        // Values are percent-encoded on the wire (including `&`, `=` inside `state`).
        #expect(url.absoluteString.hasPrefix(
            "https://oauth-origin.0xkey.io/?provider=google&clientId=web-client.apps.googleusercontent.com"
            + "&redirectUri=https%3A%2F%2Foauth-redirect.0xkey.io%2F%3Fscheme%3Dexampleapp&nonce="))
        #expect(url.absoluteString.contains("&state=provider%3Dgoogle%26flow%3Dredirect%26publicKey%3D"))
        // Not the PKCE request.
        #expect(StubAuthenticator.param(c, "code_challenge") == nil && StubAuthenticator.param(c, "client_id") == nil)
    }

    @Test func nonceIsBoundToTheSessionPublicKey() async throws {
        let server = MockServer()
        let ctx = hostedContext(server)
        var nonces: [String] = []
        var keysSeen: [String] = []
        for _ in 0..<2 {
            let auth = StubAuthenticator.hosted()
            let success = try await ctx.authorizeOAuth(.google, authenticator: auth)
            let c = try components(auth.urls.first)
            let nonce = try #require(StubAuthenticator.param(c, "nonce"))
            #expect(nonce == ZeroXKeyContext.oidcNonce(forPublicKey: success.publicKey))
            #expect(nonce == hex(sha256: success.publicKey), "lowercase hex SHA-256 of the compressed public key, as sdk-kotlin and sdk-js")
            #expect(nonce.count == 64)
            #expect(StubAuthenticator.param(c, "state")?.contains("publicKey=\(success.publicKey)&") == true)
            nonces.append(nonce)
            keysSeen.append(success.publicKey)
        }
        #expect(nonces[0] != nonces[1] && keysSeen[0] != keysSeen[1], "every attempt has its own key and nonce")
    }

    @Test func handleOAuthLogsInWithTheHostedIdToken() async throws {
        let server = MockServer()
        let ctx = hostedContext(server, configId: "cfg-hosted")
        server.on("/v1/wallet_kit_config", respond: kitConfig())
        server.on("/v1/account", respond: .json(["organizationId": "org-sub"]))
        server.on("/v1/oauth_login") { req, _ in
            .json(["session": APIFixtures.sessionJWT(publicKey: req.json["publicKey"] as! String,
                                                     organizationId: "org-sub", userId: "u", exp: 1_763_500_900)])
        }
        let auth = StubAuthenticator.hosted(idToken: "hosted.id.token")
        let result = try await ctx.handleOAuth(.google, authenticator: auth)
        #expect(result.action == .login)
        let publicKey = try #require(ctx.session?.publicKey)
        let c = try components(auth.urls.first)
        #expect(StubAuthenticator.param(c, "nonce") == hex(sha256: publicKey))
        let account = try #require(server.requests(to: "/v1/account").first)
        #expect(account.header("X-Auth-Proxy-Config-ID") == "cfg-hosted")
        #expect(account.json as? [String: String] == ["filterType": "OIDC_TOKEN", "filterValue": "hosted.id.token"])
        let login = try #require(server.requests(to: "/v1/oauth_login").first)
        #expect(login.json["oidcToken"] as? String == "hosted.id.token" && login.json["publicKey"] as? String == publicKey)
        #expect(server.requests(to: "/v1/signup").isEmpty)
    }

    @Test func handleOAuthSignsUpANewSubjectAsGoogle() async throws {
        let server = MockServer()
        let ctx = hostedContext(server, configId: "cfg-hosted")
        server.on("/v1/wallet_kit_config", respond: kitConfig())
        server.on("/v1/account", respond: .json([:]))
        server.on("/v1/signup", respond: .json(["organizationId": "org-sub", "wallet": ["walletId": "w", "addresses": []],
                                                "userId": "u", "appProofs": []]))
        server.on("/v1/oauth_login") { req, _ in
            .json(["session": APIFixtures.sessionJWT(publicKey: req.json["publicKey"] as! String,
                                                     organizationId: "org-sub", userId: "u", exp: 1_763_500_900)])
        }
        let result = try await ctx.handleOAuth(.google, authenticator: StubAuthenticator.hosted(idToken: "hosted.id.token"))
        #expect(result.action == .signup)
        let signup = try #require(server.requests(to: "/v1/signup").first?.json)
        #expect((signup["oauthProviders"] as? [[String: String]]) == [["providerName": "google", "oidcToken": "hosted.id.token"]])
    }
}

// MARK: - Client ID resolution

@Suite("Hosted Google OAuth: web client ID") @MainActor
struct HostedGoogleClientIdTests {
    func openedClientId(_ ctx: ZeroXKeyContext) async throws -> String? {
        let auth = StubAuthenticator.hosted()
        _ = try await ctx.authorizeOAuth(.google, authenticator: auth)
        return StubAuthenticator.param(try components(auth.urls.first), "clientId")
    }

    @Test func localWebClientIdBeatsTheRemoteOne() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(["oauthClientIds": ["google": "remote-web"]]))
        let ctx = hostedContext(server, oauth: .init(googleWebClientId: " local-web ", appScheme: "exampleapp"), configId: "cfg-hosted")
        #expect(try await openedClientId(ctx) == "local-web", "trimmed, and the local value wins")
    }

    @Test func remoteGoogleClientIdIsUsedWhenThereIsNoLocalOne() async throws {
        for local in [nil, "", "   "] as [String?] {
            let server = MockServer()
            server.on("/v1/wallet_kit_config", respond: kitConfig([
                "oauthClientIds": ["google": "remote-web", "discord": "d"], "oauthRedirectUrl": "exampleapp://oauth"]))
            let ctx = hostedContext(server, oauth: .init(googleWebClientId: local, appScheme: "exampleapp"), configId: "cfg-hosted")
            #expect(try await openedClientId(ctx) == "remote-web", "local: \(String(describing: local))")
            #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)
        }
    }

    @Test func missingClientWhenNeitherLocalNorRemoteHasOne() async throws {
        let noGoogle = MockServer()
        noGoogle.on("/v1/wallet_kit_config", respond: kitConfig(["oauthClientIds": ["discord": "d"]]))
        let blank = MockServer()
        blank.on("/v1/wallet_kit_config", respond: kitConfig(["oauthClientIds": ["google": ""]]))
        let failing = MockServer()
        failing.on("/v1/wallet_kit_config", respond: .text("boom", status: 500))
        let withoutProxy = MockServer()

        let table: [(String, MockServer, String?)] = [
            ("no google entry", noGoogle, "cfg"), ("blank entry", blank, "cfg"),
            ("unreadable config", failing, "cfg"), ("no auth proxy config", withoutProxy, nil),
        ]
        for (name, server, configId) in table {
            let keys = InMemoryKeyManager()
            let auth = StubAuthenticator.hosted()
            let ctx = hostedContext(server, oauth: .init(appScheme: "exampleapp"), configId: configId, keys: keys)
            await #expect(throws: ZeroXKeyOAuthError.missingClient(.google), "\(name)") {
                try await ctx.authorizeOAuth(.google, authenticator: auth)
            }
            #expect(auth.urls.isEmpty, "\(name): nothing is opened")
            #expect(try keys.listPublicKeys().isEmpty, "\(name): no session key is created")
        }
        #expect(withoutProxy.requests.isEmpty)
        // No oauth configuration at all: the missing client is still reported first (before the app scheme).
        let bare = hostedContext(MockServer(), oauth: nil)
        await #expect(throws: ZeroXKeyOAuthError.missingClient(.google)) {
            try await bare.authorizeOAuth(.google, authenticator: StubAuthenticator.hosted())
        }
    }

    @Test func theAppSchemeIsRequiredAndMustBeUsable() async throws {
        let cases: [(String?, ZeroXKeyOAuthError)] = [
            (nil, .missingAppScheme), ("  ", .missingAppScheme),
            ("https", .invalidRedirectUri("https://")), ("javascript", .invalidRedirectUri("javascript://")),
            ("1app", .invalidRedirectUri("1app://")), ("my app", .invalidRedirectUri("my app://")),
            ("myapp://", .invalidRedirectUri("myapp://://")),
        ]
        for (scheme, expected) in cases {
            let keys = InMemoryKeyManager()
            let auth = StubAuthenticator.hosted()
            let ctx = hostedContext(MockServer(), oauth: .init(googleWebClientId: webClient, appScheme: scheme), keys: keys)
            await #expect(throws: expected, "scheme: \(String(describing: scheme))") {
                try await ctx.authorizeOAuth(.google, authenticator: auth)
            }
            #expect(auth.urls.isEmpty)
            #expect(try keys.listPublicKeys().isEmpty)
        }
    }
}

// MARK: - Redirect and origin

@Suite("Hosted Google OAuth: redirect and origin") @MainActor
struct HostedGoogleRedirectTests {
    @Test func redirectUriTable() throws {
        let cases: [(String?, String)] = [
            (nil, "https://oauth-redirect.0xkey.io/?scheme=myapp"),
            ("  ", "https://oauth-redirect.0xkey.io/?scheme=myapp"),
            ("https://redirect.example.test/cb", "https://redirect.example.test/cb?scheme=myapp"),
            ("https://redirect.example.test/cb?x=1", "https://redirect.example.test/cb?x=1&scheme=myapp"),
            ("https://redirect.example.test/cb?", "https://redirect.example.test/cb?scheme=myapp"),
            ("https://redirect.example.test/cb?x=1&", "https://redirect.example.test/cb?x=1&scheme=myapp"),
            ("https://redirect.example.test/cb?scheme=myapp", "https://redirect.example.test/cb?scheme=myapp"),
        ]
        for (configured, expected) in cases {
            #expect(try ZeroXKeyContext.hostedRedirectUri(configured: configured, appScheme: "myapp") == expected,
                    "configured: \(String(describing: configured))")
        }
        #expect(try ZeroXKeyContext.hostedRedirectUri(configured: nil, appScheme: "my.app+x") == "https://oauth-redirect.0xkey.io/?scheme=my.app%2Bx")
    }

    @Test func unusableRedirectUrisAreRejected() {
        for bad in ["http://redirect.example.test/cb", "myapp://cb", "redirect.example.test/cb", "https://redirect.example.test/cb#f",
                    "https://user@redirect.example.test/cb", "https://redirect.example.test/c b",
                    "https://redirect.example.test/cb?scheme=other", "https://redirect.example.test/cb?scheme=myapp&scheme=myapp"] {
            #expect(throws: ZeroXKeyOAuthError.invalidRedirectUri(bad), "\(bad)") {
                try ZeroXKeyContext.hostedRedirectUri(configured: bad, appScheme: "myapp")
            }
        }
    }

    @Test func originUriTable() throws {
        #expect(try ZeroXKeyContext.hostedOriginUri(nil) == "https://oauth-origin.0xkey.io")
        #expect(try ZeroXKeyContext.hostedOriginUri(" https://oauth-origin.staging.example.test/start ")
                == "https://oauth-origin.staging.example.test/start")
        for bad in ["http://oauth-origin.example.test/", "oauth-origin.example.test", "https://user@oauth-origin.example.test/",
                    "https://oauth-origin.example.test/?provider=google", "https://oauth-origin.example.test/#f", "https://oauth-origin.example.test/a b"] {
            #expect(throws: ZeroXKeyOAuthError.invalidOriginUri(bad), "\(bad)") { try ZeroXKeyContext.hostedOriginUri(bad) }
        }
    }

    @Test func configuredRedirectAndOriginReachTheOpenedUrl() async throws {
        let ctx = hostedContext(MockServer(), oauth: .init(
            googleWebClientId: webClient, appScheme: "exampleapp", redirectUri: "https://redirect.example.test/cb",
            originUri: "https://oauth-origin.staging.example.test/start"))
        let auth = StubAuthenticator.hosted()
        _ = try await ctx.authorizeOAuth(.google, authenticator: auth)
        let c = try components(auth.urls.first)
        #expect(c.host == "oauth-origin.staging.example.test" && c.path == "/start")
        #expect(StubAuthenticator.param(c, "redirectUri") == "https://redirect.example.test/cb?scheme=exampleapp")
    }

    @Test func remoteRedirectUrlIsUsedWhenHttpsAndSkippedWhenCustomScheme() async throws {
        // Dashboard's `oauthRedirectUrl`, https: sdk-js uses it as the hosted redirect.
        let https = MockServer()
        https.on("/v1/wallet_kit_config", respond: kitConfig(["oauthRedirectUrl": "https://dash.example.test/cb"]))
        let a = StubAuthenticator.hosted()
        _ = try await hostedContext(https, configId: "cfg").authorizeOAuth(.google, authenticator: a)
        #expect(StubAuthenticator.param(try components(a.urls.first), "redirectUri") == "https://dash.example.test/cb?scheme=exampleapp")
        // A custom-scheme one is Discord's and X's; it is not a hosted redirect.
        let custom = MockServer()
        custom.on("/v1/wallet_kit_config", respond: kitConfig(["oauthRedirectUrl": "exampleapp://oauth"]))
        let b = StubAuthenticator.hosted()
        _ = try await hostedContext(custom, configId: "cfg").authorizeOAuth(.google, authenticator: b)
        #expect(StubAuthenticator.param(try components(b.urls.first), "redirectUri") == "https://oauth-redirect.0xkey.io/?scheme=exampleapp")
        // The local redirect wins over the Dashboard's.
        let local = MockServer()
        local.on("/v1/wallet_kit_config", respond: kitConfig(["oauthRedirectUrl": "https://dash.example.test/cb"]))
        let c = StubAuthenticator.hosted()
        _ = try await hostedContext(local, oauth: .init(googleWebClientId: webClient, appScheme: "exampleapp",
                                                        redirectUri: "https://local.example.test/cb"), configId: "cfg")
            .authorizeOAuth(.google, authenticator: c)
        #expect(StubAuthenticator.param(try components(c.urls.first), "redirectUri") == "https://local.example.test/cb?scheme=exampleapp")
    }

    @Test func aLocalRedirectThatIsNotHttpsIsRejected() async throws {
        let keys = InMemoryKeyManager()
        let ctx = hostedContext(MockServer(), oauth: .init(googleWebClientId: webClient, appScheme: "exampleapp",
                                                           redirectUri: "exampleapp://oauth"), keys: keys)
        let auth = StubAuthenticator.hosted()
        await #expect(throws: ZeroXKeyOAuthError.invalidRedirectUri("exampleapp://oauth")) {
            try await ctx.authorizeOAuth(.google, authenticator: auth)
        }
        #expect(auth.urls.isEmpty)
        #expect(try keys.listPublicKeys().isEmpty)
    }
}

// MARK: - Callback

@Suite("Hosted Google OAuth: callback") @MainActor
struct HostedGoogleCallbackTests {
    let state = "provider=google&flow=redirect&publicKey=02ab&transactionId=\(fixedTransactionId)"

    func token(_ url: String) throws -> String {
        try ZeroXKeyContext.hostedIdToken(from: try #require(URL(string: url)), appScheme: "exampleapp", state: state)
    }

    @Test func acceptsTheHostedRedirect() throws {
        let encodedState = state.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        #expect(try token("exampleapp://?state=\(encodedState)&id_token=a.b.c") == "a.b.c")
        #expect(try token("exampleapp://?id_token=a.b.c&state=\(encodedState)") == "a.b.c")
        #expect(try token("EXAMPLEAPP://?id_token=a.b.c&state=\(encodedState)") == "a.b.c", "scheme case is irrelevant")
        #expect(try token("exampleapp:///?id_token=a.b.c&state=\(encodedState)") == "a.b.c", "a trailing slash is tolerated")
        #expect(try token("exampleapp://?id_token=a.b.c&state=\(encodedState)#screen") == "a.b.c", "an unrelated fragment is ignored")
        #expect(try token("exampleapp://?id_token=a.b.c&state=\(encodedState)&other=1") == "a.b.c")
    }

    @Test func rejectsTamperedOrIncompleteCallbacks() {
        let s = state.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let forged = "forged".addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let cases: [(String, String, ZeroXKeyOAuthError)] = [
            ("state mismatch", "exampleapp://?state=\(forged)&id_token=a.b.c", .invalidCallback("state mismatch")),
            ("no state", "exampleapp://?id_token=a.b.c", .invalidCallback("state mismatch")),
            ("empty state", "exampleapp://?state=&id_token=a.b.c", .invalidCallback("state mismatch")),
            ("two states", "exampleapp://?state=\(s)&state=\(s)&id_token=a.b.c", .invalidCallback("state mismatch")),
            ("no token", "exampleapp://?state=\(s)", .invalidCallback("missing id_token")),
            ("empty token", "exampleapp://?state=\(s)&id_token=", .invalidCallback("missing id_token")),
            ("two tokens", "exampleapp://?state=\(s)&id_token=a&id_token=b", .invalidCallback("missing id_token")),
            ("token with space", "exampleapp://?state=\(s)&id_token=a%20b", .invalidCallback("malformed id_token")),
            ("oversized token", "exampleapp://?state=\(s)&id_token=" + String(repeating: "x", count: 65_537), .invalidCallback("malformed id_token")),
            ("denied", "exampleapp://?error=access_denied&state=\(s)", .canceled),
            ("denied without state", "exampleapp://?error=access_denied", .canceled),
            ("provider error", "exampleapp://?error=server_error&state=\(s)", .invalidCallback("provider error server_error")),
            ("error beats token", "exampleapp://?error=server_error&state=\(s)&id_token=a.b.c", .invalidCallback("provider error server_error")),
            ("error twice", "exampleapp://?error=access_denied&error=access_denied", .invalidCallback("provider error access_denied")),
            ("wrong scheme", "evil://?state=\(s)&id_token=a.b.c", .invalidCallback("redirect base mismatch")),
            ("host", "exampleapp://evil.example.test?state=\(s)&id_token=a.b.c", .invalidCallback("redirect base mismatch")),
            ("path", "exampleapp://cb?state=\(s)&id_token=a.b.c", .invalidCallback("redirect base mismatch")),
            ("deep path", "exampleapp:///x/y?state=\(s)&id_token=a.b.c", .invalidCallback("redirect base mismatch")),
            ("token in fragment", "exampleapp://?state=\(s)#id_token=zzz", .invalidCallback("unexpected fragment")),
            ("state in fragment", "exampleapp://?state=\(s)&id_token=a.b.c#state=\(s)", .invalidCallback("unexpected fragment")),
        ]
        for (name, url, expected) in cases {
            #expect(throws: expected, "\(name)") { try token(url) }
        }
    }

    @Test func aRejectedCallbackLeavesNoSessionKeyAndSendsNothing() async throws {
        let cases: [(String, @Sendable (URLComponents) -> URL, ZeroXKeyOAuthError)] = [
            ("forged state", { _ in hostedCallbackURL(state: "forged") }, .invalidCallback("state mismatch")),
            ("denied", { _ in URL(string: "exampleapp://?error=access_denied")! }, .canceled),
            ("no token", { c in hostedCallbackURL(state: StubAuthenticator.param(c, "state"), idToken: nil) }, .invalidCallback("missing id_token")),
        ]
        for (name, respond, expected) in cases {
            let server = MockServer()
            let keys = InMemoryKeyManager()
            let ctx = hostedContext(server, keys: keys)
            await #expect(throws: expected, "\(name)") {
                try await ctx.handleOAuth(.google, authenticator: StubAuthenticator(respond: respond))
            }
            #expect(server.requests.isEmpty, "\(name)")
            #expect(try keys.listPublicKeys().isEmpty, "\(name): the session key must be deleted")
        }
    }

    @Test func aCanceledBrowserSessionPropagatesAndLeavesNoKey() async throws {
        let keys = InMemoryKeyManager()
        let ctx = hostedContext(MockServer(), keys: keys)
        await #expect(throws: ZeroXKeyOAuthError.canceled) {
            try await ctx.authorizeOAuth(.google, authenticator: StubAuthenticator { _ in throw ZeroXKeyOAuthError.canceled })
        }
        #expect(try keys.listPublicKeys().isEmpty)
    }
}

// MARK: - Explicit client: PKCE

@Suite("Google OAuth: explicit client selects PKCE") @MainActor
struct GooglePKCESelectionTests {
    @Test func explicitClientRunsTheInstalledAppFlowEvenWithAWebClientConfigured() async throws {
        let server = MockServer()
        let ctx = hostedContext(server, configId: "cfg-hosted")   // web client ID and app scheme are configured
        ctx.googleTokenURL = server.apiURL.appendingPathComponent("google/token")
        server.on("/google/token", respond: .json(["id_token": "pkce.id.token", "access_token": "x"]))
        let auth = StubAuthenticator.echo(redirect: iosClient.redirectUri)

        let success = try await ctx.authorizeOAuth(.google, client: iosClient, authenticator: auth)
        #expect(success.oidcToken == "pkce.id.token")
        let c = try components(auth.urls.first)
        #expect(c.host == "accounts.google.com" && c.path == "/o/oauth2/v2/auth")
        #expect(StubAuthenticator.param(c, "client_id") == iosClient.clientId)
        #expect(StubAuthenticator.param(c, "redirect_uri") == iosClient.redirectUri)
        #expect(StubAuthenticator.param(c, "response_type") == "code")
        #expect(StubAuthenticator.param(c, "code_challenge_method") == "S256")
        #expect(StubAuthenticator.param(c, "code_challenge")?.isEmpty == false)
        #expect(StubAuthenticator.param(c, "nonce") == hex(sha256: success.publicKey))
        #expect(StubAuthenticator.param(c, "clientId") == nil, "no hosted-page parameters")
        #expect(auth.schemes == ["com.googleusercontent.apps.123"])
        #expect(server.requests(to: "/google/token").count == 1)
        #expect(server.requests(to: "/v1/wallet_kit_config").isEmpty, "the Dashboard is not consulted for an explicit client")
    }

    @Test func explicitClientIsNotAffectedByAMissingAppScheme() async throws {
        let server = MockServer()
        let ctx = hostedContext(server, oauth: nil)
        ctx.googleTokenURL = server.apiURL.appendingPathComponent("google/token")
        server.on("/google/token", respond: .json(["id_token": "pkce.id.token"]))
        let success = try await ctx.authorizeOAuth(
            .google, client: iosClient, authenticator: StubAuthenticator.echo(redirect: iosClient.redirectUri))
        #expect(success.oidcToken == "pkce.id.token")
    }

    @Test func discordAndXStillNeedTheirOwnClients() async throws {
        let ctx = hostedContext(MockServer())   // only a Google web client
        for provider in [OAuthWebProvider.discord, .x] {
            await #expect(throws: ZeroXKeyOAuthError.missingClient(provider)) {
                try await ctx.authorizeOAuth(provider, authenticator: StubAuthenticator.echo(redirect: "exampleapp://oauth"))
            }
        }
    }
}
