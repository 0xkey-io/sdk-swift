import Foundation
import Testing
import ZeroXKey
import ZeroXKeyHttp
import ZeroXKeyTestSupport

/// Auth Proxy `wallet_kit_config` on the client side: the unauthenticated client that exists before
/// login (`ZeroXKeyContext.client`), the configuration fetched at `configure(_:)`, and the
/// OAuth client fallback to the remote `oauthClientIds`.
@Suite("Wallet kit remote config", .serialized) @MainActor
struct WalletKitConfigTests {
    nonisolated static let t0: TimeInterval = 1_763_500_000
    nonisolated static let farFuture: TimeInterval = 4_102_444_800

    /// A `wallet_kit_config` answer shaped like the Auth Proxy's.
    func kitConfig(
        _ seconds: String? = "1800", providers: [String] = ["email", "google", "discord"],
        clientIds: [String: String]? = nil, redirect: String? = nil, otpLength: String? = nil,
        otpAlphanumeric: Bool? = nil, status: Int = 200
    ) -> MockResponse {
        var body: [String: Any] = ["enabledProviders": providers, "organizationId": "org-parent"]
        if let seconds { body["sessionExpirationSeconds"] = seconds }
        if let clientIds { body["oauthClientIds"] = clientIds }
        if let redirect { body["oauthRedirectUrl"] = redirect }
        if let otpLength { body["otpLength"] = otpLength }
        if let otpAlphanumeric { body["otpAlphanumeric"] = otpAlphanumeric }
        return .json(body, status: status)
    }

    func config(
        _ server: MockServer, configId: String? = "cfg-wkc", oauth: ZeroXKeyConfig.OAuthConfig? = nil,
        keys: InMemoryKeyManager = InMemoryKeyManager(), sessions: InMemorySessionStore = InMemorySessionStore(),
        sessionExpirationSeconds: String? = nil
    ) -> ZeroXKeyConfig {
        ZeroXKeyConfig(
            apiUrl: server.apiURL.absoluteString, authProxyUrl: server.authProxyURL.absoluteString,
            authProxyConfigId: configId, organizationId: "org-parent",
            auth: .init(oauth: oauth, autoRefreshSession: false), activityPoller: .init(intervalMs: 0, numRetries: 3),
            sessionExpirationSeconds: sessionExpirationSeconds, keyManager: keys, sessionStore: sessions,
            urlSession: server.session).trustingFixtures()
    }

    func context(_ server: MockServer, configId: String? = "cfg-wkc", oauth: ZeroXKeyConfig.OAuthConfig? = nil,
                 keys: InMemoryKeyManager = InMemoryKeyManager(),
                 sessions: InMemorySessionStore = InMemorySessionStore()) -> ZeroXKeyContext {
        ZeroXKeyContext(config: config(server, configId: configId, oauth: oauth, keys: keys, sessions: sessions),
                        now: { Date(timeIntervalSince1970: Self.t0) }, notificationCenter: NotificationCenter(),
                        foregroundNotification: nil)
    }

    /// `configure(_:)` then read `shared` without suspending, so nothing can replace it in between.
    func configured(_ config: ZeroXKeyConfig) -> ZeroXKeyContext {
        ZeroXKeyContext.configure(config)
        return ZeroXKeyContext.shared
    }

    func stampLoginRoute(_ server: MockServer) {
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(
                    publicKey: pk, organizationId: "org-parent", userId: "u", exp: Self.farFuture)]])))
        }
    }

    /// Query of the first authorization URL the stub authenticator was asked to open.
    func authComponents(_ auth: StubAuthenticator) throws -> URLComponents {
        let url = try #require(auth.urls.first)
        return try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
    }

    func requestedLifetimes(_ server: MockServer) -> [String?] {
        server.requests(to: "/public/v1/submit/stamp_login")
            .map { ($0.json["parameters"] as? [String: Any])?["expirationSeconds"] as? String }
    }

    // MARK: Client before login (R3)

    @Test func clientExistsBeforeLoginAndReadsTheWalletKitConfig() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(
            "1800", providers: ["email", "google"], clientIds: ["discord": "d-1"], redirect: "exampleapp://oauth",
            otpLength: "6", otpAlphanumeric: true))
        let ctx = context(server)
        let client = try #require(ctx.client, "the Auth Proxy client is available before login")
        #expect(client.stamper == nil)
        #expect(client.authProxyConfigId == "cfg-wkc")
        let res = try await client.proxyGetWalletKitConfig()
        #expect(res.enabledProviders == ["email", "google"])
        #expect(res.sessionExpirationSeconds == "1800")
        #expect(res.organizationId == "org-parent")
        #expect(res.oauthClientIds == ["discord": "d-1"])
        #expect(res.oauthRedirectUrl == "exampleapp://oauth")
        #expect(res.otpLength == "6")
        #expect(res.otpAlphanumeric == true)
        let sent = try #require(server.requests(to: "/v1/wallet_kit_config").first)
        #expect(sent.header("X-Auth-Proxy-Config-ID") == "cfg-wkc")
        #expect(sent.header("X-Stamp") == nil)
    }

    @Test func clientIsNilWithoutAuthProxyConfigId() {
        let server = MockServer()
        #expect(context(server, configId: nil).client == nil)
        #expect(context(server, configId: "").client == nil)
    }

    @Test func clientIsAvailableAfterConfigureWithoutASession() throws {
        let server = MockServer()
        let ctx = configured(config(server))
        #expect(ctx.authState == .unauthenticated)
        #expect(ctx.session == nil)
        let client = try #require(ctx.client)
        #expect(client.stamper == nil)
    }

    @Test func sessionCallsStillThrowNoActiveSessionBeforeLogin() async throws {
        let server = MockServer()
        let ctx = configured(config(server))
        #expect(ctx.client != nil)
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.refreshUser() }
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.refreshWallets() }
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.createWallet(walletName: "w") }
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.exportWallet(walletId: "w") }
        await #expect(throws: ZeroXKeyError.noActiveSession) {
            try await ctx.signRawPayload(signWith: "0xabc", payload: "00", encoding: .PAYLOAD_ENCODING_HEXADECIMAL,
                                         hashFunction: .HASH_FUNCTION_NO_OP)
        }
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.updateUserName("n") }
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.refreshSession() }
        // Nothing was sent: no signed (or unsigned) session request left through the unauthenticated client.
        #expect(server.requests.filter { $0.path.hasPrefix("/public/") }.isEmpty)
    }

    @Test func loginSwapsInTheSessionClientAndLogoutRestoresTheUnauthenticatedOne() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = context(server, keys: keys)
        #expect(try #require(ctx.client).stamper == nil)

        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(
            publicKey: key, organizationId: "org-sub", userId: "u", exp: Self.t0 + 900))
        #expect(ctx.authState == .authenticated)
        let signed = try #require(ctx.client)
        #expect(signed.stamper != nil)
        #expect(signed.organizationId == "org-sub")

        try ctx.logout()
        #expect(ctx.authState == .unauthenticated && ctx.session == nil)
        let after = try #require(ctx.client, "back to the unauthenticated Auth Proxy client")
        #expect(after.stamper == nil)
        #expect(after.authProxyConfigId == "cfg-wkc")
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.refreshWallets() }
        #expect(server.requests.filter { $0.path.hasPrefix("/public/") }.isEmpty)
    }

    @Test func clientIsNilAfterLogoutWithoutAuthProxyConfigId() async throws {
        let server = MockServer()
        let ctx = context(server, configId: nil)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(
            publicKey: key, organizationId: "org-sub", userId: "u", exp: Self.t0 + 900))
        #expect(ctx.client != nil)
        try ctx.logout()
        #expect(ctx.client == nil)
    }

    // MARK: Fetch at configure (R1)

    @Test func configureFetchesTheWalletKitConfigOnceAndAppliesTheSessionDuration() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        stampLoginRoute(server)
        let keys = InMemoryKeyManager(), sessions = InMemorySessionStore()
        // A stored session that `configure` restores; refreshing it asks `stamp_login` for a lifetime.
        let seed = context(server, keys: keys, sessions: sessions)
        let key = try seed.createKeyPair()
        try await seed.storeSession(jwt: APIFixtures.sessionJWT(
            publicKey: key, organizationId: "org-parent", userId: "u", exp: Self.farFuture))

        let ctx = configured(config(server, keys: keys, sessions: sessions))
        #expect(ctx.authState == .authenticated)
        #expect(await eventually { server.requests(to: "/v1/wallet_kit_config").count == 1 },
                "the configuration is fetched at startup, before any call needs it")
        try await ctx.refreshSession()
        #expect(requestedLifetimes(server) == ["1800"])
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)
    }

    @Test func aFailingFetchDoesNotAffectSessionRestoreOrLogin() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: .text("boom", status: 500))
        stampLoginRoute(server)
        let keys = InMemoryKeyManager(), sessions = InMemorySessionStore()
        let seed = context(server, keys: keys, sessions: sessions)
        let key = try seed.createKeyPair()
        try await seed.storeSession(jwt: APIFixtures.sessionJWT(
            publicKey: key, organizationId: "org-parent", userId: "u", exp: Self.farFuture))

        let ctx = configured(config(server, keys: keys, sessions: sessions, sessionExpirationSeconds: "3600"))
        #expect(ctx.authState == .authenticated, "restoring the session does not wait for the configuration")
        #expect(await eventually { server.requests(to: "/v1/wallet_kit_config").count == 1 })
        try await ctx.refreshSession()
        #expect(requestedLifetimes(server) == ["3600"], "falls back to the local setting")
        #expect(ctx.authState == .authenticated)
    }

    // MARK: OAuth client fallback (R2)

    let remoteIds = ["discord": "remote-discord", "x": "remote-x", "google": "remote-web.apps.googleusercontent.com"]

    @Test func discordClientComesFromTheRemoteConfig() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(clientIds: remoteIds, redirect: "exampleapp://oauth"))
        server.on("/v1/oauth2_authenticate", respond: .json(["oidcToken": "discord.oidc.token"]))
        let ctx = context(server)
        let auth = StubAuthenticator.echo(redirect: "exampleapp://oauth")
        let success = try await ctx.authorizeOAuth(.discord, authenticator: auth)
        #expect(success.oidcToken == "discord.oidc.token")
        let c = try authComponents(auth)
        #expect(StubAuthenticator.param(c, "client_id") == "remote-discord")
        #expect(StubAuthenticator.param(c, "redirect_uri") == "exampleapp://oauth")
        #expect(auth.schemes == ["exampleapp"])
        let exchange = try #require(server.requests(to: "/v1/oauth2_authenticate").first?.json)
        #expect(exchange["clientId"] as? String == "remote-discord")
        #expect(exchange["redirectUri"] as? String == "exampleapp://oauth")
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)
    }

    @Test func xClientComesFromTheRemoteConfig() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(clientIds: remoteIds, redirect: "exampleapp://oauth"))
        server.on("/v1/oauth2_authenticate", respond: .json(["oidcToken": "x.oidc.token"]))
        let ctx = context(server)
        let auth = StubAuthenticator.echo(redirect: "exampleapp://oauth")
        _ = try await ctx.authorizeOAuth(.x, authenticator: auth)
        let c = try authComponents(auth)
        #expect(StubAuthenticator.param(c, "client_id") == "remote-x")
        let exchange = try #require(server.requests(to: "/v1/oauth2_authenticate").first?.json)
        #expect(exchange["provider"] as? String == "OAUTH2_PROVIDER_X")
        #expect(exchange["clientId"] as? String == "remote-x")
    }

    /// Google's hosted flow takes the Dashboard's web client ID (sdk-js does too). The Dashboard's
    /// custom-scheme redirect URL belongs to Discord and X: the hosted flow skips it for its own `https` redirect.
    /// The same flow with every fallback case is in `HostedGoogleOAuthTests`.
    @Test func googleWebClientIdComesFromTheRemoteConfig() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(clientIds: remoteIds, redirect: "exampleapp://oauth"))
        let ctx = context(server, oauth: .init(appScheme: "exampleapp"))
        let auth = StubAuthenticator.hosted(scheme: "exampleapp")
        let success = try await ctx.authorizeOAuth(.google, authenticator: auth)
        #expect(success.providerName == "google")
        let c = try authComponents(auth)
        #expect(c.host == "oauth-origin.0xkey.io")
        #expect(StubAuthenticator.param(c, "clientId") == "remote-web.apps.googleusercontent.com")
        #expect(StubAuthenticator.param(c, "redirectUri") == "https://oauth-redirect.0xkey.io/?scheme=exampleapp")
        #expect(auth.schemes == ["exampleapp"])
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)
    }

    @Test func priorityIsExplicitThenLocalThenRemote() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(clientIds: remoteIds, redirect: "remoteapp://oauth"))
        server.on("/v1/oauth2_authenticate", respond: .json(["oidcToken": "t.oidc.token"]))
        let local = OAuthClient(clientId: "local-discord", redirectUri: "localapp://oauth")
        let explicit = OAuthClient(clientId: "explicit-discord", redirectUri: "explicitapp://oauth")
        let ctx = context(server, oauth: .init(discord: local))

        let viaExplicit = StubAuthenticator.echo(redirect: "explicitapp://oauth")
        _ = try await ctx.authorizeOAuth(.discord, client: explicit, authenticator: viaExplicit)
        let e = try authComponents(viaExplicit)
        #expect(StubAuthenticator.param(e, "client_id") == "explicit-discord")

        let viaLocal = StubAuthenticator.echo(redirect: "localapp://oauth")
        _ = try await ctx.authorizeOAuth(.discord, authenticator: viaLocal)
        let l = try authComponents(viaLocal)
        #expect(StubAuthenticator.param(l, "client_id") == "local-discord")
        #expect(StubAuthenticator.param(l, "redirect_uri") == "localapp://oauth", "a local client brings its own redirect")

        // X has no local client, so the remote one is used with the remote redirect.
        let viaRemote = StubAuthenticator.echo(redirect: "remoteapp://oauth")
        _ = try await ctx.authorizeOAuth(.x, authenticator: viaRemote)
        let r = try authComponents(viaRemote)
        #expect(StubAuthenticator.param(r, "client_id") == "remote-x")
        #expect(StubAuthenticator.param(r, "redirect_uri") == "remoteapp://oauth")
    }

    @Test func missingClientWhenNothingProvidesOne() async throws {
        let auth = StubAuthenticator.echo(redirect: "exampleapp://oauth")
        // The remote config has no client ID for this provider.
        let noId = MockServer()
        noId.on("/v1/wallet_kit_config", respond: kitConfig(clientIds: ["discord": "remote-discord"], redirect: "exampleapp://oauth"))
        await #expect(throws: ZeroXKeyOAuthError.missingClient(.x)) {
            try await context(noId).authorizeOAuth(.x, authenticator: auth)
        }
        // A client ID without a redirect URL cannot start a flow.
        let noRedirect = MockServer()
        noRedirect.on("/v1/wallet_kit_config", respond: kitConfig(clientIds: remoteIds))
        await #expect(throws: ZeroXKeyOAuthError.missingClient(.discord)) {
            try await context(noRedirect).authorizeOAuth(.discord, authenticator: auth)
        }
        // The configuration cannot be read.
        let failing = MockServer()
        failing.on("/v1/wallet_kit_config", respond: .text("boom", status: 500))
        await #expect(throws: ZeroXKeyOAuthError.missingClient(.discord)) {
            try await context(failing).authorizeOAuth(.discord, authenticator: auth)
        }
        // No Auth Proxy configuration: nothing to ask.
        let none = MockServer()
        await #expect(throws: ZeroXKeyOAuthError.missingClient(.discord)) {
            try await context(none, configId: nil).authorizeOAuth(.discord, authenticator: auth)
        }
        #expect(none.requests.isEmpty)
        #expect(auth.urls.isEmpty)
    }

    /// The native flow needs a custom-scheme redirect; a web redirect URL from the Dashboard is
    /// reported as such instead of silently opening a flow that cannot return to the app.
    @Test func aWebRedirectUrlFromTheRemoteConfigIsRejected() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(clientIds: remoteIds, redirect: "https://oauth.example.org/cb"))
        let ctx = context(server)
        await #expect(throws: ZeroXKeyOAuthError.invalidRedirectUri("https://oauth.example.org/cb")) {
            try await ctx.authorizeOAuth(.discord, authenticator: StubAuthenticator.echo(redirect: "https://oauth.example.org/cb"))
        }
    }
}
