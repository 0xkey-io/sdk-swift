import Foundation
import Testing
import ZeroXKey
import ZeroXKeyTestSupport

/// The internal runtime configuration: what `wallet_kit_config` and the
/// local `ZeroXKeyConfig` resolve to, how it is fetched (once, shared, retried after a failure),
/// and that a failing fetch never blocks anything. Reached through `package` accessors.
@Suite("Runtime config", .serialized) @MainActor
struct RuntimeConfigTests {
    nonisolated static let t0: TimeInterval = 1_763_500_000

    nonisolated func kitConfig(_ extra: [String: Any] = [:], status: Int = 200) -> MockResponse {
        var body: [String: Any] = ["enabledProviders": ["email"], "organizationId": "org-parent", "sessionExpirationSeconds": "1800"]
        for (k, v) in extra { body[k] = v }
        return .json(body, status: status)
    }

    func config(_ server: MockServer, configId: String? = "cfg-rc", oauth: ZeroXKeyConfig.OAuthConfig? = nil,
                local: String? = nil) -> ZeroXKeyConfig {
        ZeroXKeyConfig(
            apiUrl: server.apiURL.absoluteString, authProxyUrl: server.authProxyURL.absoluteString,
            authProxyConfigId: configId, organizationId: "org-parent",
            auth: .init(oauth: oauth, autoRefreshSession: false), sessionExpirationSeconds: local,
            keyManager: InMemoryKeyManager(), sessionStore: InMemorySessionStore(), urlSession: server.session).trustingFixtures()
    }

    func context(_ server: MockServer, configId: String? = "cfg-rc", oauth: ZeroXKeyConfig.OAuthConfig? = nil,
                 local: String? = nil, time: TestTime = TestTime()) -> ZeroXKeyContext {
        ZeroXKeyContext(config: config(server, configId: configId, oauth: oauth, local: local), now: time.clock,
                        notificationCenter: NotificationCenter(), foregroundNotification: nil)
    }

    @Test func remoteValuesAreApplied() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig([
            "otpLength": "6", "otpAlphanumeric": true, "oauthRedirectUrl": "exampleapp://oauth",
            "oauthClientIds": ["discord": "d-1", "x": "x-1", "google": "g-web"],
        ]))
        let ctx = context(server, local: "3600")
        #expect(ctx.runtimeConfig == nil, "nothing is fetched until it is needed or `configure` asks")
        let rc = await ctx.loadRuntimeConfig()
        #expect(rc.fetched)
        #expect(rc.auth.sessionExpirationSeconds == "1800", "the Dashboard value beats the local one, as in sdk-js")
        #expect(rc.auth.otpLength == 6)
        #expect(rc.auth.otpAlphanumeric == true)
        #expect(rc.auth.oauth.redirectUrl == "exampleapp://oauth")
        #expect(rc.auth.oauth.clients[.discord] == OAuthClient(clientId: "d-1", redirectUri: "exampleapp://oauth"))
        #expect(rc.auth.oauth.clients[.x] == OAuthClient(clientId: "x-1", redirectUri: "exampleapp://oauth"))
        #expect(rc.auth.oauth.clients[.google] == nil, "Google's web client ID is not an OAuthClient: it feeds the hosted flow")
        #expect(rc.auth.oauth.googleWebClientId == "g-web", "the Dashboard's Google client ID is the hosted flow's web client")
        #expect(ctx.runtimeConfig == rc)
    }

    @Test func localOAuthClientBeatsTheRemoteOne() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig([
            "oauthRedirectUrl": "exampleapp://oauth", "oauthClientIds": ["discord": "d-remote", "x": "x-remote"],
        ]))
        let local = OAuthClient(clientId: "d-local", redirectUri: "localapp://cb")
        let rc = await context(server, oauth: .init(googleWebClientId: "g-local", discord: local)).loadRuntimeConfig()
        #expect(rc.auth.oauth.clients[.discord] == local)
        #expect(rc.auth.oauth.clients[.google] == nil)
        #expect(rc.auth.oauth.googleWebClientId == "g-local", "the local web client ID beats the Dashboard's")
        #expect(rc.auth.oauth.clients[.x]?.clientId == "x-remote")
    }

    @Test func googleWebClientIdFallsBackToTheRemoteOneAndIgnoresBlankValues() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(["oauthClientIds": ["google": "g-remote"]]))
        // No redirect URL is needed for Google: the hosted page is the default redirect.
        #expect(await context(server).loadRuntimeConfig().auth.oauth.googleWebClientId == "g-remote")
        #expect(await context(server, oauth: .init(googleWebClientId: "  ")).loadRuntimeConfig().auth.oauth.googleWebClientId == "g-remote")
        let blank = MockServer()
        blank.on("/v1/wallet_kit_config", respond: kitConfig(["oauthClientIds": ["google": ""]]))
        #expect(await context(blank).loadRuntimeConfig().auth.oauth.googleWebClientId == nil)
        let failing = MockServer()
        failing.on("/v1/wallet_kit_config", respond: .text("boom", status: 500))
        #expect(await context(failing, oauth: .init(googleWebClientId: "g-local")).loadRuntimeConfig().auth.oauth.googleWebClientId == "g-local")
    }

    @Test func otpParametersAreOnlyKeptWhenUsable() async throws {
        for bad in ["abc", "0", "-4", ""] {
            let server = MockServer()
            server.on("/v1/wallet_kit_config", respond: kitConfig(["otpLength": bad]))
            let rc = await context(server).loadRuntimeConfig()
            #expect(rc.auth.otpLength == nil, "\(bad)")
            #expect(rc.auth.otpAlphanumeric == nil)
        }
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(["otpLength": "9", "otpAlphanumeric": false]))
        let rc = await context(server).loadRuntimeConfig()
        #expect(rc.auth.otpLength == 9 && rc.auth.otpAlphanumeric == false)
    }

    @Test func sessionDurationWithoutAUsableRemoteValueFallsBackToLocalThenDefault() async throws {
        for answer in ["", " ", "0", "abc", "12abc", "-5", "1.5", "99999999999999999999"] {
            let server = MockServer()
            server.on("/v1/wallet_kit_config", respond: kitConfig(["sessionExpirationSeconds": answer]))
            #expect(await context(server, local: "3600").loadRuntimeConfig().auth.sessionExpirationSeconds == "3600", "\(answer)")
            #expect(await context(server).loadRuntimeConfig().auth.sessionExpirationSeconds == "900", "\(answer)")
            // An unusable local value is unset as well.
            #expect(await context(server, local: "0").loadRuntimeConfig().auth.sessionExpirationSeconds == "900", "\(answer)")
            #expect(await context(server, local: "abc").loadRuntimeConfig().auth.sessionExpirationSeconds == "900", "\(answer)")
        }
    }

    @Test func sessionDurationIsKeptInCanonicalForm() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(["sessionExpirationSeconds": " +1800 "]))
        #expect(await context(server, local: "3600").loadRuntimeConfig().auth.sessionExpirationSeconds == "1800")
        let plain = MockServer()
        #expect(await context(plain, configId: nil, local: " 0600 ").loadRuntimeConfig().auth.sessionExpirationSeconds == "600")
    }

    @Test func aFailedFetchWithAnUnusableLocalValueUsesTheDefault() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: .text("boom", status: 500))
        #expect(await context(server, local: "0").loadRuntimeConfig().auth.sessionExpirationSeconds == "900")
    }

    @Test func zeroArgumentResolvesLikeNoArgument() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig())
        let ctx = context(server, local: "3600")
        #expect(await ctx.resolvedExpirationSeconds(nil) == "1800")
        #expect(await ctx.resolvedExpirationSeconds("0") == "1800")
        #expect(await ctx.resolvedExpirationSeconds(" ") == "1800")
        #expect(await ctx.resolvedExpirationSeconds("-5") == "1800")
        #expect(await ctx.resolvedExpirationSeconds("45") == "45")
        #expect(await ctx.resolvedExpirationSeconds(" 45 ") == "45")
    }

    @Test func aFailedFetchFallsBackToLocalValuesAndIsRetriedAfterAMinute() async throws {
        let server = MockServer()
        let time = TestTime()
        server.on("/v1/wallet_kit_config", respond: .text("boom", status: 500))
        let ctx = context(server, local: "3600", time: time)
        let first = await ctx.loadRuntimeConfig()
        #expect(!first.fetched)
        #expect(first.auth.sessionExpirationSeconds == "3600")
        #expect(first.auth.otpLength == nil && first.auth.oauth.clients.isEmpty)
        #expect(await ctx.loadRuntimeConfig() == first)
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1, "not asked again at once")
        time.advance(61)
        server.on("/v1/wallet_kit_config", respond: kitConfig(["otpLength": "6"]))
        let retried = await ctx.loadRuntimeConfig()
        #expect(retried.fetched && retried.auth.sessionExpirationSeconds == "1800" && retried.auth.otpLength == 6)
        _ = await ctx.loadRuntimeConfig()
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 2, "read once, then cached")
    }

    @Test func withoutAnAuthProxyConfigurationNothingIsFetched() async throws {
        let server = MockServer()
        let rc = await context(server, configId: nil, local: "3600").loadRuntimeConfig()
        #expect(!rc.fetched)
        #expect(rc.auth.sessionExpirationSeconds == "3600")
        #expect(server.requests.isEmpty)
    }

    @Test func concurrentCallersShareOneRequest() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config") { _, _ in
            Thread.sleep(forTimeInterval: 0.15)   // long enough for every caller to arrive while it is in flight
            return self.kitConfig(["otpLength": "6"])
        }
        let ctx = context(server)
        async let a = ctx.loadRuntimeConfig()
        async let b = ctx.loadRuntimeConfig()
        async let c = ctx.loadRuntimeConfig()
        async let d = ctx.resolvedExpirationSeconds(nil)
        let (ra, rb, rc, seconds) = await (a, b, c, d)
        #expect(ra == rb && rb == rc && ra.fetched)
        #expect(seconds == "1800")
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)
    }

    @Test func configureStartsOneFetchWithoutBlockingAuthState() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config") { _, _ in
            Thread.sleep(forTimeInterval: 0.1)
            return self.kitConfig(["otpLength": "6"])
        }
        ZeroXKeyContext.configure(config(server))
        let ctx = ZeroXKeyContext.shared
        #expect(ctx.authState == .unauthenticated, "state is known at once; the fetch is not awaited")
        #expect(ctx.runtimeConfig == nil)
        let loaded = await ctx.loadRuntimeConfig()      // joins the request `configure` started
        #expect(loaded.fetched && loaded.auth.otpLength == 6)
        #expect(await eventually { ctx.runtimeConfig == loaded })
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)
    }
}
