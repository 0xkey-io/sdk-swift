import Foundation
import Testing
import ZeroXKey
import ZeroXKeyHttp
import ZeroXKeyTestSupport

/// The lifetime `stamp_login` asks for: call argument, else the Auth Proxy configuration's session
/// duration, else `config.sessionExpirationSeconds`, else 900 (the order the sdk-js wallet kits use).
/// At every layer a value that is empty, blank, not an integer or ≤ 0 (`"0"`, `"-5"`, `"abc"`) is unset and
/// the next layer applies.
@Suite("Session duration") @MainActor
struct SessionDurationTests {
    nonisolated static let t0: TimeInterval = 1_763_500_000

    func kitConfig(_ seconds: String?, status: Int = 200) -> MockResponse {
        var body: [String: Any] = ["enabledProviders": ["passkey"], "organizationId": "org-parent"]
        if let seconds { body["sessionExpirationSeconds"] = seconds }
        return .json(body, status: status)
    }

    func loginRoute(_ server: MockServer) {
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(
                    publicKey: pk, organizationId: "org-parent", userId: "u", exp: Self.t0 + 3600)]])))
        }
    }

    func requested(_ server: MockServer) -> [String?] {
        server.requests(to: "/public/v1/submit/stamp_login").map { ($0.json["parameters"] as? [String: Any])?["expirationSeconds"] as? String }
    }

    func passkeyContext(_ server: MockServer, configId: String? = "cfg-e2e", local: String? = nil,
                        time: TestTime? = nil) -> ZeroXKeyContext {
        let ctx = makeContext(server, rpId: "login.example.org", assertion: FakeAsserter(),
                              clock: time?.clock, authProxyConfigId: configId, sessionExpirationSeconds: local)
        return ctx
    }

    @Test func passkeyLoginUsesTheAuthProxyDuration() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(server)
        try await passkeyContext(server).loginWithPasskey()
        #expect(requested(server) == ["1800"])
        let cfg = try #require(server.requests(to: "/v1/wallet_kit_config").first)
        #expect(cfg.header("X-Auth-Proxy-Config-ID") == "cfg-e2e")
    }

    @Test func explicitArgumentWinsOverEverything() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(server)
        try await passkeyContext(server, local: "3600").loginWithPasskey(expirationSeconds: "120")
        #expect(requested(server) == ["120"])
        #expect(server.requests(to: "/v1/wallet_kit_config").isEmpty)   // not even asked
    }

    /// As in sdk-js: with an Auth Proxy configuration the Dashboard value beats the local setting.
    @Test func authProxyDurationBeatsTheLocalSetting() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(server)
        try await passkeyContext(server, local: "3600").loginWithPasskey()
        #expect(requested(server) == ["1800"])
    }

    @Test func localSettingApplies_whenTheAuthProxyHasNoDuration() async throws {
        for answer in [kitConfig(nil), kitConfig(""), kitConfig("0"), kitConfig("abc"), kitConfig("-5")] {
            let server = MockServer()
            server.on("/v1/wallet_kit_config", respond: answer)
            loginRoute(server)
            try await passkeyContext(server, local: "3600").loginWithPasskey()
            #expect(requested(server) == ["3600"])
        }
    }

    @Test func defaultIs900() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(nil))
        loginRoute(server)
        try await passkeyContext(server).loginWithPasskey()
        #expect(requested(server) == ["900"])
    }

    @Test func withoutAuthProxyConfigNothingIsFetched() async throws {
        let server = MockServer()
        loginRoute(server)
        try await passkeyContext(server, configId: nil, local: "3600").loginWithPasskey()
        #expect(requested(server) == ["3600"])
        #expect(server.requests(to: "/v1/wallet_kit_config").isEmpty)
        let plain = MockServer()
        loginRoute(plain)
        try await passkeyContext(plain, configId: nil).loginWithPasskey()
        #expect(requested(plain) == ["900"])
    }

    @Test func aFailingConfigRequestFallsBackAndIsRetriedAfterAMinute() async throws {
        let server = MockServer()
        let time = TestTime()
        server.on("/v1/wallet_kit_config", respond: .text("boom", status: 500))
        loginRoute(server)
        let ctx = passkeyContext(server, local: "3600", time: time)
        try await ctx.loginWithPasskey()
        #expect(requested(server) == ["3600"])                              // the login still works
        try await ctx.loginWithPasskey()
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)    // not asked again at once
        time.advance(61)
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        try await ctx.loginWithPasskey()
        #expect(requested(server) == ["3600", "3600", "1800"])
        try await ctx.loginWithPasskey()
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 2)    // read once, then cached
    }

    @Test func refreshUsesTheResolvedDuration() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(server)
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-parent", userId: "u", exp: Self.t0 + 900))
        try await ctx.refreshSession()
        try await ctx.refreshSession(expirationSeconds: "60")
        #expect(requested(server) == ["1800", "60"])
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)
    }

    @Test func otpLoginAttestedStampUsesTheResolvedDuration() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(server)
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-d", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
        try await ctx.loginWithOtp(verificationToken: vt, organizationId: "org-parent")
        #expect(requested(server) == ["1800"])
    }

    @Test func configValueAloneStillWorksAsBefore() {
        #expect(ZeroXKeyConfig().sessionExpirationSeconds == nil)
        #expect(ZeroXKeyConfig(sessionExpirationSeconds: "3600").sessionExpirationSeconds == "3600")
        #expect(ZeroXKeyConfig.defaultSessionExpirationSeconds == "900")
    }

    // MARK: - What counts as "set" (every layer goes through `usableSessionSeconds`)

    /// Values that are unset at any layer: `nil`, empty, blank, zero, negative, not an integer, too big.
    nonisolated static let unusable: [String?] = [
        nil, "", " ", "\n", "0", "00", "-0", "-5", "abc", "12abc", "abc12", "1.5", "30.0", "1e3", "0x10", "30 s", "٣٠",
        "99999999999999999999",
    ]

    @Test(arguments: SessionDurationTests.unusable)
    func unusableValuesAreUnset(_ raw: String?) {
        #expect(ZeroXKeyRuntimeConfig.usableSessionSeconds(raw) == nil, "\(String(describing: raw))")
    }

    @Test(arguments: [
        ("1", "1"), ("30", "30"), ("900", "900"), ("3600", "3600"), (" 120 ", "120"), ("\t45\n", "45"),
        ("+30", "30"), ("030", "30"), (" +030 ", "30"), ("9223372036854775807", "9223372036854775807"),
    ])
    func usableValuesAreIntegersAboveZeroInCanonicalForm(_ raw: String, _ expected: String) {
        #expect(ZeroXKeyRuntimeConfig.usableSessionSeconds(raw) == expected)
    }

    // MARK: - Call argument layer

    /// An argument that is unset falls back to the Dashboard, and the configuration is read for it.
    @Test(arguments: SessionDurationTests.unusable)
    func unusableArgumentFallsBackToTheDashboard(_ argument: String?) async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(server)
        try await passkeyContext(server, local: "3600").loginWithPasskey(expirationSeconds: argument)
        #expect(requested(server) == ["1800"], "\(String(describing: argument))")
        #expect(server.requests(to: "/v1/wallet_kit_config").count == 1)
    }

    @Test func zeroArgumentFallsBackToDashboardThenLocalThenDefault() async throws {
        // Dashboard has a value.
        let dashboard = MockServer()
        dashboard.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(dashboard)
        try await passkeyContext(dashboard, local: "3600").loginWithPasskey(expirationSeconds: "0")
        #expect(requested(dashboard) == ["1800"])
        // Dashboard has none: the local value.
        let local = MockServer()
        local.on("/v1/wallet_kit_config", respond: kitConfig(nil))
        loginRoute(local)
        try await passkeyContext(local, local: "3600").loginWithPasskey(expirationSeconds: "0")
        #expect(requested(local) == ["3600"])
        // Neither: 900.
        let neither = MockServer()
        neither.on("/v1/wallet_kit_config", respond: kitConfig(nil))
        loginRoute(neither)
        try await passkeyContext(neither).loginWithPasskey(expirationSeconds: "0")
        #expect(requested(neither) == ["900"])
        // No Auth Proxy configuration at all: local, else 900, and nothing is fetched.
        let plain = MockServer()
        loginRoute(plain)
        try await passkeyContext(plain, configId: nil, local: "3600").loginWithPasskey(expirationSeconds: "0")
        try await passkeyContext(plain, configId: nil).loginWithPasskey(expirationSeconds: "0")
        #expect(requested(plain) == ["3600", "900"])
        #expect(plain.requests(to: "/v1/wallet_kit_config").isEmpty)
    }

    @Test func aUsableArgumentIsSentTrimmedAndNormalised() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(server)
        let ctx = passkeyContext(server, local: "3600")
        try await ctx.loginWithPasskey(expirationSeconds: " 120 ")
        try await ctx.loginWithPasskey(expirationSeconds: "+60")
        try await ctx.loginWithPasskey(expirationSeconds: "1")
        #expect(requested(server) == ["120", "60", "1"])
        #expect(server.requests(to: "/v1/wallet_kit_config").isEmpty)
    }

    // MARK: - Dashboard layer

    @Test(arguments: SessionDurationTests.unusable)
    func unusableDashboardValueFallsBackToLocal(_ remote: String?) async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(remote))
        loginRoute(server)
        try await passkeyContext(server, local: "3600").loginWithPasskey()
        #expect(requested(server) == ["3600"], "\(String(describing: remote))")
    }

    @Test(arguments: SessionDurationTests.unusable)
    func unusableDashboardAndLocalValuesFallBackTo900(_ bad: String?) async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(bad))
        loginRoute(server)
        try await passkeyContext(server, local: bad).loginWithPasskey()
        #expect(requested(server) == ["900"], "\(String(describing: bad))")
    }

    @Test func aDashboardValueIsSentTrimmedAndNormalised() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig(" +1800 "))
        loginRoute(server)
        try await passkeyContext(server, local: "3600").loginWithPasskey()
        #expect(requested(server) == ["1800"])
    }

    // MARK: - Local layer

    @Test(arguments: SessionDurationTests.unusable)
    func unusableLocalValueFallsBackTo900(_ local: String?) async throws {
        // With an Auth Proxy configuration that has no duration, and without any Auth Proxy configuration.
        let withProxy = MockServer()
        withProxy.on("/v1/wallet_kit_config", respond: kitConfig(nil))
        loginRoute(withProxy)
        try await passkeyContext(withProxy, local: local).loginWithPasskey()
        #expect(requested(withProxy) == ["900"], "\(String(describing: local))")
        let plain = MockServer()
        loginRoute(plain)
        try await passkeyContext(plain, configId: nil, local: local).loginWithPasskey()
        #expect(requested(plain) == ["900"], "\(String(describing: local))")
    }

    @Test func aLocalValueIsSentTrimmedAndNormalised() async throws {
        let server = MockServer()
        loginRoute(server)
        try await passkeyContext(server, configId: nil, local: " 3600 ").loginWithPasskey()
        #expect(requested(server) == ["3600"])
    }

    /// A Dashboard value beats a local one only when it is usable; an unusable Dashboard value never
    /// hides a usable local one, and a usable argument beats all of it.
    @Test func everyLayerFallsThroughIndependently() async throws {
        for (argument, remote, local, expected) in [
            ("0", "1800", "3600", "1800"), ("abc", "0", "3600", "3600"), ("-1", "x", "0", "900"),
            ("", "", "", "900"), (nil, "1800", "0", "1800"), ("60", "0", "0", "60"), ("0", "0", "7200", "7200"),
        ] as [(String?, String, String, String)] {
            let server = MockServer()
            server.on("/v1/wallet_kit_config", respond: kitConfig(remote))
            loginRoute(server)
            try await passkeyContext(server, local: local).loginWithPasskey(expirationSeconds: argument)
            #expect(requested(server) == [expected], "arg \(String(describing: argument)) remote \(remote) local \(local)")
        }
    }

    // MARK: - Every stamp_login path resolves through the chain

    @Test func refreshWithAZeroArgumentUsesTheDashboardDuration() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
        loginRoute(server)
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-parent", userId: "u", exp: Self.t0 + 900))
        try await ctx.refreshSession(expirationSeconds: "0")
        try await ctx.refreshSession(expirationSeconds: "abc")
        try await ctx.refreshSession(expirationSeconds: "")
        try await ctx.refreshSession(expirationSeconds: "60")
        #expect(requested(server) == ["1800", "1800", "1800", "60"])
    }

    @Test func otpLoginWithAZeroArgumentUsesTheDashboardDuration() async throws {
        for (argument, expected) in [("0", "1800"), ("-1", "1800"), ("90", "90")] {
            let server = MockServer()
            server.on("/v1/wallet_kit_config", respond: kitConfig("1800"))
            loginRoute(server)
            let ctx = makeContext(server, sessionExpirationSeconds: "3600")
            let key = try ctx.createKeyPair()
            let vt = APIFixtures.jwt(["id": "vt-z", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
            try await ctx.loginWithOtp(verificationToken: vt, organizationId: "org-parent", expirationSeconds: argument)
            #expect(requested(server) == [expected], "argument \(argument)")
        }
    }

    @Test func otpLoginFallsBackToLocalWhenTheDashboardValueIsUnusable() async throws {
        let server = MockServer()
        server.on("/v1/wallet_kit_config", respond: kitConfig("0"))
        loginRoute(server)
        let ctx = makeContext(server, sessionExpirationSeconds: "3600")
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-l", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
        try await ctx.loginWithOtp(verificationToken: vt, organizationId: "org-parent")
        #expect(requested(server) == ["3600"])
    }
}
