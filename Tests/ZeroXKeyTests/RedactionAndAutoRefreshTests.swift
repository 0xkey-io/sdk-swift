import Foundation
import Testing
import ZeroXKey
import ZeroXKeyEncoding
import ZeroXKeyHttp
import ZeroXKeyTestSupport

@Suite("Verification token redaction") @MainActor
struct VerifyOtpResultRedactionTests {
    @Test func neverPrintsTheVerificationToken() async throws {
        let otpFx: OtpFixture = try Fixtures.load("otp-bundle")
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-r", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
        server.on("/v1/otp_verify_v2", respond: .json(["verificationToken": vt]))
        server.on("/v1/account", respond: .json(["organizationId": "org-existing"]))
        let result = try await ctx.verifyOtp(
            otpId: "o", otpCode: otpFx.otpCode, otpEncryptionTargetBundle: otpFx.otpEncryptionTargetBundle,
            contact: "a@b.c", otpType: .email, publicKey: key)
        var dumped = ""
        dump(result, to: &dumped)
        for text in [String(describing: result), String(reflecting: result), "\(result)", dumped] {
            #expect(!text.contains(vt), "\(text)")
            #expect(text.contains("<redacted>") && text.contains("org-existing"))
        }
        #expect(result.verificationToken == vt)
    }
}

/// Automatic refresh is tracked per session slot, and a refresh that the user's own logout or
/// switch made obsolete is not reported as a failed renewal.
@Suite("Automatic refresh per session slot") @MainActor
struct AutoRefreshSlotTests {
    nonisolated static let t0: TimeInterval = 1_763_500_000

    final class Log {
        var events: [String] = []
    }

    /// `stamp_login` answers for the stamping key's organization; requests stamped by `slow` wait.
    func loginRoute(_ server: MockServer, orgs: [String: String], slow: String? = nil, delay: TimeInterval = 0.3) {
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let stamp = (try? stampPublicKey(req)) ?? ""
            if stamp == slow { Thread.sleep(forTimeInterval: delay) }
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            let org = orgs[stamp] ?? "unknown"
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                organizationId: org, status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(
                    publicKey: pk, organizationId: org, userId: "u", exp: Self.t0 + 3600)]])))
        }
    }

    func record(_ ctx: ZeroXKeyContext) -> Log {
        let log = Log()
        ctx.onSessionEvent = { e in
            switch e {
            case .refreshed: log.events.append("refreshed")
            case .refreshFailed(let k, _): log.events.append("refreshFailed:\(k)")
            case .expired(let k): log.events.append("expired:\(k)")
            }
        }
        return log
    }

    @Test func logoutDuringAutomaticRefreshReportsNoFailure() async throws {
        let server = MockServer()
        let time = TestTime(longReleases: 1)
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys, autoRefresh: true, clock: time.clock)
        ctx.sleep = time.sleeper
        let log = record(ctx)
        let a = try ctx.createKeyPair()
        loginRoute(server, orgs: [a: "org-a"], slow: a)
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: a, organizationId: "org-a", userId: "u", exp: Self.t0 + 900))

        // The timer fires (released), the refresh is on the wire; the user logs out.
        #expect(await eventually { server.requests(to: "/public/v1/submit/stamp_login").count == 1 })
        try ctx.logout()
        try await Task.sleep(nanoseconds: 700_000_000)   // let the discarded refresh finish

        #expect(ctx.session == nil && ctx.authState != .authenticated)
        #expect(try keys.listPublicKeys().isEmpty)
        #expect(log.events.isEmpty, "\(log.events)")
    }

    @Test func aGenuineFailureIsStillReported() async throws {
        let server = MockServer()
        let time = TestTime(longReleases: 1)
        let ctx = makeContext(server, autoRefresh: true, clock: time.clock)
        ctx.sleep = time.sleeper
        let log = record(ctx)
        server.on("/public/v1/submit/stamp_login", respond: .text("Unauthorized: session revoked\n", status: 401))
        let a = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: a, organizationId: "org-a", userId: "u", exp: Self.t0 + 900))
        #expect(await eventually { log.events == ["refreshFailed:\(ZeroXKeySessionKey.default)"] })
    }

    /// Session A is being refreshed when the user switches to session B, which is already within
    /// the lead time. B's refresh must run on its own, not join A's (discarded) one.
    @Test func switchingSessionsDoesNotStarveTheNewOnesRefresh() async throws {
        let server = MockServer()
        let time = TestTime(longReleases: 1)
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys, autoRefresh: true, clock: time.clock)
        ctx.sleep = time.sleeper
        let log = record(ctx)
        let a = try ctx.createKeyPair()
        let b = try ctx.createKeyPair()
        loginRoute(server, orgs: [a: "org-a", b: "org-b"], slow: a)
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: a, organizationId: "org-a", userId: "ua", exp: Self.t0 + 900), sessionKey: "a")
        #expect(await eventually { server.requests(to: "/public/v1/submit/stamp_login").count == 1 })   // A in flight

        // B has 40 s left at the (advanced) clock: inside the 60 s lead, so its timer refreshes at once.
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: b, organizationId: "org-b", userId: "ub", exp: Self.t0 + 880), sessionKey: "b")
        #expect(await eventually { ctx.session?.organizationId == "org-b" && ctx.session?.publicKey != b })
        #expect(server.requests(to: "/public/v1/submit/stamp_login").count == 2)
        let stampers = try server.requests(to: "/public/v1/submit/stamp_login").map(stampPublicKey)
        #expect(Set(stampers) == [a, b])
        try await Task.sleep(nanoseconds: 700_000_000)   // A's discarded refresh ends

        #expect(log.events == ["refreshed"], "\(log.events)")   // only B's; A's was superseded, not failed
        #expect(try ctx.activeSessionKey() == "b")
        let storedA = try #require(try ctx.storedSession(sessionKey: "a"))
        #expect(storedA.publicKey == a)   // A untouched
    }
}
