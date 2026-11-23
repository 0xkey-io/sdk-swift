import Foundation
import Testing
@_spi(Experimental) import ZeroXKey
import ZeroXKeyCrypto
import ZeroXKeyStamper
import ZeroXKeyTestSupport

/// Experimental API (`@_spi(Experimental)`): the 0xkey servers reject attested scoped logins today.
@Suite("Scoped session recovery (experimental; OTP + MFA approval)") @MainActor
struct ScopedRecoveryTests {
    nonisolated static let t0: TimeInterval = 1_763_500_000
    nonisolated static let org = "org-sub"

    struct Env {
        let ctx: ZeroXKeyContext
        let server: MockServer
        let key: String
        let vt: String
    }

    func env(_ server: MockServer = MockServer(), rpId: String? = nil,
             assertion: (any PasskeyAssertionProvider)? = nil) throws -> Env {
        let ctx = makeContext(server, rpId: rpId, assertion: assertion)
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-r", "public_key": key, "contact": "a@example.org", "verification_type": "OTP_TYPE_EMAIL"])
        return Env(ctx: ctx, server: server, key: key, vt: vt)
    }

    nonisolated static func scopedJWT(_ key: String) -> String {
        APIFixtures.jwt(["exp": t0 + 600, "public_key": key, "session_type": "SESSION_TYPE_READ_WRITE", "user_id": "u-1",
                         "organization_id": Self.org, "session_profile_id": "sp-recovery", "scope": "recovery"])
    }

    nonisolated static func held(status: String = "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED", result: [String: Any] = [:]) -> [String: Any] {
        APIFixtures.activity(id: "act-login", organizationId: org, status: status, type: "ACTIVITY_TYPE_STAMP_LOGIN",
                             result: result, fingerprint: "fp-login")
    }

    nonisolated(unsafe) static let mfaStatus: [String: Any] = [
        "mfaPolicyId": "mp-1", "userId": "u-1", "satisfied": false, "satisfiedMethods": [String](),
        "requiredMethods": [["any": [["type": "AUTHENTICATION_TYPE_PASSKEY"]]]],
    ]

    /// Routes for a login held by MFA, approved, then completed on the n-th poll.
    func holdThenComplete(_ e: Env, completeOnPoll: Int) {
        e.server.on("/public/v1/submit/stamp_login", respond: .json(APIFixtures.activityResponse(Self.held())))
        e.server.on("/public/v1/query/get_mfa_status", respond: .json(["mfaStatuses": [Self.mfaStatus]]))
        e.server.on("/public/v1/submit/approve_activity", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            id: "act-approve", organizationId: Self.org, status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_APPROVE_ACTIVITY"))))
        let jwt = Self.scopedJWT(e.key)
        e.server.on("/public/v1/query/get_activity") { _, n in
            // n == 0 is beginOtpLogin's fingerprint lookup; resume polls start at n == 1.
            n >= completeOnPoll
                ? .json(APIFixtures.activityResponse(Self.held(status: "ACTIVITY_STATUS_COMPLETED",
                                                               result: ["stampLoginResult": ["session": jwt]])))
                : .json(APIFixtures.activityResponse(Self.held()))
        }
    }

    @Test func fullFlowOtpHeldApprovedResumed() async throws {
        let e = try env(rpId: "login.example.org")
        holdThenComplete(e, completeOnPoll: 3)

        let outcome = try await e.ctx.beginOtpLogin(verificationToken: e.vt, organizationId: Self.org, sessionProfileId: "sp-recovery")
        guard case .mfaRequired(let pending) = outcome else { Issue.record("expected mfaRequired, got \(outcome)"); return }
        #expect(pending.activityId == "act-login" && pending.fingerprint == "fp-login" && pending.organizationId == Self.org)
        #expect(pending.mfaStatuses.map(\.mfaPolicyId) == ["mp-1"])
        #expect(pending.sessionProfileId == "sp-recovery" && pending.publicKey == e.key)
        #expect(e.ctx.session == nil)

        // stamp_login carries the session profile and is attested by the verification token.
        let login = try #require(e.server.requests(to: "/public/v1/submit/stamp_login").first)
        let params = try #require(login.json["parameters"] as? [String: Any])
        #expect(params["sessionProfileId"] as? String == "sp-recovery")
        #expect(params["publicKey"] as? String == e.key)
        _ = try verifyStamp(login, header: "X-Stamp-Attested", publicKey: e.key)
        #expect(e.server.requests(to: "/v1/otp_login_v2").isEmpty)

        // Second factor: an API key of another credential approves the held activity.
        let approver = generateP256KeyPair()
        let approverStamper = try ApiKeyStamper(apiPublicKey: approver.publicKey, apiPrivateKey: approver.privateKey)
        _ = try await e.ctx.approvePendingLogin(pending, stamper: approverStamper)
        let approve = try #require(e.server.requests(to: "/public/v1/submit/approve_activity").first)
        _ = try verifyStamp(approve, publicKey: approver.publicKey)
        #expect(approve.json["type"] as? String == "ACTIVITY_TYPE_APPROVE_ACTIVITY")
        #expect(approve.json["organizationId"] as? String == Self.org)
        #expect((approve.json["parameters"] as? [String: String]) == ["fingerprint": "fp-login"])

        let jwt = try await e.ctx.resumeOtpLogin(pending, intervalSeconds: 0)
        #expect(e.server.requests(to: "/public/v1/query/get_activity").count == 4)   // lookup + 3 polls
        for poll in e.server.requests(to: "/public/v1/query/get_activity") {
            #expect(poll.json["activityId"] as? String == "act-login")
            _ = try verifyStamp(poll, header: "X-Stamp-Attested", publicKey: e.key)
        }
        #expect(e.ctx.session?.token == jwt)
        #expect(e.ctx.session?.sessionProfileId == "sp-recovery" && e.ctx.session?.scope == "recovery")
        #expect(e.ctx.authState == .authenticated)
    }

    @Test func notHeldCompletesDirectly() async throws {
        let e = try env()
        let jwt = Self.scopedJWT(e.key)
        e.server.on("/public/v1/submit/stamp_login", respond: .json(APIFixtures.activityResponse(Self.held(
            status: "ACTIVITY_STATUS_COMPLETED", result: ["stampLoginResult": ["session": jwt]]))))
        let outcome = try await e.ctx.beginOtpLogin(verificationToken: e.vt, organizationId: Self.org, sessionProfileId: "sp-recovery")
        #expect(outcome == .completed(session: jwt))
        #expect(e.ctx.session?.scope == "recovery")
        #expect(e.server.requests(to: "/public/v1/query/get_activity").isEmpty)
    }

    @Test func approveWithPasskeyUsesConfiguredRpId() async throws {
        let asserter = FakeAsserter()
        let e = try env(rpId: "login.example.org", assertion: asserter)
        holdThenComplete(e, completeOnPoll: 1)
        guard case .mfaRequired(let pending) = try await e.ctx.beginOtpLogin(verificationToken: e.vt, organizationId: Self.org)
        else { Issue.record("expected mfaRequired"); return }
        _ = try await e.ctx.approvePendingLoginWithPasskey(pending)
        #expect(asserter.seen.first?.rpId == "login.example.org")
        let approve = try #require(e.server.requests(to: "/public/v1/submit/approve_activity").first)
        #expect(approve.header("X-Stamp-Webauthn") != nil && approve.header("X-Stamp") == nil)
    }

    @Test func rejectedApprovalSurfacesAndStoresNothing() async throws {
        let e = try env()
        e.server.on("/public/v1/submit/stamp_login", respond: .json(APIFixtures.activityResponse(Self.held())))
        e.server.on("/public/v1/query/get_mfa_status", respond: .json(["mfaStatuses": [Self.mfaStatus]]))
        e.server.on("/public/v1/query/get_activity") { _, n in
            .json(APIFixtures.activityResponse(Self.held(status: n == 0 ? "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED" : "ACTIVITY_STATUS_REJECTED")))
        }
        guard case .mfaRequired(let pending) = try await e.ctx.beginOtpLogin(verificationToken: e.vt, organizationId: Self.org)
        else { Issue.record("expected mfaRequired"); return }
        await #expect(throws: ZeroXKeyActivityError.rejected(activityId: "act-login")) { try await e.ctx.resumeOtpLogin(pending, intervalSeconds: 0) }
        #expect(e.ctx.session == nil)
    }

    @Test func stillHeldAfterMaxAttemptsReportsFreshMfaStatus() async throws {
        let e = try env()
        holdThenComplete(e, completeOnPoll: 100)
        guard case .mfaRequired(let pending) = try await e.ctx.beginOtpLogin(verificationToken: e.vt, organizationId: Self.org)
        else { Issue.record("expected mfaRequired"); return }
        do {
            _ = try await e.ctx.resumeOtpLogin(pending, maxAttempts: 4, intervalSeconds: 0)
            Issue.record("expected authenticatorsNeeded")
        } catch ZeroXKeyActivityError.authenticatorsNeeded(let id, let statuses) {
            #expect(id == "act-login" && statuses.map(\.mfaPolicyId) == ["mp-1"])
        }
        #expect(e.server.requests(to: "/public/v1/query/get_activity").count == 5)
        #expect(e.server.requests(to: "/public/v1/query/get_mfa_status").count == 2)
    }

    @Test func scopedLoginWithOtpNeverFallsBackToAuthProxy() async throws {
        let e = try env()
        e.server.on("/public/v1/submit/stamp_login", respond: .text("Unauthorized\n", status: 401))
        e.server.on("/v1/otp_login_v2", respond: .json(["session": Self.scopedJWT(e.key)]))
        await #expect(throws: ZeroXKeyRequestError.self) {
            try await e.ctx.loginWithOtp(verificationToken: e.vt, organizationId: Self.org, sessionProfileId: "sp-recovery")
        }
        #expect(e.server.requests(to: "/v1/otp_login_v2").isEmpty)
        // Unscoped logins keep the fallback.
        _ = try await e.ctx.loginWithOtp(verificationToken: e.vt, organizationId: Self.org)
        #expect(e.server.requests(to: "/v1/otp_login_v2").count == 1)
    }

    @Test func refreshKeepsSessionProfile() async throws {
        let e = try env()
        try await e.ctx.storeSession(jwt: Self.scopedJWT(e.key))
        e.server.on("/public/v1/submit/stamp_login") { req, _ in
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return .json(APIFixtures.activityResponse(Self.held(status: "ACTIVITY_STATUS_COMPLETED",
                                                                result: ["stampLoginResult": ["session": Self.scopedJWT(pk)]])))
        }
        try await e.ctx.refreshSession()
        let params = try #require(e.server.requests(to: "/public/v1/submit/stamp_login").first?.json["parameters"] as? [String: Any])
        #expect(params["sessionProfileId"] as? String == "sp-recovery")
    }

    func pending(_ e: Env) async throws -> PendingOtpLogin {
        e.server.on("/public/v1/submit/stamp_login", respond: .json(APIFixtures.activityResponse(Self.held())))
        e.server.on("/public/v1/query/get_mfa_status", respond: .json(["mfaStatuses": [Self.mfaStatus]]))
        guard case .mfaRequired(let p) = try await e.ctx.beginOtpLogin(verificationToken: e.vt, organizationId: Self.org) else {
            throw ZeroXKeyError.badResponse("expected mfaRequired")
        }
        return p
    }

    @Test func pendingLoginNeverPrintsTheVerificationToken() async throws {
        let e = try env()
        e.server.on("/public/v1/query/get_activity", respond: .json(APIFixtures.activityResponse(Self.held())))
        let p = try await pending(e)
        var dumped = ""
        dump(p, to: &dumped)
        for text in [String(describing: p), String(reflecting: p), "\(p)", dumped] {
            #expect(!text.contains(e.vt), "\(text)")
            #expect(text.contains("<redacted>") && text.contains("act-login"))
        }
    }

    @Test func resumeStopsOnMissingActivity() async throws {
        let e = try env()
        e.server.on("/public/v1/query/get_activity") { _, n in
            n == 0 ? .json(APIFixtures.activityResponse(Self.held())) : .json(["activity": NSNull()])
        }
        let p = try await pending(e)
        await #expect(throws: ZeroXKeyError.badResponse("get_activity returned no activity for act-login")) {
            try await e.ctx.resumeOtpLogin(p, maxAttempts: 30, intervalSeconds: 0)
        }
        #expect(e.server.requests(to: "/public/v1/query/get_activity").count == 2)
    }

    @Test func resumeKeepsFailureDetails() async throws {
        let e = try env()
        e.server.on("/public/v1/query/get_activity") { _, n in
            var a = Self.held(status: n == 0 ? "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED" : "ACTIVITY_STATUS_FAILED")
            if n > 0 { a["failure"] = ["code": 9, "message": "policy denied"] }
            return .json(APIFixtures.activityResponse(a))
        }
        let p = try await pending(e)
        do {
            _ = try await e.ctx.resumeOtpLogin(p, intervalSeconds: 0)
            Issue.record("expected failed")
        } catch ZeroXKeyActivityError.failed(let id, let status, let failure) {
            #expect(id == "act-login" && status == "ACTIVITY_STATUS_FAILED")
            #expect(failure == .object(["code": .number(9), "message": .string("policy denied")]))
        }
    }

    @Test func resumeReportsConsensusNotMfa() async throws {
        let e = try env()
        e.server.on("/public/v1/query/get_activity") { _, n in
            .json(APIFixtures.activityResponse(Self.held(status: n == 0 ? "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED" : "ACTIVITY_STATUS_CONSENSUS_NEEDED")))
        }
        let p = try await pending(e)
        await #expect(throws: ZeroXKeyActivityError.consensusNeeded(activityId: "act-login", fingerprint: "fp-login")) {
            try await e.ctx.resumeOtpLogin(p, intervalSeconds: 0)
        }
        #expect(e.server.requests(to: "/public/v1/query/get_activity").count == 2)
    }

    @Test func undecodableMfaStatusIsNotSwallowed() async throws {
        let e = try env()
        holdThenComplete(e, completeOnPoll: 100)
        let p = try await pending(e)
        e.server.on("/public/v1/query/get_mfa_status", respond: .json(["mfaStatuses": [["mfaPolicyId": 7]]]))
        await #expect(throws: ZeroXKeyHttpError.self) { try await e.ctx.resumeOtpLogin(p, maxAttempts: 2, intervalSeconds: 0) }
    }
}
