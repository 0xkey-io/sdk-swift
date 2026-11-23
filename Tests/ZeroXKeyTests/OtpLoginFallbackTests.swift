import Foundation
import Testing
import ZeroXKey
import ZeroXKeyHttp
import ZeroXKeyTestSupport

/// One failed attested `stamp_login`: the HTTP status and raw body the gateway answered with, and whether
/// the rule (sdk-js `isAttestedLoginUnavailable`, `packages/core/src/utils.ts:1232-1269`) lets
/// `loginWithOtp` fall back to Auth Proxy `otp_login_v2`.
struct OtpFallbackCase: Sendable, CustomTestStringConvertible {
    let label: String
    let status: Int
    let body: String
    let fallsBack: Bool

    var testDescription: String { "\(label), HTTP \(status) -> \(fallsBack ? "falls back" : "no fallback")" }

    var error: ZeroXKeyRequestError { ZeroXKeyRequestError.parse(httpStatus: status, body: Data(body.utf8)) }
    var response: MockResponse { MockResponse(status: status, body: Data(body.utf8)) }
}

/// The branches of the rule, one table per branch. Used by the rule's unit tests and by the flow tests.
enum OtpFallbackTable {
    static func info(_ reason: String, typed: Bool = true) -> String {
        typed
            ? #"{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"\#(reason)","domain":"gateway.example.test"}"#
            : #"{"reason":"\#(reason)"}"#
    }

    /// A gRPC status body (`ZeroXKeyRequestError.Kind.grpcStatus`) whose details carry `reasons`.
    static func grpc(_ reasons: [String] = [], typed: Bool = true) -> String {
        let details = reasons.map { info($0, typed: typed) }.joined(separator: ",")
        return #"{"code":3,"message":"rejected","details":[\#(details)]}"#
    }

    static func make(_ label: String, _ statuses: [Int], body: String, fallsBack: Bool) -> [OtpFallbackCase] {
        statuses.map { OtpFallbackCase(label: label, status: $0, body: body, fallsBack: fallsBack) }
    }

    // MARK: Not JSON: sdk-js ZeroXKeyHttpError

    /// Plain text 401, 404, 501, 503: the server cannot take attested logins.
    static let plainTextFallsBack: [OtpFallbackCase] = {
        var r = make("plain text", [401, 404, 501, 503], body: "Unauthorized\n", fallsBack: true)
        r += make("plain text 404 page", [404], body: "404 page not found\n", fallsBack: true)
        return r
    }()

    /// Any other plain text status, 403 included.
    static let plainTextOtherStatuses: [OtpFallbackCase] = make(
        "plain text", [400, 403, 408, 409, 429, 500, 502, 504], body: "upstream said no", fallsBack: false)

    /// An empty body is not JSON either (`response.json()` throws), so the same status rule applies.
    static let emptyBody: [OtpFallbackCase] = {
        var r = make("empty body", [401, 404, 501, 503], body: "", fallsBack: true)
        r += make("empty body", [400, 403, 500, 502], body: "", fallsBack: false)
        return r
    }()

    // MARK: JSON that is not a gRPC status: still sdk-js ZeroXKeyRequestError (anything `response.json()` accepts)

    static let jsonWithoutCodeOrMessage: [OtpFallbackCase] = {
        let error = #"{"error":"x"}"#
        let notEnabled = #"{"details":[{"reason":"ATTESTED_STAMP_NOT_ENABLED"}]}"#
        let loginReason = #"{"details":[{"reason":"ATTESTED_LOGIN_MFA_REQUIRED"}]}"#
        var r = make("JSON object without code or message", [404, 501, 503], body: error, fallsBack: true)
        r += make("JSON object without code or message", [400, 401, 403, 500], body: error, fallsBack: false)
        r += make("JSON array", [401, 500], body: "[]", fallsBack: false)
        r += make("JSON number", [503], body: "123", fallsBack: true)
        r += make("JSON string", [401], body: #""denied""#, fallsBack: false)
        // `null` makes sdk-js's `new ZeroXKeyRequestError(null)` throw inside the `try`, so it is an HttpError.
        r += make("JSON null", [401, 404, 501, 503], body: "null", fallsBack: true)
        r += make("JSON null", [400, 403, 500], body: "null", fallsBack: false)
        r += make("details only, ATTESTED_STAMP_NOT_ENABLED", [400, 401], body: notEnabled, fallsBack: true)
        r += make("details only, ATTESTED_LOGIN_ reason", [404, 503], body: loginReason, fallsBack: false)
        r += make("details only, ATTESTED_STAMP_NOT_ENABLED", [403], body: notEnabled, fallsBack: false)
        return r
    }()

    // MARK: Structured (sdk-js ZeroXKeyRequestError)

    /// 403 never falls back (it can be an MFA requirement), whatever the reasons say.
    static let status403: [OtpFallbackCase] = {
        var r = make("403 without reasons", [403], body: grpc(), fallsBack: false)
        r += make("403 with ATTESTED_STAMP_NOT_ENABLED", [403], body: grpc(["ATTESTED_STAMP_NOT_ENABLED"]), fallsBack: false)
        r += make("403 with ATTESTED_LOGIN_ reason", [403], body: grpc(["ATTESTED_LOGIN_MFA_REQUIRED"]), fallsBack: false)
        r += make("403 with another reason", [403], body: grpc(["SOMETHING_ELSE"]), fallsBack: false)
        return r
    }()

    /// A reason starting with `ATTESTED_LOGIN_` never falls back, even on 404/501/503 and even next to
    /// `ATTESTED_STAMP_NOT_ENABLED`.
    static let attestedLoginReason: [OtpFallbackCase] = {
        var r = make("ATTESTED_LOGIN_ reason", [400, 401, 404, 500, 501, 503],
                     body: grpc(["ATTESTED_LOGIN_MFA_REQUIRED"]), fallsBack: false)
        r += make("ATTESTED_LOGIN_ after ATTESTED_STAMP_NOT_ENABLED", [400, 404],
                  body: grpc(["ATTESTED_STAMP_NOT_ENABLED", "ATTESTED_LOGIN_MFA_REQUIRED"]), fallsBack: false)
        r += make("ATTESTED_LOGIN_ before ATTESTED_STAMP_NOT_ENABLED", [404],
                  body: grpc(["ATTESTED_LOGIN_MFA_REQUIRED", "ATTESTED_STAMP_NOT_ENABLED"]), fallsBack: false)
        r += make("ATTESTED_LOGIN_ reason without @type", [404],
                  body: grpc(["ATTESTED_LOGIN_MFA_REQUIRED"], typed: false), fallsBack: false)
        return r
    }()

    /// `ATTESTED_STAMP_NOT_ENABLED` falls back for any status except 403 (and a missing one).
    static let stampNotEnabled: [OtpFallbackCase] = {
        var r = make("ATTESTED_STAMP_NOT_ENABLED", [400, 401, 404, 409, 500, 501, 503],
                     body: grpc(["ATTESTED_STAMP_NOT_ENABLED"]), fallsBack: true)
        r += make("ATTESTED_STAMP_NOT_ENABLED without @type", [400],
                  body: grpc(["ATTESTED_STAMP_NOT_ENABLED"], typed: false), fallsBack: true)
        r += make("ATTESTED_STAMP_NOT_ENABLED next to another ATTESTED_ reason", [400, 404],
                  body: grpc(["ATTESTED_STAMP_INVALID", "ATTESTED_STAMP_NOT_ENABLED"]), fallsBack: true)
        r += make("ATTESTED_STAMP_NOT_ENABLED next to an unrelated reason", [400],
                  body: grpc(["SOMETHING_ELSE", "ATTESTED_STAMP_NOT_ENABLED"]), fallsBack: true)
        return r
    }()

    /// Any other `ATTESTED_` reason: the server checked the stamp and refused it.
    static let otherAttestedReasons: [OtpFallbackCase] = {
        var r = make("ATTESTED_STAMP_INVALID", [400, 401, 404, 501, 503], body: grpc(["ATTESTED_STAMP_INVALID"]), fallsBack: false)
        r += make("ATTESTED_STAMP_EXPIRED", [503], body: grpc(["ATTESTED_STAMP_EXPIRED"]), fallsBack: false)
        r += make("ATTESTED_ALGORITHM_UNSUPPORTED", [404], body: grpc(["ATTESTED_ALGORITHM_UNSUPPORTED"]), fallsBack: false)
        r += make("ATTESTED_STAMP_INVALID without @type", [404], body: grpc(["ATTESTED_STAMP_INVALID"], typed: false), fallsBack: false)
        return r
    }()

    /// Reasons that are not `ATTESTED_`: the status decides, 404, 501 and 503 only.
    static let otherReasonsUseTheStatus: [OtpFallbackCase] = {
        let numeric = #"{"code":3,"message":"m","details":[{"reason":5}]}"#
        let notObjects = #"{"code":3,"message":"m","details":["x",3,null]}"#
        var r = make("WEBAUTHN_RP_ID_NOT_ALLOWED", [404, 501, 503], body: grpc(["WEBAUTHN_RP_ID_NOT_ALLOWED"]), fallsBack: true)
        r += make("WEBAUTHN_RP_ID_NOT_ALLOWED", [400, 401, 409, 500, 502, 504], body: grpc(["WEBAUTHN_RP_ID_NOT_ALLOWED"]), fallsBack: false)
        // The match is case sensitive and needs the exact prefix / value.
        r += make("lower-case attested_stamp_not_enabled", [404], body: grpc(["attested_stamp_not_enabled"]), fallsBack: true)
        r += make("lower-case attested_stamp_not_enabled", [400], body: grpc(["attested_stamp_not_enabled"]), fallsBack: false)
        r += make("lower-case attested_login_", [404], body: grpc(["attested_login_mfa"]), fallsBack: true)
        // Only a string `reason` counts.
        r += make("numeric reason", [404, 503], body: numeric, fallsBack: true)
        r += make("numeric reason", [400], body: numeric, fallsBack: false)
        r += make("details that are not objects", [404], body: notObjects, fallsBack: true)
        r += make("details that are not objects", [401], body: notObjects, fallsBack: false)
        return r
    }()

    /// No reasons at all: 404, 501 and 503 fall back; 400, 401, 500, ... do not.
    static let noReasonsUseTheStatus: [OtpFallbackCase] = {
        let missing = #"{"code":5,"message":"m"}"#
        var r = make("no details", [404, 501, 503], body: grpc(), fallsBack: true)
        r += make("no details", [400, 401, 409, 500, 502, 504], body: grpc(), fallsBack: false)
        r += make("details missing", [404, 501, 503], body: missing, fallsBack: true)
        r += make("details missing", [400, 401, 500], body: missing, fallsBack: false)
        return r
    }()

    static let all: [OtpFallbackCase] = {
        let groups: [[OtpFallbackCase]] = [
            plainTextFallsBack, plainTextOtherStatuses, emptyBody, jsonWithoutCodeOrMessage, status403,
            attestedLoginReason, stampNotEnabled, otherAttestedReasons, otherReasonsUseTheStatus, noReasonsUseTheStatus,
        ]
        return groups.flatMap { $0 }
    }()
    static let fallbacks: [OtpFallbackCase] = all.filter { $0.fallsBack }
    static let noFallbacks: [OtpFallbackCase] = all.filter { !$0.fallsBack }
}

/// The rule itself (pure function), branch by branch. Mirrors sdk-js `isAttestedLoginUnavailable`.
@Suite("OTP login fallback rule")
struct OtpLoginFallbackRuleTests {
    private func verdict(_ c: OtpFallbackCase) -> Bool {
        ZeroXKeyContext.isAttestedLoginUnavailable(c.error)
    }

    // Not JSON (sdk-js ZeroXKeyHttpError): status 401, 404, 501, 503 only.

    @Test(arguments: OtpFallbackTable.plainTextFallsBack)
    func plainTextOn401404501503FallsBack(_ c: OtpFallbackCase) {
        #expect(c.error.kind == .plainText)
        #expect(verdict(c) == true)
    }

    @Test(arguments: OtpFallbackTable.plainTextOtherStatuses)
    func plainTextOnOtherStatusesDoesNotFallBack(_ c: OtpFallbackCase) {
        #expect(c.error.kind == .plainText)
        #expect(verdict(c) == false)
    }

    @Test(arguments: OtpFallbackTable.emptyBody)
    func emptyBodyFollowsThePlainTextStatusRule(_ c: OtpFallbackCase) {
        #expect(c.error.kind == .empty)
        #expect(verdict(c) == c.fallsBack)
    }

    @Test(arguments: OtpFallbackTable.jsonWithoutCodeOrMessage)
    func jsonThatIsNotAGrpcStatusIsStillJudgedLikeSdkJs(_ c: OtpFallbackCase) {
        #expect(verdict(c) == c.fallsBack)
    }

    // Structured (sdk-js ZeroXKeyRequestError).

    @Test func aStructuredErrorWithoutAnHttpStatusNeverFallsBack() {
        let notEnabled = JSONValue.object(["reason": .string("ATTESTED_STAMP_NOT_ENABLED")])
        for details in [[], [notEnabled]] as [[JSONValue]] {
            for code in [5, 12, 14] {
                let error = ZeroXKeyRequestError(
                    httpStatus: 0, kind: .grpcStatus, code: code, message: "m", details: details, retryAfter: nil, rawBody: "")
                #expect(ZeroXKeyContext.isAttestedLoginUnavailable(error) == false)
            }
        }
    }

    @Test(arguments: OtpFallbackTable.status403)
    func structured403NeverFallsBack(_ c: OtpFallbackCase) {
        #expect(c.error.kind == .grpcStatus)
        #expect(verdict(c) == false)
    }

    @Test(arguments: OtpFallbackTable.attestedLoginReason)
    func anAttestedLoginReasonNeverFallsBack(_ c: OtpFallbackCase) {
        #expect(verdict(c) == false)
    }

    @Test(arguments: OtpFallbackTable.stampNotEnabled)
    func attestedStampNotEnabledFallsBack(_ c: OtpFallbackCase) {
        #expect(verdict(c) == true)
    }

    @Test(arguments: OtpFallbackTable.otherAttestedReasons)
    func anyOtherAttestedReasonDoesNotFallBack(_ c: OtpFallbackCase) {
        #expect(verdict(c) == false)
    }

    @Test(arguments: OtpFallbackTable.otherReasonsUseTheStatus)
    func reasonsThatAreNotAttestedLeaveTheDecisionToTheStatus(_ c: OtpFallbackCase) {
        #expect(verdict(c) == c.fallsBack)
    }

    @Test(arguments: OtpFallbackTable.noReasonsUseTheStatus)
    func withoutReasonsOnly404501503FallBack(_ c: OtpFallbackCase) {
        #expect(c.error.kind == .grpcStatus)
        #expect(verdict(c) == c.fallsBack)
    }

    @Test func theDecisionUsesTheErrorDetailsOfAStructuredError() {
        // Built by hand, not parsed: `details` decides for `.grpcStatus`; `rawBody` is not consulted.
        func error(_ status: Int, _ reasons: [String]) -> ZeroXKeyRequestError {
            ZeroXKeyRequestError(
                httpStatus: status, kind: .grpcStatus, code: 3, message: "m",
                details: reasons.map { .object(["@type": .string("type.googleapis.com/google.rpc.ErrorInfo"), "reason": .string($0)]) },
                retryAfter: nil, rawBody: "")
        }
        #expect(ZeroXKeyContext.isAttestedLoginUnavailable(error(400, ["ATTESTED_STAMP_NOT_ENABLED"])) == true)
        #expect(ZeroXKeyContext.isAttestedLoginUnavailable(error(404, ["ATTESTED_LOGIN_MFA_REQUIRED"])) == false)
        #expect(ZeroXKeyContext.isAttestedLoginUnavailable(error(503, ["ATTESTED_STAMP_INVALID"])) == false)
        #expect(ZeroXKeyContext.isAttestedLoginUnavailable(error(503, [])) == true)
        #expect(ZeroXKeyContext.isAttestedLoginUnavailable(error(401, [])) == false)
        #expect(ZeroXKeyContext.isAttestedLoginUnavailable(error(403, [])) == false)
    }

    @Test func theStatusRuleForPlainTextIncludes401ButTheStructuredRuleDoesNot() {
        let plain = ZeroXKeyRequestError.parse(httpStatus: 401, body: Data("Unauthorized".utf8))
        let structured = ZeroXKeyRequestError.parse(httpStatus: 401, body: Data(OtpFallbackTable.grpc().utf8))
        #expect(ZeroXKeyContext.isAttestedLoginUnavailable(plain) == true)
        #expect(ZeroXKeyContext.isAttestedLoginUnavailable(structured) == false)
    }

    @Test func theTableCoversEveryDecisionInBothDirections() {
        #expect(!OtpFallbackTable.fallbacks.isEmpty && !OtpFallbackTable.noFallbacks.isEmpty)
        for c in OtpFallbackTable.all { #expect(verdict(c) == c.fallsBack, "\(c.testDescription)") }
    }
}

/// `loginWithOtp` end to end: a fallback request reaches `otp_login_v2`, anything else surfaces the
/// original error and never touches it.
@Suite("OTP login fallback flow") @MainActor
struct OtpLoginFallbackFlowTests {
    static let org = "org-existing"

    struct Env {
        let ctx: ZeroXKeyContext
        let server: MockServer
        let key: String
        let vt: String
        let jwt: String
    }

    func env(authProxyConfigId: String? = "cfg-e2e") throws -> Env {
        let server = MockServer()
        let ctx = makeContext(server, authProxyConfigId: authProxyConfigId)
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-fb", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
        let jwt = APIFixtures.sessionJWT(publicKey: key, organizationId: Self.org, userId: "u", exp: 1_763_503_600)
        server.on("/v1/otp_login_v2", respond: .json(["session": jwt]))
        return Env(ctx: ctx, server: server, key: key, vt: vt, jwt: jwt)
    }

    @Test(arguments: OtpFallbackTable.fallbacks)
    func fallsBackToOtpLoginV2(_ c: OtpFallbackCase) async throws {
        let e = try env()
        e.server.on("/public/v1/submit/stamp_login", respond: c.response)
        let session = try await e.ctx.loginWithOtp(verificationToken: e.vt, organizationId: Self.org)
        #expect(session == e.jwt)
        #expect(e.server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(e.server.requests(to: "/v1/otp_login_v2").count == 1)
        #expect(e.ctx.session?.organizationId == Self.org)
    }

    @Test(arguments: OtpFallbackTable.noFallbacks)
    func throwsTheOriginalErrorWithoutRequestingOtpLoginV2(_ c: OtpFallbackCase) async throws {
        let e = try env()
        e.server.on("/public/v1/submit/stamp_login", respond: c.response)
        do {
            _ = try await e.ctx.loginWithOtp(verificationToken: e.vt, organizationId: Self.org)
            Issue.record("expected the stamp_login error to be thrown")
        } catch let error as ZeroXKeyRequestError {
            #expect(error.httpStatus == c.status)
            #expect(error.kind == c.error.kind)
            #expect(error.rawBody == c.body)
        } catch {
            Issue.record("unexpected error \(error)")
        }
        #expect(e.server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(e.server.requests(to: "/v1/otp_login_v2").isEmpty)
        #expect(e.ctx.authState != .authenticated)
        #expect(e.ctx.session == nil)
    }

    /// An MFA requirement on 403 must stay an error: the fallback would sign the user in without it.
    @Test func anMfaRequirementOn403DoesNotFallBack() async throws {
        let e = try env()
        e.server.on("/public/v1/submit/stamp_login", respond: .json(
            ["code": 7, "message": "mfa required", "details": [["reason": "ATTESTED_LOGIN_MFA_REQUIRED"]]], status: 403))
        await #expect(throws: ZeroXKeyRequestError.self) {
            try await e.ctx.loginWithOtp(verificationToken: e.vt, organizationId: Self.org)
        }
        #expect(e.server.requests(to: "/v1/otp_login_v2").isEmpty)
    }

    @Test func aPlainTextForbiddenDoesNotFallBackEither() async throws {
        let e = try env()
        e.server.on("/public/v1/submit/stamp_login", respond: .text("Forbidden\n", status: 403))
        await #expect(throws: ZeroXKeyRequestError.self) {
            try await e.ctx.loginWithOtp(verificationToken: e.vt, organizationId: Self.org)
        }
        #expect(e.server.requests(to: "/v1/otp_login_v2").isEmpty)
    }

    /// The original conditions stay: no Auth Proxy configuration, no fallback.
    @Test func withoutAnAuthProxyConfigurationTheErrorIsThrownAsIs() async throws {
        let e = try env(authProxyConfigId: nil)
        e.server.on("/public/v1/submit/stamp_login", respond: .text("Unauthorized\n", status: 401))
        do {
            _ = try await e.ctx.loginWithOtp(verificationToken: e.vt, organizationId: Self.org)
            Issue.record("expected the stamp_login error to be thrown")
        } catch let error as ZeroXKeyRequestError {
            #expect(error.httpStatus == 401)
        } catch {
            Issue.record("unexpected error \(error)")
        }
        #expect(e.server.requests(to: "/v1/otp_login_v2").isEmpty)
    }

    /// `completeOtp` logs in through the same path.
    @Test func completeOtpOnAnExistingAccountFallsBackOnPlainText404() async throws {
        let otpFx: OtpFixture = try Fixtures.load("otp-bundle")
        let e = try env()
        e.server.on("/v1/otp_verify_v2", respond: .json(["verificationToken": e.vt]))
        e.server.on("/v1/account", respond: .json(["organizationId": Self.org]))
        e.server.on("/public/v1/submit/stamp_login", respond: .text("404 page not found\n", status: 404))
        let result = try await e.ctx.completeOtp(
            otpId: "o", otpCode: "000000", otpEncryptionTargetBundle: otpFx.otpEncryptionTargetBundle,
            contact: "a@b.c", otpType: .email, publicKey: e.key)
        #expect(result.action == .login && result.sessionToken == e.jwt)
        #expect(e.server.requests(to: "/v1/otp_login_v2").count == 1)
    }
}
