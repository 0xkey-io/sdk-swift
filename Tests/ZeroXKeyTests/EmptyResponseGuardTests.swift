import Foundation
import Testing
import ZeroXKey
import ZeroXKeyHttp
import ZeroXKeyTestSupport

/// A response that carries the strict fields but with an empty value (not absent: that fails to
/// decode) is rejected by the high-level API instead of being used.
@Suite("Empty identifiers in responses") @MainActor
struct EmptyResponseGuardTests {
    func signedIn(_ server: MockServer) async throws -> ZeroXKeyContext {
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u-1", exp: 1_763_500_900))
        return ctx
    }

    @Test func createSubOrganizationRejectsEmptyId() async throws {
        let server = MockServer()
        let ctx = try await signedIn(server)
        server.on("/public/v1/submit/create_sub_organization", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8",
            result: ["createSubOrganizationResultV8": ["subOrganizationId": ""]]))))
        await #expect(throws: ZeroXKeyError.badResponse("create_sub_organization returned no subOrganizationId")) {
            _ = try await ctx.createSubOrganization(TCreateSubOrganizationBody(
                subOrganizationName: "s", rootUsers: [], rootQuorumThreshold: 1))
        }
    }

    @Test func createSubOrganizationReturnsTheId() async throws {
        let server = MockServer()
        let ctx = try await signedIn(server)
        server.on("/public/v1/submit/create_sub_organization", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8",
            result: ["createSubOrganizationResultV8": ["subOrganizationId": "sub-1"]]))))
        let res = try await ctx.createSubOrganization(TCreateSubOrganizationBody(
            subOrganizationName: "s", rootUsers: [], rootQuorumThreshold: 1))
        #expect(res.subOrganizationId == "sub-1")
    }

    @Test func createSubOrganizationWithoutIdFailsToDecode() async throws {
        let server = MockServer()
        let ctx = try await signedIn(server)
        server.on("/public/v1/submit/create_sub_organization", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8",
            result: ["createSubOrganizationResultV8": ["rootUserIds": ["u-1"]]]))))
        await #expect(throws: ZeroXKeyHttpError.self) {
            _ = try await ctx.createSubOrganization(TCreateSubOrganizationBody(
                subOrganizationName: "s", rootUsers: [], rootQuorumThreshold: 1))
        }
    }

    @Test func otpLoginViaAuthProxyRejectsEmptySession() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-9", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
        server.on("/public/v1/submit/stamp_login", respond: .text("Unauthorized\n", status: 401))
        server.on("/v1/otp_login_v2", respond: .json(["session": ""]))
        await #expect(throws: ZeroXKeyError.badResponse("otp_login_v2 returned no session")) {
            _ = try await ctx.loginWithOtp(verificationToken: vt, organizationId: "org-existing")
        }
        #expect(ctx.authState != .authenticated)
    }

    @Test func verifyOtpRejectsEmptyVerificationToken() async throws {
        let otpFx: OtpFixture = try Fixtures.load("otp-bundle")
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        server.on("/v1/otp_verify_v2", respond: .json(["verificationToken": ""]))
        await #expect(throws: ZeroXKeyError.badResponse("otp_verify_v2 returned no verificationToken")) {
            _ = try await ctx.verifyOtp(
                otpId: "o", otpCode: otpFx.otpCode, otpEncryptionTargetBundle: otpFx.otpEncryptionTargetBundle,
                contact: "a@b.c", otpType: .email, publicKey: key)
        }
        #expect(server.requests(to: "/v1/account").isEmpty)
    }
}
