import Foundation
import Testing
import ZeroXKey
import ZeroXKeyCrypto
import ZeroXKeyTestSupport

@Suite("OTP target bundle trust (context)") @MainActor
struct OtpTargetBundleTrustTests {
    let otpFx: OtpFixture = try! Fixtures.load("otp-bundle")

    @Test func productionTrustAnchorsAreTheDefault() {
        #expect(ZeroXKeyConfig().trustAnchors == .production)
        #expect(ZeroXKeyConfig.TrustAnchors.production.signerPublicKey == ZeroXKeyTrustAnchors.productionSignerSignPublicKey)
        #expect(ZeroXKeyConfig.TrustAnchors(dangerouslyOverrideSignerPublicKey: "04ab").signerPublicKey == "04ab")
    }

    /// A target bundle that the production signer did not sign is refused before `otp_verify_v2`.
    @Test func verifyOtpRefusesABundleNotSignedByTheConfiguredSigner() async throws {
        let server = MockServer()
        let ctx = makeContext(server, trustAnchors: .production)
        let key = try ctx.createKeyPair()
        await #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(
            expected: ZeroXKeyTrustAnchors.productionSignerSignPublicKey, found: otpFx.signerPublicKey)) {
            _ = try await ctx.verifyOtp(
                otpId: "o", otpCode: otpFx.otpCode, otpEncryptionTargetBundle: otpFx.otpEncryptionTargetBundle,
                contact: "a@b.c", otpType: .email, publicKey: key)
        }
        await #expect(throws: ZeroXKeyCryptoError.self) {
            _ = try await ctx.completeOtp(
                otpId: "o", otpCode: otpFx.otpCode, otpEncryptionTargetBundle: otpFx.otpEncryptionTargetBundle,
                contact: "a@b.c", otpType: .email, publicKey: key)
        }
        #expect(server.requests.isEmpty)
    }

    @Test func verifyOtpRefusesAnUnsignedBundle() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        let unsigned = #"{"data":"7b22746172676574507562c6963223a223034227d"}"#
        await #expect(throws: ZeroXKeyCryptoError.self) {
            _ = try await ctx.verifyOtp(otpId: "o", otpCode: "1", otpEncryptionTargetBundle: unsigned,
                                        contact: "a@b.c", otpType: .email, publicKey: key)
        }
        #expect(server.requests.isEmpty)
    }

    @Test func verifyOtpUsesTheConfiguredSigner() async throws {
        let server = MockServer()
        let ctx = makeContext(server, trustAnchors: .init(dangerouslyOverrideSignerPublicKey: otpFx.signerPublicKey))
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-t", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
        server.on("/v1/otp_verify_v2", respond: .json(["verificationToken": vt]))
        server.on("/v1/account", respond: .json(["organizationId": "org-existing"]))
        let result = try await ctx.verifyOtp(
            otpId: "o", otpCode: otpFx.otpCode, otpEncryptionTargetBundle: otpFx.otpEncryptionTargetBundle,
            contact: "a@b.c", otpType: .email, publicKey: key)
        #expect(result.subOrganizationId == "org-existing")
        #expect(server.requests(to: "/v1/otp_verify_v2").count == 1)
    }
}
