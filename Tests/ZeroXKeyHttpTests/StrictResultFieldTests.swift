import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

/// The generator's DECODE_STRICT_FIELDS list, exercised through the real endpoints: the response of
/// each endpoint is decoded exactly as the client decodes it (`activity.result[resultKey]`, the
/// key taken from the endpoint manifest), so a strict entry written against a different version
/// of the result definition than the endpoint parses (the V7 / V8 mix-up this list once had) is
/// caught here, not only in the generator.
@Suite("Strict result fields, end to end")
struct StrictResultFieldTests {
    private struct EmptyActivityBody: ZeroXKeyActivityBody {
        var organizationId: String?
        var timestampMs: String?
    }
    private struct EmptyProxyBody: ZeroXKeyProxyBody {}

    /// One endpoint with the fields of its result and the ones that must not be missing.
    private struct Case {
        let name: String
        let path: String
        let resultKey: String?  // nil: Auth Proxy endpoint
        let activityType: String?
        let fields: [String: Any]
        let strict: [String]
        let call: (ZeroXKeyClient, String, String?, String?) async throws -> Void
    }

    private static func endpoint(_ method: String) -> ZeroXKeyEndpointInfo {
        ZeroXKeyAPIManifest.endpoints.first { $0.method == method }!
    }

    private static func activity<R: Decodable & Sendable>(
        _ method: String, _ type: R.Type, _ fields: [String: Any], strict: [String]
    ) -> Case {
        let e = endpoint(method)
        return Case(name: method, path: e.path, resultKey: e.resultKey, activityType: e.activityType, fields: fields, strict: strict) {
            client, path, resultKey, activityType in
            _ = try await client.activity(path, type: activityType!, body: EmptyActivityBody(), resultKey: resultKey!, as: R.self)
        }
    }

    private static func proxy<R: Decodable & Sendable>(_ path: String, _ type: R.Type, _ fields: [String: Any], strict: [String]) -> Case {
        Case(name: path, path: path, resultKey: nil, activityType: nil, fields: fields, strict: strict) { client, path, _, _ in
            _ = try await client.authProxy(path, body: EmptyProxyBody(), captchaToken: nil, as: R.self)
        }
    }

    private static var cases: [Case] { [
        activity("createSubOrganization", TCreateSubOrganizationResponse.self,
                 ["subOrganizationId": "sub-1"], strict: ["subOrganizationId"]),
        activity("createWallet", TCreateWalletResponse.self,
                 ["walletId": "w-1", "addresses": ["0x01"]], strict: ["walletId", "addresses"]),
        activity("createWalletAccounts", TCreateWalletAccountsResponse.self,
                 ["addresses": ["0x01"]], strict: ["addresses"]),
        activity("otpLogin", TOtpLoginResponse.self, ["session": "jwt"], strict: ["session"]),
        activity("oauthLogin", TOauthLoginResponse.self, ["session": "jwt"], strict: ["session"]),
        activity("createReadWriteSession", TCreateReadWriteSessionResponse.self,
                 ["credentialBundle": "bundle"], strict: ["credentialBundle"]),
        activity("oauth", TOauthResponse.self, ["credentialBundle": "bundle"], strict: ["credentialBundle"]),
        activity("initOtp", TInitOtpResponse.self, ["otpId": "otp-1"], strict: ["otpId"]),
        activity("initOtpAuth", TInitOtpAuthResponse.self, ["otpId": "otp-1"], strict: ["otpId"]),
        activity("verifyOtp", TVerifyOtpResponse.self, ["verificationToken": "vt"], strict: ["verificationToken"]),
        activity("exportWallet", TExportWalletResponse.self, ["exportBundle": "b"], strict: ["exportBundle"]),
        activity("exportWalletAccount", TExportWalletAccountResponse.self, ["exportBundle": "b"], strict: ["exportBundle"]),
        activity("exportPrivateKey", TExportPrivateKeyResponse.self, ["exportBundle": "b"], strict: ["exportBundle"]),
        activity("initImportWallet", TInitImportWalletResponse.self, ["importBundle": "b"], strict: ["importBundle"]),
        activity("initImportPrivateKey", TInitImportPrivateKeyResponse.self, ["importBundle": "b"], strict: ["importBundle"]),
        proxy("/v1/otp_init", ProxyTInitOtpResponse.self, ["otpId": "otp-1"], strict: ["otpId"]),
        proxy("/v1/otp_init_v2", ProxyTInitOtpV2Response.self,
              ["otpId": "otp-1", "otpEncryptionTargetBundle": "b"], strict: ["otpId", "otpEncryptionTargetBundle"]),
        proxy("/v1/otp_verify", ProxyTVerifyOtpResponse.self, ["verificationToken": "vt"], strict: ["verificationToken"]),
        proxy("/v1/otp_verify_v2", ProxyTVerifyOtpV2Response.self, ["verificationToken": "vt"], strict: ["verificationToken"]),
        proxy("/v1/otp_login", ProxyTOtpLoginResponse.self, ["session": "jwt"], strict: ["session"]),
        proxy("/v1/otp_login_v2", ProxyTOtpLoginV2Response.self, ["session": "jwt"], strict: ["session"]),
        proxy("/v1/oauth_login", ProxyTOAuthLoginResponse.self, ["session": "jwt"], strict: ["session"]),
        proxy("/v1/signup", ProxyTSignupResponse.self, ["organizationId": "org-1"], strict: ["organizationId"]),
        proxy("/v1/signup_v2", ProxyTSignupV2Response.self, ["organizationId": "org-1"], strict: ["organizationId"]),
    ] }

    private func respond(_ c: Case, fields: [String: Any], on server: MockServer) {
        if let resultKey = c.resultKey {
            server.on(c.path, respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: c.activityType!, result: [resultKey: fields]))))
        } else {
            server.on(c.path, respond: .json(fields))
        }
    }

    private func client(_ server: MockServer) -> ZeroXKeyClient {
        let key = generateP256KeyPair()
        // swiftlint:disable:next force_try
        return makeClient(server, stamper: try! ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey))
    }

    @Test func manifestMatchesTheCases() {
        // Every case points at the endpoint's own result key (the one the client reads).
        for c in Self.cases where c.resultKey != nil {
            #expect(Self.endpoint(c.name).resultKey == c.resultKey, "\(c.name)")
            #expect(ZeroXKeyAPIManifest.endpoints.contains { $0.path == c.path }, "\(c.name)")
        }
    }

    @Test func completeResultsDecode() async throws {
        for c in Self.cases {
            let server = MockServer()
            respond(c, fields: c.fields, on: server)
            do { try await c.call(client(server), c.path, c.resultKey, c.activityType) } catch {
                Issue.record("\(c.name): complete result failed: \(error)")
            }
        }
    }

    @Test func everyStrictFieldIsRequired() async throws {
        var checked = 0
        for c in Self.cases {
            for key in c.strict {
                #expect(c.fields[key] != nil, "\(c.name).\(key) is not in the base result")
                var without = c.fields
                without[key] = nil
                var asNull = c.fields
                asNull[key] = NSNull()
                for variant in [without, asNull] {
                    let server = MockServer()
                    respond(c, fields: variant, on: server)
                    do {
                        try await c.call(client(server), c.path, c.resultKey, c.activityType)
                        Issue.record("\(c.name) decoded without \(key)")
                    } catch ZeroXKeyHttpError.decodingFailed(_, let message) {
                        #expect(message.contains(key), "\(c.name): error does not name \(key): \(message)")
                    } catch {
                        Issue.record("\(c.name) without \(key): unexpected error \(error)")
                    }
                }
                checked += 1
            }
        }
        #expect(checked == Self.cases.reduce(0) { $0 + $1.strict.count })
        #expect(checked == 26)
    }

    /// Regression for the version mix-up: the swagger still defines `…ResultV7`, but
    /// `create_sub_organization` parses `createSubOrganizationResultV8`. A V8 result without the
    /// sub-organization ID must fail, even when a V7 result next to it carries one.
    @Test func createSubOrganizationParsesV8NotV7() async throws {
        #expect(Self.endpoint("createSubOrganization").resultKey == "createSubOrganizationResultV8")
        let server = MockServer()
        server.on("/public/v1/submit/create_sub_organization", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8",
            result: ["createSubOrganizationResultV8": ["rootUserIds": ["u-1"]],
                     "createSubOrganizationResultV7": ["subOrganizationId": "old"]]))))
        await #expect(throws: ZeroXKeyHttpError.self) {
            _ = try await client(server).createSubOrganization(TCreateSubOrganizationBody(
                subOrganizationName: "s", rootUsers: [], rootQuorumThreshold: 1))
        }
    }
}
