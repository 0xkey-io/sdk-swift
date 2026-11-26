import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

@Suite("Auth Proxy requests")
struct AuthProxyTests {
    @Test func initOtpV2HeadersAndBody() async throws {
        let server = MockServer()
        server.on("/v1/otp_init_v2", respond: .json(["otpId": "otp-1", "otpEncryptionTargetBundle": "{}"]))
        let key = generateP256KeyPair()
        let client = makeClient(server, stamper: try ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey))
        let res = try await client.proxyInitOtpV2(ProxyTInitOtpV2Body(otpType: "OTP_TYPE_EMAIL", contact: "a@example.org"))
        #expect(res.otpId == "otp-1")
        let req = try #require(server.requests.first)
        #expect(req.url.absoluteString == "https://\(server.authProxyHost)/v1/otp_init_v2")
        #expect(req.method == "POST")
        #expect(req.header("X-Auth-Proxy-Config-ID") == "cfg-123")
        #expect(req.header("Content-Type") == "application/json")
        // Auth Proxy calls are never stamped (sdk-client-base.ts authProxyRequest).
        #expect(req.header("X-Stamp") == nil && req.header("X-Captcha-Token") == nil)
        #expect(req.json as? [String: String] == ["otpType": "OTP_TYPE_EMAIL", "contact": "a@example.org"])
    }

    @Test func captchaTokenOnProtectedRoute() async throws {
        let server = MockServer()
        server.on("/v1/signup_v2", respond: .json(["organizationId": "o", "userId": "u"]))
        _ = try await makeClient(server, stamper: nil).proxySignupV2(
            ProxyTSignupV2Body(apiKeys: [], authenticators: [], oauthProviders: []), captchaToken: "cap-tok")
        let req = try #require(server.requests.first)
        #expect(req.header("X-Captcha-Token") == "cap-tok")
        #expect(req.url.query == "captcha_config_id=cfg-123")
        #expect(req.url.path == "/v1/signup_v2")
    }

    @Test func captchaRejectedOnOtherRoutesBeforeSending() async throws {
        let server = MockServer()
        let client = makeClient(server, stamper: nil)
        await #expect(throws: ZeroXKeyHttpError.captchaNotSupported(path: "/v1/oauth_login")) {
            try await client.authProxy("/v1/oauth_login", body: ProxyTOAuthLoginBody(oidcToken: "t", publicKey: "p"),
                                       captchaToken: "x", as: ProxyTOAuthLoginResponse.self)
        }
        #expect(server.requests.isEmpty)
        #expect(ZeroXKeyClient.captchaProtectedAuthProxyPaths == ["/v1/otp_init", "/v1/otp_init_v2", "/v1/signup", "/v1/signup_v2"])
    }

    @Test func missingConfigIdFailsWithoutRequest() async throws {
        let server = MockServer()
        await #expect(throws: ZeroXKeyHttpError.missingAuthProxyConfiguration) {
            try await makeClient(server, stamper: nil, configId: nil).proxyGetWalletKitConfig(ProxyTGetWalletKitConfigBody())
        }
        #expect(server.requests.isEmpty)
    }

    @Test func authProxyPlainTextError() async throws {
        let server = MockServer()
        server.on("/v1/otp_verify_v2", respond: .text("Invalid OTP code", status: 400))
        await #expect {
            try await makeClient(server, stamper: nil).proxyVerifyOtpV2(ProxyTVerifyOtpV2Body(otpId: "o", encryptedOtpBundle: "{}"))
        } throws: { e in
            (e as? ZeroXKeyRequestError).map { $0.kind == .plainText && $0.code == 3 && $0.message == "Invalid OTP code" } ?? false
        }
    }
}

@Suite("Generated endpoint manifest")
struct ManifestTests {
    func entry(_ method: String) -> ZeroXKeyEndpointInfo? {
        ZeroXKeyAPIManifest.endpoints.first { $0.method == method }
    }

    @Test func provenance() {
        #expect(ZeroXKeyAPIManifest.publicSwaggerSHA256 == "51bbd0129ec359ec8b931922164364ae67c12e90aa16c8321bf39c0351234a3d") // gitleaks:allow
        #expect(ZeroXKeyAPIManifest.authProxySwaggerSHA256 == "6b035dbbae61dfbe4533a1e24ccbe2e83ef56ccf81023a38b2ae47535c9c71fe")
        #expect(ZeroXKeyAPIManifest.sdkJsCommit == "4519de9650d783e8cf032b783d7f6d9eed235649") // gitleaks:allow
        #expect(ZeroXKeyAPIManifest.endpoints.count == 153)
        #expect(ZeroXKeyAPIManifest.endpoints.filter { $0.kind == "proxy" }.count == 13)
    }

    /// Activity types are 0xkey's swagger versions (capped like sdk-js), not newer upstream ones.
    @Test func requiredEndpointsWith0xkeyVersions() throws {
        let expected: [(String, String, String?)] = [
            ("getWhoami", "/public/v1/query/whoami", nil),
            ("getOrganizationConfigs", "/public/v1/query/get_organization_configs", nil),
            ("getUser", "/public/v1/query/get_user", nil),
            ("getWallets", "/public/v1/query/list_wallets", nil),
            ("getWalletAccounts", "/public/v1/query/list_wallet_accounts", nil),
            ("getActivity", "/public/v1/query/get_activity", nil),
            ("getSubOrgIds", "/public/v1/query/list_suborgs", nil),
            ("createSubOrganization", "/public/v1/submit/create_sub_organization", "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8"),
            ("createUsers", "/public/v1/submit/create_users", "ACTIVITY_TYPE_CREATE_USERS_V3"),
            ("createWallet", "/public/v1/submit/create_wallet", "ACTIVITY_TYPE_CREATE_WALLET"),
            ("createWalletAccounts", "/public/v1/submit/create_wallet_accounts", "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS"),
            ("signRawPayload", "/public/v1/submit/sign_raw_payload", "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"),
            ("signTransaction", "/public/v1/submit/sign_transaction", "ACTIVITY_TYPE_SIGN_TRANSACTION_V2"),
            ("exportWallet", "/public/v1/submit/export_wallet", "ACTIVITY_TYPE_EXPORT_WALLET"),
            ("exportWalletAccount", "/public/v1/submit/export_wallet_account", "ACTIVITY_TYPE_EXPORT_WALLET_ACCOUNT"),
            ("exportPrivateKey", "/public/v1/submit/export_private_key", "ACTIVITY_TYPE_EXPORT_PRIVATE_KEY"),
            ("initImportWallet", "/public/v1/submit/init_import_wallet", "ACTIVITY_TYPE_INIT_IMPORT_WALLET"),
            ("importWallet", "/public/v1/submit/import_wallet", "ACTIVITY_TYPE_IMPORT_WALLET"),
            ("initImportPrivateKey", "/public/v1/submit/init_import_private_key", "ACTIVITY_TYPE_INIT_IMPORT_PRIVATE_KEY"),
            ("importPrivateKey", "/public/v1/submit/import_private_key", "ACTIVITY_TYPE_IMPORT_PRIVATE_KEY"),
            ("createApiKeys", "/public/v1/submit/create_api_keys", "ACTIVITY_TYPE_CREATE_API_KEYS_V2"),
            ("deleteApiKeys", "/public/v1/submit/delete_api_keys", "ACTIVITY_TYPE_DELETE_API_KEYS"),
            ("createAuthenticators", "/public/v1/submit/create_authenticators", "ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2"),
            ("createReadWriteSession", "/public/v1/submit/create_read_write_session", "ACTIVITY_TYPE_CREATE_READ_WRITE_SESSION_V2"),
            ("stampLogin", "/public/v1/submit/stamp_login", "ACTIVITY_TYPE_STAMP_LOGIN"),
            ("initOtp", "/public/v1/submit/init_otp", "ACTIVITY_TYPE_INIT_OTP_V2"),
            ("verifyOtp", "/public/v1/submit/verify_otp", "ACTIVITY_TYPE_VERIFY_OTP"),
            ("otpLogin", "/public/v1/submit/otp_login", "ACTIVITY_TYPE_OTP_LOGIN"),
            ("oauthLogin", "/public/v1/submit/oauth_login", "ACTIVITY_TYPE_OAUTH_LOGIN"),
        ]
        for (method, path, type) in expected {
            let e = try #require(entry(method), "\(method) missing")
            #expect(e.path == path, "\(method)")
            #expect(e.activityType == type, "\(method)")
        }
        // get_organization is not in 0xkey's swagger (whoami + get_organization_configs cover it).
        #expect(ZeroXKeyAPIManifest.endpoints.contains { $0.path == "/public/v1/query/get_organization" } == false)
    }

    @Test func authProxyRoutes() throws {
        let proxy = ZeroXKeyAPIManifest.endpoints.filter { $0.kind == "proxy" }
        #expect(Set(proxy.map(\.path)) == [
            "/v1/account", "/v1/oauth2_authenticate", "/v1/oauth_login", "/v1/otp_init", "/v1/otp_init_v2",
            "/v1/otp_login", "/v1/otp_login_v2", "/v1/otp_verify", "/v1/otp_verify_v2", "/v1/signup", "/v1/signup_v2",
            "/v1/wallet_kit_client_params", "/v1/wallet_kit_config",
        ])
        #expect(Set(proxy.filter(\.captchaProtected).map(\.path)) == ZeroXKeyClient.captchaProtectedAuthProxyPaths)
    }
}
