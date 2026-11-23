import Foundation
import Testing
import ZeroXKey
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

struct ClientSignatureFixture: Decodable {
    struct Input: Decodable {
        let email: String?
        let phoneNumber: String?
        let apiKeys: [v1ApiKeyParamsV2]
        let authenticators: [v1AuthenticatorParamsV2]
        let oauthProviders: [v1OauthProviderParams]
    }
    struct SignupCase: Decodable { let label: String; let input: Input; let message: String; let publicKey: String }
    struct Attested: Decodable {
        struct Decoded: Decodable { let publicKeyAttestation: String; let scheme: String; let publicKey: String; let signature: String }
        let payload: String; let stampHeaderName: String; let stampHeaderValue: String; let decoded: Decoded
    }
    struct Nonce: Decodable { let publicKey: String; let expected: String }
    struct LoginCase: Decodable {
        struct Input: Decodable { let sessionPublicKey: String? }
        let label: String; let input: Input; let message: String; let publicKey: String
    }
    let key: KeyPairFixture
    let verificationToken: String
    let signupCases: [SignupCase]
    let loginCases: [LoginCase]
    let attested: Attested
    let nonce: Nonce
}

@Suite("sdk-js vectors for auth helpers")
struct AuthVectorTests {
    let fx: ClientSignatureFixture = try! Fixtures.load("client-signature")

    @Test func signupClientSignatureMessageMatchesSdkJs() throws {
        #expect(fx.signupCases.count == 2)
        for c in fx.signupCases {
            let msg = SignUpBody.clientSignatureMessage(
                tokenId: "vt-fixture-1", email: c.input.email, phoneNumber: c.input.phoneNumber,
                apiKeys: c.input.apiKeys, authenticators: c.input.authenticators, oauthProviders: c.input.oauthProviders)
            #expect(msg == c.message, "\(c.label)")
            #expect(c.publicKey == fx.key.publicKey)
        }
    }

    @Test func loginClientSignatureMessageMatchesSdkJs() throws {
        #expect(fx.loginCases.count == 2)
        for c in fx.loginCases {
            let msg = SignUpBody.loginClientSignatureMessage(
                tokenId: "vt-fixture-1", sessionPublicKey: c.input.sessionPublicKey ?? fx.key.publicKey)
            #expect(msg == c.message, "\(c.label)")
            #expect(c.publicKey == fx.key.publicKey)
        }
    }

    @Test func attestedStampMatchesSdkJsWithSameSignature() async throws {
        // Inject sdk-js's deterministic DER signature so the whole header can be compared byte-for-byte.
        let der = try Hex.decode(fx.attested.decoded.signature)
        let apiKey = ApiKeyStamper(apiPublicKey: fx.key.publicKey, privateKey: try Hex.decode(fx.key.privateKey)) { _ in der }
        let stamp = try await AttestedStamper(attestedIdentity: fx.verificationToken, apiKey: apiKey).stamp(payload: fx.attested.payload)
        #expect(stamp.stampHeaderName == fx.attested.stampHeaderName)
        #expect(stamp.stampHeaderValue == fx.attested.stampHeaderValue)
    }

    @Test func attestedStampWithRealSignerVerifies() async throws {
        let apiKey = try ApiKeyStamper(apiPublicKey: fx.key.publicKey, apiPrivateKey: fx.key.privateKey)
        let stamp = try await AttestedStamper(attestedIdentity: fx.verificationToken, apiKey: apiKey).stamp(payload: fx.attested.payload)
        let json = try JSONSerialization.jsonObject(with: Base64URL.decode(stamp.stampHeaderValue)) as! [String: String]
        #expect(Array(json.keys).sorted() == ["publicKey", "publicKeyAttestation", "scheme", "signature"])
        #expect(json["scheme"] == "STAMP_ATTESTED_SCHEME_P256_VERIFICATION_TOKEN")
        #expect(try verifyStampSignature(publicKey: fx.key.publicKey, signature: json["signature"]!, signedData: fx.attested.payload))
        #expect(try !verifyStampSignature(publicKey: fx.key.publicKey, signature: json["signature"]!, signedData: fx.attested.payload + " "))
    }

    @Test @MainActor func oidcNonceMatchesSdkJs() {
        #expect(ZeroXKeyContext.oidcNonce(forPublicKey: fx.nonce.publicKey) == fx.nonce.expected)
    }
}

struct StaticTokenProvider: OIDCTokenProvider {
    let token: String
    let seenNonce = NonceBox()
    func idToken(nonce: String) async throws -> String {
        seenNonce.set(nonce)
        return token
    }
}

final class NonceBox: @unchecked Sendable {
    private let lock = NSLock()
    private var v: String?
    func set(_ s: String) { lock.withLock { v = s } }
    var value: String? { lock.withLock { v } }
}

final class FakeRegistrar: PasskeyRegistrationProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var _seen: [PasskeyRegistrationRequest] = []
    var seen: [PasskeyRegistrationRequest] { lock.withLock { _seen } }
    func register(_ request: PasskeyRegistrationRequest) async throws -> PasskeyRegistration {
        lock.withLock { _seen.append(request) }
        return PasskeyRegistration(credentialId: Data([0xC0, 0xFF, 0xEE]), clientDataJSON: Data("{}".utf8),
                                   attestationObject: Data([0xA1, 0x01]), transports: ["AUTHENTICATOR_TRANSPORT_INTERNAL"])
    }
}

final class FakeAsserter: PasskeyAssertionProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var _seen: [PasskeyAssertionRequest] = []
    var seen: [PasskeyAssertionRequest] { lock.withLock { _seen } }
    func assert(_ request: PasskeyAssertionRequest) async throws -> PasskeyAssertion {
        lock.withLock { _seen.append(request) }
        return PasskeyAssertion(credentialId: Data([9]), authenticatorData: Data([8]), clientDataJSON: Data("{}".utf8), signature: Data([7]))
    }
}

@Suite("OAuth and passkey flows") @MainActor
struct OAuthPasskeyFlowTests {
    nonisolated static func loginActivity(_ jwt: String) -> MockResponse {
        .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN", result: ["stampLoginResult": ["session": jwt]])))
    }

    @Test func appleOAuthNewUserSignsUpThenLogsIn() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        server.on("/v1/account", respond: .json(["organizationId": ""]))
        server.on("/v1/signup", respond: .json(["organizationId": "org-apple", "userId": "u"]))
        server.on("/v1/oauth_login") { req, _ in
            let pk = req.json["publicKey"] as! String
            return .json(["session": APIFixtures.sessionJWT(publicKey: pk, organizationId: "org-apple", userId: "u", exp: 1_763_503_600)])
        }
        let provider = StaticTokenProvider(token: "apple.id.token")
        let res = try await ctx.handleAppleOAuth(tokenProvider: provider)
        #expect(res.action == .signup)

        let pk = try #require(ctx.session?.publicKey)
        #expect(try keys.listPublicKeys() == [pk])
        #expect(provider.seenNonce.value == ZeroXKeyContext.oidcNonce(forPublicKey: pk))
        #expect((server.requests(to: "/v1/account").first?.json as? [String: String]) == ["filterType": "OIDC_TOKEN", "filterValue": "apple.id.token"])
        let signup = try #require(server.requests(to: "/v1/signup").first).json
        #expect((signup["oauthProviders"] as? [[String: String]]) == [["providerName": "apple", "oidcToken": "apple.id.token"]])
        #expect((signup["apiKeys"] as? [Any])?.isEmpty == true)
        let login = try #require(server.requests(to: "/v1/oauth_login").first)
        #expect(login.header("X-Auth-Proxy-Config-ID") == "cfg-e2e")
        #expect(login.json["oidcToken"] as? String == "apple.id.token")
        #expect(login.json["invalidateExisting"] as? Bool == false)
        #expect(ctx.authState == .authenticated)
    }

    @Test func completeOAuthExistingUserSkipsSignup() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let pk = try ctx.createKeyPair()
        server.on("/v1/account", respond: .json(["organizationId": "org-g"]))
        server.on("/v1/oauth_login", respond: .json(["session": APIFixtures.sessionJWT(publicKey: pk, organizationId: "org-g", userId: "u", exp: 1_763_503_600)]))
        let res = try await ctx.completeOAuth(oidcToken: "google.token", publicKey: pk)
        #expect(res.action == .login)
        #expect(server.requests(to: "/v1/signup").isEmpty)
    }

    @Test func appleOAuthFailureDeletesGeneratedKey() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        server.on("/v1/account", respond: .text("Unauthorized: invalid oidc token", status: 401))
        await #expect(throws: ZeroXKeyRequestError.self) { try await ctx.handleAppleOAuth(tokenProvider: StaticTokenProvider(token: "bad")) }
        #expect(try keys.listPublicKeys().isEmpty)
        #expect(ctx.authState != .authenticated)
    }

    @Test func missingAuthProxyConfigIsReportedWithoutNetwork() async throws {
        let server = MockServer()
        let ctx = ZeroXKeyContext(config: ZeroXKeyConfig(
            apiUrl: server.apiURL.absoluteString, authProxyUrl: server.authProxyURL.absoluteString,
            keyManager: InMemoryKeyManager(), sessionStore: InMemorySessionStore(), urlSession: server.session).trustingFixtures())
        await #expect(throws: ZeroXKeyError.missingAuthProxyConfiguration) { try await ctx.initOtp(contact: "a@b.c", otpType: .email) }
        await #expect(throws: ZeroXKeyError.missingAuthProxyConfiguration) { try await ctx.completeOAuth(oidcToken: "t", publicKey: "p") }
        #expect(server.requests.isEmpty)
    }

    @Test func passkeyLoginUsesWebAuthnStampAndCallerRpId() async throws {
        let server = MockServer()
        let asserter = FakeAsserter()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys, rpId: "login.example.org", assertion: asserter)
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return Self.loginActivity(APIFixtures.sessionJWT(publicKey: pk, organizationId: "org-parent", userId: "u", exp: 1_763_503_600))
        }
        try await ctx.loginWithPasskey()
        let req = try #require(server.requests(to: "/public/v1/submit/stamp_login").first)
        #expect(req.header("X-Stamp-Webauthn") != nil && req.header("X-Stamp") == nil)
        #expect(asserter.seen.first?.rpId == "login.example.org")
        #expect(asserter.seen.first?.challenge == WebAuthnStamp.challenge(for: req.bodyString))
        #expect(req.json["organizationId"] as? String == "org-parent")
        #expect(ctx.authState == .authenticated)
    }

    @Test func passkeyLoginFailureCleansUpKey() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys, rpId: "wallet.example.com", assertion: FakeAsserter())
        server.on("/public/v1/submit/stamp_login", respond: .text("Unauthorized: RP ID hash mismatch\n", status: 401))
        await #expect {
            try await ctx.loginWithPasskey()
        } throws: { ($0 as? ZeroXKeyRequestError)?.reason == .webAuthnRpIdNotAllowed }
        #expect(try keys.listPublicKeys().isEmpty)
    }

    @Test func passkeyRequiresProviderAndRpId() async throws {
        let server = MockServer()
        await #expect(throws: ZeroXKeyError.missingPasskeyProvider) { try await makeContext(server, rpId: "x").loginWithPasskey() }
        await #expect(throws: ZeroXKeyError.missingRpId) { try await makeContext(server, assertion: FakeAsserter()).loginWithPasskey() }
        #expect(server.requests.isEmpty)
    }

    @Test func passkeySignupMirrorsSdkJs() async throws {
        let server = MockServer()
        let registrar = FakeRegistrar()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys, rpId: "wallet.example.com", registration: registrar)
        server.on("/v1/signup", respond: .json(["organizationId": "org-new", "userId": "u"]))
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return Self.loginActivity(APIFixtures.sessionJWT(publicKey: pk, organizationId: "org-new", userId: "u", exp: 1_763_503_600))
        }
        try await ctx.signUpWithPasskey(passkeyDisplayName: "My Phone")

        let reg = try #require(registrar.seen.first)
        #expect(reg.rpId == "wallet.example.com" && reg.challenge.count == 32 && reg.userName == "My Phone")
        let signup = try #require(server.requests(to: "/v1/signup").first).json
        let auths = try #require(signup["authenticators"] as? [[String: Any]])
        #expect(auths.count == 1)
        #expect(auths[0]["authenticatorName"] as? String == "My Phone")
        #expect(auths[0]["challenge"] as? String == Base64URL.encode(reg.challenge))
        let att = try #require(auths[0]["attestation"] as? [String: Any])
        #expect(att["credentialId"] as? String == "wP_u")
        #expect(att["attestationObject"] as? String == "oQE")
        let apiKeys = try #require(signup["apiKeys"] as? [[String: String]])
        let bootstrap = try #require(apiKeys.first?["publicKey"])
        #expect(apiKeys == [["apiKeyName": "passkey-auth-\(bootstrap)", "publicKey": bootstrap,
                             "curveType": "API_KEY_CURVE_P256", "expirationSeconds": "60"]])

        // stamp_login is stamped by the bootstrap key and requests a different session key.
        let login = try #require(server.requests(to: "/public/v1/submit/stamp_login").first)
        let stamp = try verifyStamp(login, publicKey: bootstrap)
        #expect(stamp["scheme"] == "SIGNATURE_SCHEME_TK_API_P256")
        let sessionKey = try #require(ctx.session?.publicKey)
        #expect(sessionKey != bootstrap)
        #expect(login.json["organizationId"] as? String == "org-new")
        #expect(try keys.listPublicKeys() == [sessionKey])
    }
}
