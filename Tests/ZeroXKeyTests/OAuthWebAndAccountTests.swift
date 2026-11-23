import CryptoKit
import Foundation
import Testing
@_spi(Unsafe) import ZeroXKey
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyTestSupport

/// Records the authorization URL and answers with a callback built from it.
final class StubAuthenticator: WebAuthenticator, @unchecked Sendable {
    private let lock = NSLock()
    private var _urls: [URL] = []
    private var _schemes: [String] = []
    let respond: @Sendable (URLComponents) throws -> URL

    init(respond: @escaping @Sendable (URLComponents) throws -> URL) { self.respond = respond }

    var urls: [URL] { lock.withLock { _urls } }
    var schemes: [String] { lock.withLock { _schemes } }

    func authenticate(url: URL, callbackURLScheme: String) async throws -> URL {
        lock.withLock { _urls.append(url); _schemes.append(callbackURLScheme) }
        return try respond(URLComponents(url: url, resolvingAgainstBaseURL: false)!)
    }

    static func param(_ c: URLComponents, _ name: String) -> String? { c.queryItems?.first { $0.name == name }?.value }

    /// Echoes `state` back with `code`.
    static func echo(redirect: String, code: String = "auth-code-1") -> StubAuthenticator {
        StubAuthenticator { c in URL(string: "\(redirect)?code=\(code)&state=\(param(c, "state")!)")! }
    }
}

let fixedRandom: @Sendable (Int) -> Data = { n in Data((0..<n).map { UInt8($0) }) }

@Suite("OAuth web flows") @MainActor
struct OAuthWebTests {
    let discord = OAuthClient(clientId: "discord-client", redirectUri: "exampleapp://oauth")
    let google = OAuthClient(clientId: "123.apps.googleusercontent.com",
                             redirectUri: "com.googleusercontent.apps.123:/oauth2redirect")

    func signupAndLoginRoutes(_ server: MockServer, existing: Bool) {
        server.on("/v1/account", respond: .json(existing ? ["organizationId": "org-sub"] : [:]))
        server.on("/v1/signup", respond: .json(["organizationId": "org-sub", "wallet": ["walletId": "w", "addresses": []],
                                                "userId": "u", "appProofs": []]))
        server.on("/v1/oauth_login") { req, _ in
            .json(["session": APIFixtures.sessionJWT(publicKey: req.json["publicKey"] as! String,
                                                     organizationId: "org-sub", userId: "u", exp: 1_763_500_900)])
        }
    }

    @Test func pkceVectorMatchesRFC7636() {
        // RFC 7636 Appendix B: verifier dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
        #expect(PKCEAttempt.challenge(for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        let a = PKCEAttempt(randomBytes: fixedRandom)
        #expect(a.verifier == "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")   // base64url(0x00…0x1f)
        #expect(a.state == "AAECAwQFBgcICQoLDA0ODw")                          // base64url(0x00…0x0f)
    }

    @Test func discordCodeIsExchangedThroughAuthProxy() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        ctx.oauthRandomBytes = fixedRandom
        server.on("/v1/oauth2_authenticate", respond: .json(["oidcToken": "discord.oidc.token"]))
        signupAndLoginRoutes(server, existing: false)
        let auth = StubAuthenticator.echo(redirect: "exampleapp://oauth")

        let result = try await ctx.handleOAuth(.discord, client: discord, authenticator: auth)
        #expect(result.action == .signup)

        let url = try #require(auth.urls.first)
        let c = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
        #expect(c.host == "discord.com" && c.path == "/oauth2/authorize")
        #expect(StubAuthenticator.param(c, "client_id") == "discord-client")
        #expect(StubAuthenticator.param(c, "redirect_uri") == "exampleapp://oauth")
        #expect(StubAuthenticator.param(c, "response_type") == "code")
        #expect(StubAuthenticator.param(c, "scope") == "identify email")
        #expect(StubAuthenticator.param(c, "code_challenge_method") == "S256")
        let verifier = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        #expect(StubAuthenticator.param(c, "code_challenge")
                == Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8)))))
        #expect(StubAuthenticator.param(c, "nonce") == nil)
        #expect(auth.schemes == ["exampleapp"])

        let publicKey = try #require(ctx.session?.publicKey)
        let exchange = try #require(server.requests(to: "/v1/oauth2_authenticate").first)
        #expect(exchange.header("X-Auth-Proxy-Config-ID") == "cfg-e2e")
        #expect(exchange.json as? [String: String] == [
            "provider": "OAUTH2_PROVIDER_DISCORD", "authCode": "auth-code-1", "redirectUri": "exampleapp://oauth",
            "codeVerifier": verifier, "clientId": "discord-client",
            "nonce": Hex.encode(Data(SHA256.hash(data: Data(publicKey.utf8)))),
        ])
        let signup = try #require(server.requests(to: "/v1/signup").first?.json)
        #expect((signup["oauthProviders"] as? [[String: String]]) == [["providerName": "discord", "oidcToken": "discord.oidc.token"]])
        #expect(server.requests(to: "/v1/oauth_login").first?.json["publicKey"] as? String == publicKey)
    }

    @Test func googleCodeIsExchangedAtGoogleWithNonce() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        ctx.oauthRandomBytes = fixedRandom
        ctx.googleTokenURL = server.apiURL.appendingPathComponent("google/token")
        server.on("/google/token", respond: .json(["id_token": "google.id.token", "access_token": "x"]))
        signupAndLoginRoutes(server, existing: true)
        let auth = StubAuthenticator.echo(redirect: "com.googleusercontent.apps.123:/oauth2redirect")

        let result = try await ctx.handleOAuth(.google, client: google, authenticator: auth)
        #expect(result.action == .login)
        let authURL = try #require(auth.urls.first)
        let c = try #require(URLComponents(url: authURL, resolvingAgainstBaseURL: false))
        #expect(c.host == "accounts.google.com")
        #expect(StubAuthenticator.param(c, "scope") == "openid email profile")
        let publicKey = try #require(ctx.session?.publicKey)
        #expect(StubAuthenticator.param(c, "nonce") == Hex.encode(Data(SHA256.hash(data: Data(publicKey.utf8)))))

        let token = try #require(server.requests(to: "/google/token").first)
        #expect(token.header("Content-Type") == "application/x-www-form-urlencoded")
        let form = Dictionary(uniqueKeysWithValues: (URLComponents(string: "?" + token.bodyString)?.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        #expect(form == ["client_id": "123.apps.googleusercontent.com",
                         "redirect_uri": "com.googleusercontent.apps.123:/oauth2redirect",
                         "code": "auth-code-1", "code_verifier": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                         "grant_type": "authorization_code"])
        #expect(server.requests(to: "/v1/signup").isEmpty)
        #expect(server.requests(to: "/v1/oauth_login").first?.json["oidcToken"] as? String == "google.id.token")
    }

    @Test func callbackValidationRejectsTamperedResponses() async throws {
        let cases: [(String, @Sendable (URLComponents) -> URL, ZeroXKeyOAuthError)] = [
            ("state", { _ in URL(string: "exampleapp://oauth?code=c&state=forged")! }, .invalidCallback("state mismatch")),
            ("base", { c in URL(string: "evil://oauth?code=c&state=\(StubAuthenticator.param(c, "state")!)")! },
             .invalidCallback("redirect base mismatch")),
            ("no code", { c in URL(string: "exampleapp://oauth?state=\(StubAuthenticator.param(c, "state")!)")! }, .invalidCallback("missing code")),
            ("two codes", { c in URL(string: "exampleapp://oauth?code=a&code=b&state=\(StubAuthenticator.param(c, "state")!)")! },
             .invalidCallback("missing code")),
            ("denied", { _ in URL(string: "exampleapp://oauth?error=access_denied")! }, .canceled),
            ("fragment", { c in URL(string: "exampleapp://oauth?code=c&state=\(StubAuthenticator.param(c, "state")!)#x")! },
             .invalidCallback("unexpected fragment")),
        ]
        for (name, respond, expected) in cases {
            let server = MockServer()
            let keys = InMemoryKeyManager()
            let ctx = makeContext(server, keys: keys)
            await #expect(throws: expected, "\(name)") {
                try await ctx.handleOAuth(.discord, client: discord, authenticator: StubAuthenticator(respond: respond))
            }
            #expect(server.requests.isEmpty, "\(name)")
            #expect(try keys.listPublicKeys().isEmpty, "\(name): session key must be deleted")
        }
    }

    @Test func configuredClientAndValidation() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        await #expect(throws: ZeroXKeyOAuthError.missingClient(.x)) {
            try await ctx.authorizeOAuth(.x, authenticator: StubAuthenticator.echo(redirect: "exampleapp://oauth"))
        }
        await #expect(throws: ZeroXKeyOAuthError.invalidRedirectUri("https://wallet.example.com/cb")) {
            try await ctx.authorizeOAuth(.x, client: OAuthClient(clientId: "x", redirectUri: "https://wallet.example.com/cb"),
                                         authenticator: StubAuthenticator.echo(redirect: "https://wallet.example.com/cb"))
        }
        // Without any client the Dashboard configuration is consulted (and has no route here); nothing else is sent.
        #expect(server.requests.allSatisfy { $0.path == "/v1/wallet_kit_config" })
    }

    @Test func authorizeOnlyReturnsTokenWithoutLogin() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        server.on("/v1/oauth2_authenticate", respond: .json(["oidcToken": "x.oidc.token"]))
        let success = try await ctx.authorizeOAuth(.x, client: OAuthClient(clientId: "x-client", redirectUri: "exampleapp://x"),
                                                   authenticator: StubAuthenticator.echo(redirect: "exampleapp://x"))
        #expect(success.oidcToken == "x.oidc.token" && success.providerName == "x")
        #expect(try keys.listPublicKeys() == [success.publicKey])
        #expect(server.requests(to: "/v1/oauth2_authenticate").first?.json["provider"] as? String == "OAUTH2_PROVIDER_X")
        #expect(ctx.session == nil)
    }
}

@Suite("Accounts, sessions, user") @MainActor
struct AccountTests {
    let t0: TimeInterval = 1_763_500_000

    func login(_ ctx: ZeroXKeyContext, user: String, org: String, key: String) async throws -> String {
        let pk = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: pk, organizationId: org, userId: user, exp: t0 + 900),
                                   sessionKey: key)
        return pk
    }

    @Test func multipleSessionsSwitchAndClear() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        let a = try await login(ctx, user: "ua", org: "org-a", key: "a")
        let b = try await login(ctx, user: "ub", org: "org-b", key: "b")
        #expect(try ctx.sessionKeys() == ["a", "b"])
        #expect(try ctx.activeSessionKey() == "b" && ctx.session?.userId == "ub")
        #expect(try ctx.storedSession(sessionKey: "a")?.publicKey == a)

        try ctx.setActiveSession(sessionKey: "a")
        #expect(ctx.session?.organizationId == "org-a" && ctx.authState == .authenticated)
        server.on("/public/v1/query/get_user", respond: .json(["user": APIFixtures.user(id: "ua")]))
        _ = try await ctx.refreshUser()
        let req = try #require(server.requests(to: "/public/v1/query/get_user").first)
        _ = try verifyStamp(req, publicKey: a)
        #expect(req.json["organizationId"] as? String == "org-a")

        #expect(throws: ZeroXKeyError.noActiveSession) { try ctx.setActiveSession(sessionKey: "missing") }
        try ctx.clearAllSessions()
        #expect(try ctx.sessionKeys().isEmpty && ctx.session == nil && ctx.authState == .unauthenticated)
        #expect(try keys.listPublicKeys().isEmpty)
        _ = b
    }

    @Test func reloginUnderSameKeyDeletesReplacedKey() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        let first = try await login(ctx, user: "u", org: "org-1", key: ZeroXKeySessionKey.default)
        let second = try await login(ctx, user: "u", org: "org-1", key: ZeroXKeySessionKey.default)
        #expect(first != second)
        #expect(try keys.listPublicKeys() == [second])
        #expect(ctx.session?.publicKey == second)
    }

    @Test func switchingUserClearsPublishedData() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        _ = try await login(ctx, user: "ua", org: "org-a", key: "a")
        server.on("/public/v1/query/list_wallets", respond: .json(["wallets": [APIFixtures.wallet(id: "wa", name: "A")]]))
        server.on("/public/v1/query/list_wallet_accounts", respond: .json(["accounts": []]))
        _ = try await ctx.refreshWallets()
        #expect(ctx.wallets.count == 1)
        _ = try await login(ctx, user: "ub", org: "org-b", key: "b")
        #expect(ctx.wallets.isEmpty && ctx.user == nil)
    }

    @Test func updateUserEmailPhoneName() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let pk = try await login(ctx, user: "u-1", org: "org-1", key: "s")
        for (path, type, key) in [("update_user_email", "ACTIVITY_TYPE_UPDATE_USER_EMAIL", "updateUserEmailResult"),
                                  ("update_user_phone_number", "ACTIVITY_TYPE_UPDATE_USER_PHONE_NUMBER", "updateUserPhoneNumberResult"),
                                  ("update_user_name", "ACTIVITY_TYPE_UPDATE_USER_NAME", "updateUserNameResult")] {
            server.on("/public/v1/submit/\(path)", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: type, result: [key: ["userId": "u-1"]]))))
        }
        server.on("/public/v1/query/get_user", respond: .json(["user": APIFixtures.user(id: "u-1")]))

        #expect(try await ctx.updateUserEmail("a@b.co", verificationToken: "vt") == "u-1")
        #expect(try await ctx.updateUserPhoneNumber("") == "u-1")
        #expect(try await ctx.updateUserName("Alice") == "u-1")

        func params(_ path: String) throws -> [String: String] {
            let r = try #require(server.requests(to: "/public/v1/submit/\(path)").first)
            _ = try verifyStamp(r, publicKey: pk)
            return try #require(r.json["parameters"] as? [String: String])
        }
        #expect(try params("update_user_email") == ["userId": "u-1", "userEmail": "a@b.co", "verificationToken": "vt"])
        #expect(try params("update_user_phone_number") == ["userId": "u-1", "userPhoneNumber": ""])
        #expect(try params("update_user_name") == ["userId": "u-1", "userName": "Alice"])
        #expect(server.requests(to: "/public/v1/query/get_user").count == 3)
    }

    @Test func unsafeSignWithSessionKeySignsArbitraryBytes() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        #expect(throws: ZeroXKeyError.noActiveSession) { try ctx.unsafeSignWithSessionKey(Data([1])) }
        let pk = try await login(ctx, user: "u", org: "o", key: "s")
        let message = Data([0xff, 0xfe, 0x00, 0x80])   // not valid UTF-8
        let der = try ctx.unsafeSignWithSessionKey(message)
        #expect(try P256Signer.verifyDER(signature: der, message: message, publicKey: Hex.decode(pk)))
        #expect(try !P256Signer.verifyDER(signature: der, message: Data([0xff, 0xfe, 0x00, 0x81]), publicKey: Hex.decode(pk)))
    }
}
