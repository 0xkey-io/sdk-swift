import Foundation
import Testing
import ZeroXKey
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

@Suite("Session handling", .serialized) @MainActor
struct SessionTests {
    let now = Date(timeIntervalSince1970: 1_763_500_000)

    @Test func parsesSessionJwtClaims() throws {
        let jwt = APIFixtures.sessionJWT(publicKey: "02ab", organizationId: "org", userId: "u", exp: 1_763_500_900)
        let s = try ZeroXKeySession.parse(jwt: jwt)
        #expect(s == ZeroXKeySession(sessionType: "SESSION_TYPE_READ_WRITE", userId: "u", organizationId: "org",
                                     expiry: 1_763_500_900, publicKey: "02ab", token: jwt))
        #expect(s.expirationSeconds(at: now) == 900)
        #expect(!s.isExpired(at: now))
        #expect(s.isExpired(at: Date(timeIntervalSince1970: 1_763_500_900)))
    }

    @Test func rejectsMalformedJwts() {
        #expect(throws: ZeroXKeyError.self) { try ZeroXKeySession.parse(jwt: "nodots") }
        #expect(throws: ZeroXKeyError.self) { try ZeroXKeySession.parse(jwt: "a.!!!.c") }
        let missingOrg = APIFixtures.jwt(["exp": 1, "public_key": "02", "session_type": "s", "user_id": "u"])
        #expect(throws: ZeroXKeyError.invalidSessionToken("JWT payload missing required fields")) {
            try ZeroXKeySession.parse(jwt: missingOrg)
        }
    }

    @Test func phase1SessionJwtVectorSignatureVerifies() throws {
        struct V: Decodable { let jwt: String; let tamperedJwt: String; let notarizerPublicKey: String }
        let v: V = try Fixtures.load("session-jwt")
        // The phase-1 vector carries only organization_id/public_key/exp, so it is not a full
        // session; verify the signature through ZeroXKeySession with the vector's claims.
        let s = ZeroXKeySession(sessionType: "t", userId: "u", organizationId: "o", expiry: 0, publicKey: "02aa", token: v.jwt)
        #expect(try s.verifySignature(dangerouslyOverrideNotarizerPublicKey: v.notarizerPublicKey))
        #expect((try? s.verifySignature()) != true)
        let tampered = ZeroXKeySession(sessionType: "t", userId: "u", organizationId: "o", expiry: 0, publicKey: "02aa", token: v.tamperedJwt)
        #expect((try? tampered.verifySignature(dangerouslyOverrideNotarizerPublicKey: v.notarizerPublicKey)) != true)
        #expect(throws: ZeroXKeyError.self) { try ZeroXKeySession.parse(jwt: v.jwt) }
    }

    @Test func storeSessionRequiresLocalKeyAndUnexpiredToken() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys, now: now)
        let unknown = generateP256KeyPair().publicKey
        await #expect(throws: ZeroXKeyError.keyPairNotFound(publicKey: unknown)) {
            try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: unknown, organizationId: "o", userId: "u", exp: 1_763_509_999))
        }
        let key = try ctx.createKeyPair()
        await #expect(throws: ZeroXKeyError.sessionExpired) {
            try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: 1_763_499_999))
        }
        #expect(ctx.authState == .loading)
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: 1_763_509_999))
        #expect(ctx.authState == .authenticated)
        #expect(ctx.client?.organizationId == "o")
    }

    @Test func restoresStoredSessionOnConfigureAndClears() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager(), sessions = InMemorySessionStore()
        let first = makeContext(server, keys: keys, sessions: sessions, now: now)
        let key = try first.createKeyPair()
        // configure(_:) uses the wall clock, so the token must not be expired in real time.
        try await first.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: 4_102_444_800))

        ZeroXKeyContext.configure(ZeroXKeyConfig(
            apiUrl: server.apiURL.absoluteString, authProxyUrl: server.authProxyURL.absoluteString,
            keyManager: keys, sessionStore: sessions, urlSession: server.session).trustingFixtures())
        let shared = ZeroXKeyContext.shared
        #expect(shared.authState == .authenticated)
        #expect(shared.session?.publicKey == key)

        try shared.clearSession()
        #expect(shared.authState == .unauthenticated && shared.session == nil && shared.client == nil)
        #expect(try keys.listPublicKeys().isEmpty)
        #expect(try sessions.allSessionKeys().isEmpty)
    }

    @Test func expiredStoredSessionIsUnauthenticated() async throws {
        let keys = InMemoryKeyManager(), sessions = InMemorySessionStore()
        let key = try keys.createKeyPair()
        try sessions.store(token: APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: 100), sessionKey: "k")
        try sessions.setActiveSessionKey("k")
        ZeroXKeyContext.configure(ZeroXKeyConfig(keyManager: keys, sessionStore: sessions, urlSession: MockURLProtocol.session()).trustingFixtures())
        #expect(ZeroXKeyContext.shared.authState == .unauthenticated)
    }

    @Test func methodsNeedSession() async throws {
        let ctx = makeContext(MockServer())
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.refreshWallets() }
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.exportWallet(walletId: "w") }
    }

    @Test func sessionExpiringAfterLoginFailsBeforeNetwork() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager(), sessions = InMemorySessionStore()
        let key = try keys.createKeyPair()
        let jwt = APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: 1_763_500_010)
        try await makeContext(server, keys: keys, sessions: sessions, now: now).storeSession(jwt: jwt)
        // Same stored session, clock 60 s later: restore refuses it.
        ZeroXKeyContext.configure(ZeroXKeyConfig(
            apiUrl: server.apiURL.absoluteString, keyManager: keys, sessionStore: sessions, urlSession: server.session).trustingFixtures())
        #expect(ZeroXKeyContext.shared.authState == .unauthenticated)
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ZeroXKeyContext.shared.refreshWallets() }
        #expect(server.requests.isEmpty)
    }
}

@Suite("Key managers")
struct KeyManagerTests {
    @Test func inMemoryRoundTrip() throws {
        let m = InMemoryKeyManager()
        let a = try m.createKeyPair(), b = try m.createKeyPair()
        #expect(try m.listPublicKeys() == [a, b])
        let stamper = try m.stamper(forPublicKey: a)
        #expect(stamper.apiPublicKey == a)
        try m.deleteKeyPair(publicKey: a)
        #expect(try m.privateKey(forPublicKey: a) == nil)
        #expect(throws: ZeroXKeyError.keyPairNotFound(publicKey: a)) { try m.stamper(forPublicKey: a) }
    }

    @Test func importDerivesCompressedPublicKey() throws {
        struct F: Decodable { struct C: Decodable { let privateKey: String; let publicKey: String }; let cases: [C] }
        let fx = try #require((try Fixtures.load("api-key-stamp", as: F.self)).cases.first)
        let m = InMemoryKeyManager()
        #expect(try m.importPrivateKey(fx.privateKey) == fx.publicKey)
        #expect(throws: (any Error).self) { try m.importPrivateKey("zz") }
    }
}

@Suite("Message encoding and defaults")
struct EncodingDefaultsTests {
    @Test func addressFormatDefaultsMatchSdkJs() throws {
        #expect(try AddressFormatDefaults.hashFunction(for: .ADDRESS_FORMAT_ETHEREUM) == .HASH_FUNCTION_KECCAK256)
        #expect(try AddressFormatDefaults.hashFunction(for: .ADDRESS_FORMAT_SOLANA) == .HASH_FUNCTION_NOT_APPLICABLE)
        #expect(try AddressFormatDefaults.encoding(for: .ADDRESS_FORMAT_COSMOS) == .PAYLOAD_ENCODING_TEXT_UTF8)
        #expect(try AddressFormatDefaults.hashFunction(for: .ADDRESS_FORMAT_BITCOIN_MAINNET_P2TR) == .HASH_FUNCTION_SHA256)
        #expect(throws: ZeroXKeyError.unsupportedAddressFormat("ADDRESS_FORMAT_NOPE")) {
            try AddressFormatDefaults.encoding(for: v1AddressFormat(rawValue: "ADDRESS_FORMAT_NOPE"))
        }
        #expect(AddressFormatDefaults.defaultWalletAccounts.map(\.path) == ["m/44'/60'/0'/0/0", "m/44'/501'/0'/0'"])
    }

    @Test func oidcNonceIsHexSha256OfPublicKeyString() {
        // sha256("key-1") as in sdk-js oauth-flow-test.ts:204
        #expect(ZeroXKeyContext.oidcNonce(forPublicKey: "key-1") == "be2974546978e3739e6d6da85c4be9f334ce32df2b9fd4b6ff1b55c0d57e9d44")
        #expect(ZeroXKeyContext.oidcNonce(forPublicKey: "abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }
}
