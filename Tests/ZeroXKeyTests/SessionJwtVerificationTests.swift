import CryptoKit
import Foundation
import Testing
import ZeroXKey
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyHttp
import ZeroXKeyTestSupport

private let t0: TimeInterval = 1_763_500_000
private let rogue = P256.Signing.PrivateKey()

private func claims(publicKey: String = "02aa", exp: TimeInterval = t0 + 3600) -> [String: Any] {
    ["exp": exp, "public_key": publicKey, "session_type": "SESSION_TYPE_READ_WRITE", "user_id": "u", "organization_id": "o"]
}

/// Replaces the payload segment of `jwt`, keeping header and signature.
private func withPayload(_ jwt: String, _ claims: [String: Any]) -> String {
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
    let payload = APIFixtures.base64URL(try! JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys]))
    return "\(parts[0]).\(payload).\(parts[2])"
}

@Suite("Session JWT verification (ZeroXKeySession.verified)")
struct SessionJwtVerifiedTests {
    let notarizer = APIFixtures.notarizerPublicKey
    let now = Date(timeIntervalSince1970: t0)

    @Test func acceptsASignedUnexpiredJwt() throws {
        let jwt = APIFixtures.jwt(claims())
        let s = try ZeroXKeySession.verified(jwt: jwt, dangerouslyOverrideNotarizerPublicKey: notarizer, at: now)
        #expect(s.token == jwt && s.organizationId == "o" && s.expiry == t0 + 3600)
    }

    @Test func productionNotarizerIsTheDefault() {
        #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) {
            try ZeroXKeySession.verified(jwt: APIFixtures.jwt(claims()), at: now)
        }
        #expect(ZeroXKeyConfig.TrustAnchors.production.notarizerPublicKey == ZeroXKeyTrustAnchors.productionNotarizerSignPublicKey)
    }

    @Test func rejectsASignatureByAnotherKey() {
        #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) {
            try ZeroXKeySession.verified(jwt: APIFixtures.jwt(claims(), signer: rogue),
                                         dangerouslyOverrideNotarizerPublicKey: notarizer, at: now)
        }
    }

    @Test func rejectsATamperedPayload() {
        let jwt = APIFixtures.jwt(claims(publicKey: "02aa"))
        #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) {
            try ZeroXKeySession.verified(jwt: withPayload(jwt, claims(publicKey: "02bb")),
                                         dangerouslyOverrideNotarizerPublicKey: notarizer, at: now)
        }
        #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) {
            try ZeroXKeySession.verified(jwt: withPayload(jwt, claims(exp: t0 + 999_999)),
                                         dangerouslyOverrideNotarizerPublicKey: notarizer, at: now)
        }
    }

    @Test func rejectsAWrongExpectedKey() {
        let jwt = APIFixtures.jwt(claims())
        for key in [ZeroXKeyTrustAnchors.productionNotarizerSignPublicKey,
                    ZeroXKeyTrustAnchors.productionTlsFetcherEncryptPublicKey,
                    Hex.encode(rogue.publicKey.x963Representation)] {
            #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) {
                try ZeroXKeySession.verified(jwt: jwt, dangerouslyOverrideNotarizerPublicKey: key, at: now)
            }
        }
        #expect(throws: ZeroXKeyCryptoError.invalidPublicKey) {
            try ZeroXKeySession.verified(jwt: jwt, dangerouslyOverrideNotarizerPublicKey: "04abcd", at: now)
        }
    }

    @Test func rejectsAnExpiredJwtAtTheInjectedClock() throws {
        let jwt = APIFixtures.jwt(claims(exp: t0 + 60))
        _ = try ZeroXKeySession.verified(jwt: jwt, dangerouslyOverrideNotarizerPublicKey: notarizer, at: now)
        for later in [t0 + 60, t0 + 61] {
            #expect(throws: ZeroXKeyError.sessionExpired) {
                try ZeroXKeySession.verified(jwt: jwt, dangerouslyOverrideNotarizerPublicKey: notarizer,
                                             at: Date(timeIntervalSince1970: later))
            }
        }
    }

    @Test func rejectsMalformedJwts() {
        let good = APIFixtures.jwt(claims())
        let parts = good.split(separator: ".").map(String.init)
        let unsigned = "\(parts[0]).\(parts[1])."
        let shortSignature = "\(parts[0]).\(parts[1]).\(APIFixtures.base64URL(Data(repeating: 1, count: 32)))"
        let notBase64 = "\(parts[0]).\(parts[1]).!!!"
        for jwt in [unsigned, "\(parts[0]).\(parts[1])", shortSignature, notBase64] {
            #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid, "\(jwt)") {
                try ZeroXKeySession.verified(jwt: jwt, dangerouslyOverrideNotarizerPublicKey: notarizer, at: now)
            }
        }
        for jwt in ["", "abc", "a.b.c", "\(parts[0])..\(parts[2])"] {
            #expect(throws: ZeroXKeyError.self, "\(jwt)") {
                try ZeroXKeySession.verified(jwt: jwt, dangerouslyOverrideNotarizerPublicKey: notarizer, at: now)
            }
        }
        var missingClaim = claims()
        missingClaim["organization_id"] = nil
        #expect(throws: ZeroXKeyError.invalidSessionToken("JWT payload missing required fields")) {
            try ZeroXKeySession.verified(jwt: APIFixtures.jwt(missingClaim), dangerouslyOverrideNotarizerPublicKey: notarizer, at: now)
        }
    }
}

@Suite("Session JWT verification (context)") @MainActor
struct SessionJwtContextTests {
    @Test func storeSessionRejectsAForgedJwtAndStoresNothing() async throws {
        let sessions = InMemorySessionStore()
        let ctx = makeContext(MockServer(), sessions: sessions)
        let key = try ctx.createKeyPair()
        let forged = APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: t0 + 3600, signer: rogue)
        await #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) { try await ctx.storeSession(jwt: forged) }
        let tampered = withPayload(APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: t0 + 3600),
                                   claims(publicKey: key, exp: t0 + 7200))
        await #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) { try await ctx.storeSession(jwt: tampered) }
        #expect(try sessions.allSessionKeys().isEmpty)
        #expect(ctx.authState != .authenticated && ctx.session == nil)
    }

    @Test func productionTrustAnchorsRejectTestSignedSessions() async throws {
        let ctx = makeContext(MockServer(), trustAnchors: .production)
        let key = try ctx.createKeyPair()
        let jwt = APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: t0 + 3600)
        await #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) { try await ctx.storeSession(jwt: jwt) }
    }

    @Test func storeSessionRejectsAnExpiredJwt() async throws {
        let ctx = makeContext(MockServer())
        let key = try ctx.createKeyPair()
        let jwt = APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: t0)
        await #expect(throws: ZeroXKeyError.sessionExpired) { try await ctx.storeSession(jwt: jwt) }
    }

    /// A login whose `stamp_login` answer carries a forged JWT does not sign anyone in.
    @Test func passkeyLoginWithAForgedSessionFails() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys, rpId: "login.example.org", assertion: FakeAsserter())
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let publicKey = (req.json["parameters"] as? [String: Any])?["publicKey"] as? String ?? ""
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(
                    publicKey: publicKey, organizationId: "o", userId: "u", exp: t0 + 3600, signer: rogue)]])))
        }
        await #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) { try await ctx.loginWithPasskey() }
        #expect(ctx.authState != .authenticated)
        #expect(try keys.listPublicKeys().isEmpty)
    }

    @Test func refreshWithAForgedSessionKeepsTheOldOne() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager(), sessions = InMemorySessionStore()
        let ctx = makeContext(server, keys: keys, sessions: sessions)
        let key = try ctx.createKeyPair()
        let original = APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: t0 + 3600)
        try await ctx.storeSession(jwt: original)
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let publicKey = (req.json["parameters"] as? [String: Any])?["publicKey"] as? String ?? ""
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(
                    publicKey: publicKey, organizationId: "o", userId: "u", exp: t0 + 7200, signer: rogue)]])))
        }
        await #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) { try await ctx.refreshSession() }
        #expect(ctx.session?.token == original)
        #expect(try sessions.token(sessionKey: ZeroXKeySessionKey.default) == original)
        #expect(try keys.listPublicKeys() == [key])
    }

    @Test func restoreAndSetActiveSessionRejectAForgedStoredJwt() async throws {
        let keys = InMemoryKeyManager(), sessions = InMemorySessionStore()
        let key = try keys.createKeyPair()
        try sessions.store(token: APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: 4_102_444_800,
                                                         signer: rogue), sessionKey: "k")
        try sessions.setActiveSessionKey("k")
        let ctx = makeContext(MockServer(), keys: keys, sessions: sessions)
        ZeroXKeyContext.configure(ctx.config)
        #expect(ZeroXKeyContext.shared.authState == .unauthenticated)
        #expect(throws: ZeroXKeyError.sessionJwtSignatureInvalid) { try ctx.setActiveSession(sessionKey: "k") }
        #expect(ctx.session == nil)
    }
}
