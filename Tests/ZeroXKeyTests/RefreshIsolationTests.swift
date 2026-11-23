import Foundation
import Testing
import ZeroXKey
import ZeroXKeyEncoding
import ZeroXKeyTestSupport

/// A refresh must not write over state that changed while its `stamp_login` was in flight, and
/// `refreshSession(sessionKey:)` refreshes exactly that slot.
/// Public key of the `X-Stamp` header (for routing mock responses by stamping session).
func stampPublicKey(_ req: RecordedRequest) throws -> String {
    guard let value = req.header("X-Stamp"),
          let json = try JSONSerialization.jsonObject(with: Base64URL.decode(value)) as? [String: String],
          let pk = json["publicKey"] else { throw ZeroXKeyError.badResponse("no X-Stamp") }
    return pk
}

@Suite("Refresh isolation") @MainActor
struct RefreshIsolationTests {
    nonisolated static let t0: TimeInterval = 1_763_500_000

    /// `stamp_login` answers with a session for the request's public key, for the user and
    /// organization of the stamping session (looked up by the stamp's public key).
    func loginRoute(_ server: MockServer, delay: TimeInterval = 0, users: [String: (user: String, org: String)]) {
        server.on("/public/v1/submit/stamp_login") { req, _ in
            if delay > 0 { Thread.sleep(forTimeInterval: delay) }
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            let stampKey = (try? stampPublicKey(req)) ?? ""
            let who = users[stampKey] ?? (user: "unknown", org: "unknown")
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                organizationId: who.org, status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(
                    publicKey: pk, organizationId: who.org, userId: who.user, exp: Self.t0 + 1800)]])))
        }
    }

    // MARK: D2 - logout / switch during refresh

    @Test func logoutDuringRefreshDoesNotRevive() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: Self.t0 + 900))
        loginRoute(server, delay: 0.2, users: [key: ("u", "org-1")])

        let refresh = Task { try await ctx.refreshSession() }
        #expect(await eventually { server.requests(to: "/public/v1/submit/stamp_login").count == 1 })
        try ctx.logout()
        let result = await refresh.result

        #expect(throws: ZeroXKeyError.sessionChanged) { try result.get() }
        #expect(ctx.session == nil && ctx.authState != .authenticated)
        #expect(try ctx.sessionKeys().isEmpty && ctx.activeSessionKey() == nil)
        // Neither the old key (deleted by logout) nor the refresh's new key is left behind.
        #expect(try keys.listPublicKeys().isEmpty)
    }

    @Test func switchingSessionDuringRefreshDiscardsResult() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        let a = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: a, organizationId: "org-a", userId: "ua", exp: Self.t0 + 900), sessionKey: "a")
        let b = try ctx.createKeyPair()
        let jwtB = APIFixtures.sessionJWT(publicKey: b, organizationId: "org-b", userId: "ub", exp: Self.t0 + 900)
        try await ctx.storeSession(jwt: jwtB, sessionKey: "b")
        let jwtA = try #require(try ctx.storedSession(sessionKey: "a")?.token)
        try ctx.setActiveSession(sessionKey: "a")
        loginRoute(server, delay: 0.2, users: [a: ("ua", "org-a")])

        let refresh = Task { try await ctx.refreshSession() }
        #expect(await eventually { server.requests(to: "/public/v1/submit/stamp_login").count == 1 })
        try ctx.setActiveSession(sessionKey: "b")
        let result = await refresh.result

        #expect(throws: ZeroXKeyError.sessionChanged) { try result.get() }
        #expect(try ctx.activeSessionKey() == "b" && ctx.session?.token == jwtB)
        #expect(try ctx.storedSession(sessionKey: "a")?.token == jwtA)   // untouched
        #expect(Set(try keys.listPublicKeys()) == [a, b])                 // new key cleaned up
    }

    // MARK: D3 - refreshSession(sessionKey:) on a non-active slot

    @Test func refreshNamedNonActiveSlotUsesThatSlot() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        let bob = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: bob, organizationId: "org-b", userId: "bob", exp: Self.t0 + 900), sessionKey: "B")
        let alice = try ctx.createKeyPair()
        let jwtAlice = APIFixtures.sessionJWT(publicKey: alice, organizationId: "org-a", userId: "alice", exp: Self.t0 + 900)
        try await ctx.storeSession(jwt: jwtAlice, sessionKey: "A")
        #expect(try ctx.activeSessionKey() == "A")
        loginRoute(server, users: [alice: ("alice", "org-a"), bob: ("bob", "org-b")])

        let jwt = try await ctx.refreshSession(sessionKey: "B")

        // Stamped by bob's key, in bob's organization.
        let req = try #require(server.requests(to: "/public/v1/submit/stamp_login").first)
        _ = try verifyStamp(req, publicKey: bob)
        #expect(req.json["organizationId"] as? String == "org-b")
        // Slot B holds bob's new session; A stays active and untouched.
        let b = try #require(try ctx.storedSession(sessionKey: "B"))
        #expect(b.token == jwt && b.userId == "bob" && b.organizationId == "org-b" && b.publicKey != bob)
        #expect(try ctx.activeSessionKey() == "A")
        #expect(ctx.session?.token == jwtAlice && ctx.session?.userId == "alice")
        #expect(try ctx.storedSession(sessionKey: "A")?.token == jwtAlice)
        // bob's old key is gone, alice's key and bob's new key remain.
        #expect(Set(try keys.listPublicKeys()) == [alice, b.publicKey])
    }

    @Test func refreshNamedActiveSlotStillActivates() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let k = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: k, organizationId: "org-a", userId: "alice", exp: Self.t0 + 900), sessionKey: "A")
        loginRoute(server, users: [k: ("alice", "org-a")])
        let jwt = try await ctx.refreshSession(sessionKey: "A")
        #expect(ctx.session?.token == jwt && ctx.session?.publicKey != k && ctx.authState == .authenticated)
    }

    @Test func refreshUnknownSlotThrows() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let k = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: k, organizationId: "org-a", userId: "alice", exp: Self.t0 + 900))
        await #expect(throws: ZeroXKeyError.noActiveSession) { try await ctx.refreshSession(sessionKey: "missing") }
        #expect(server.requests(to: "/public/v1/submit/stamp_login").isEmpty)
    }
}
