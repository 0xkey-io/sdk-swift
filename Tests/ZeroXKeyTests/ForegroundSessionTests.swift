import Foundation
import Testing
import ZeroXKey
import ZeroXKeyTestSupport

/// Records `onSessionEvent` deliveries.
@MainActor
final class EventLog {
    var events: [String] = []
    func record(_ e: ZeroXKeySessionEvent) {
        switch e {
        case .refreshed(let s): events.append("refreshed:\(s.expiry)")
        case .refreshFailed(let key, let error): events.append("refreshFailed:\(key):\(error is ZeroXKeyRequestError)")
        case .expired(let key): events.append("expired:\(key)")
        }
    }
}

@Suite("Session check on app foreground") @MainActor
struct ForegroundSessionTests {
    let t0: TimeInterval = 1_763_500_000
    nonisolated static let foreground = Notification.Name("test.app.foreground")

    struct Setup {
        let ctx: ZeroXKeyContext
        let server: MockServer
        let keys: InMemoryKeyManager
        let time: TestTime
        let center: NotificationCenter
        let log: EventLog
        let key: String
        func enterForeground() { center.post(name: ForegroundSessionTests.foreground, object: nil) }
    }

    func setUp(autoRefresh: Bool = true) async throws -> Setup {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let time = TestTime(longReleases: 0)   // timers park: only the foreground check acts
        let center = NotificationCenter()
        let ctx = makeContext(server, keys: keys, autoRefresh: autoRefresh, clock: time.clock,
                              notificationCenter: center, foregroundNotification: Self.foreground)
        ctx.sleep = time.sleeper
        let log = EventLog()
        ctx.onSessionEvent = { log.record($0) }
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 900))
        return Setup(ctx: ctx, server: server, keys: keys, time: time, center: center, log: log, key: key)
    }

    func loginRoute(_ server: MockServer, exp: TimeInterval) {
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(publicKey: pk, organizationId: "org-1", userId: "u", exp: exp)]])))
        }
    }

    @Test func expiredWhileSuspendedIsCleared() async throws {
        let s = try await setUp()
        s.time.advance(901)
        s.enterForeground()
        #expect(await eventually { s.ctx.authState == .unauthenticated })
        #expect(s.log.events == ["expired:\(ZeroXKeySessionKey.default)"])
        #expect(try s.keys.listPublicKeys().isEmpty)
        #expect(try s.ctx.sessionKeys().isEmpty)
        #expect(s.server.requests.isEmpty)
    }

    @Test func withinLeadRefreshesImmediately() async throws {
        let s = try await setUp()
        loginRoute(s.server, exp: t0 + 870 + 900)
        s.time.advance(870)                   // 30 s left < 60 s lead
        s.enterForeground()
        #expect(await eventually { s.ctx.session?.publicKey != s.key })
        // The event follows the session update once refreshSession returns: wait for it.
        #expect(await eventually { s.log.events == ["refreshed:\(t0 + 1770)"] })
        #expect(s.server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(s.ctx.authState == .authenticated)
    }

    @Test func plentyLeftOnlyRearmsTimer() async throws {
        let s = try await setUp()
        #expect(await eventually { s.time.longSleeps == [840] })
        s.time.advance(300)
        s.enterForeground()
        #expect(await eventually { s.time.longSleeps == [840, 540] })   // 900 − 300 − 60
        #expect(s.server.requests.isEmpty && s.log.events.isEmpty)
    }

    @Test func failedForegroundRefreshKeepsSessionUntilExpiry() async throws {
        let s = try await setUp()
        s.server.on("/public/v1/submit/stamp_login", respond: .text("Unauthorized: session revoked\n", status: 401))
        s.time.advance(870)
        s.enterForeground()
        #expect(await eventually { s.log.events == ["refreshFailed:\(ZeroXKeySessionKey.default):true"] })
        #expect(s.ctx.session?.publicKey == s.key && s.ctx.authState == .authenticated)
        // Expiry cutoff re-armed for the remaining 30 s, without another refresh attempt.
        #expect(await eventually { s.time.longSleeps.last == 30 })
        #expect(s.server.requests(to: "/public/v1/submit/stamp_login").count == 1)
    }

    @Test func overlappingChecksRefreshOnce() async throws {
        let s = try await setUp()
        loginRoute(s.server, exp: t0 + 1770)
        s.time.advance(870)
        async let a: Void = s.ctx.checkSessionOnForeground()
        async let b: Void = s.ctx.checkSessionOnForeground()
        _ = await (a, b)
        #expect(s.server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(s.log.events == ["refreshed:\(t0 + 1770)"])
    }

    @Test func autoRefreshOffOnlyExpires() async throws {
        let s = try await setUp(autoRefresh: false)
        s.time.advance(870)
        s.enterForeground()
        #expect(await eventually { s.time.longSleeps.count == 2 })
        #expect(s.server.requests.isEmpty && s.ctx.authState == .authenticated)
        s.time.advance(31)
        await s.ctx.checkSessionOnForeground()
        #expect(s.ctx.authState == .unauthenticated)
        #expect(s.log.events == ["expired:\(ZeroXKeySessionKey.default)"])
    }

    @Test func noSessionIsANoOp() async throws {
        let server = MockServer()
        let ctx = makeContext(server, autoRefresh: true)
        await ctx.checkSessionOnForeground()
        #expect(ctx.authState != .authenticated && server.requests.isEmpty)
    }
}

@Suite("Overlapping session refreshes") @MainActor
struct RefreshDedupTests {
    let t0: TimeInterval = 1_763_500_000

    func setUp(_ server: MockServer, delayFirst: Bool = true) async throws -> (ZeroXKeyContext, String) {
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 900))
        server.on("/public/v1/submit/stamp_login") { req, n in
            if delayFirst && n == 0 { Thread.sleep(forTimeInterval: 0.1) }   // keep the first request in flight
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(publicKey: pk, organizationId: "org-1", userId: "u", exp: t0 + 1800 + Double(n))]])))
        }
        return (ctx, key)
    }

    @Test func concurrentManualRefreshesShareOneRequest() async throws {
        let server = MockServer()
        let (ctx, oldKey) = try await setUp(server)
        async let a = ctx.refreshSession()
        async let b = ctx.refreshSession()
        let (ja, jb) = try await (a, b)
        #expect(ja == jb)
        #expect(server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(ctx.session?.token == ja && ctx.session?.publicKey != oldKey)
        // Finished refreshes are not reused: the next call sends a new request.
        let jc = try await ctx.refreshSession()
        #expect(jc != ja && server.requests(to: "/public/v1/submit/stamp_login").count == 2)
    }

    @Test func manualRefreshJoinsForegroundRefresh() async throws {
        let server = MockServer()
        let time = TestTime(longReleases: 0)
        let ctx = makeContext(server, autoRefresh: true, clock: time.clock)
        ctx.sleep = time.sleeper
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 900))
        server.on("/public/v1/submit/stamp_login") { req, _ in
            Thread.sleep(forTimeInterval: 0.1)
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(publicKey: pk, organizationId: "org-1", userId: "u", exp: t0 + 1800)]])))
        }
        var events: [String] = []
        ctx.onSessionEvent = { if case .refreshed = $0 { events.append("refreshed") } }
        time.advance(870)   // 30 s left: the foreground check refreshes
        async let foreground: Void = ctx.checkSessionOnForeground()
        async let manual = ctx.refreshSession()
        let (_, jwt) = try await (foreground, manual)
        #expect(ctx.session?.token == jwt && ctx.session?.publicKey != key)
        #expect(server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(events == ["refreshed"])
    }

    @Test func joinedCallersSeeTheSameError() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 900))
        server.on("/public/v1/submit/stamp_login") { _, _ in
            Thread.sleep(forTimeInterval: 0.1)
            return .text("Unauthorized: session revoked\n", status: 401)
        }
        async let a: String? = try? ctx.refreshSession()
        async let b: String? = try? ctx.refreshSession()
        let (ra, rb) = await (a, b)
        #expect(ra == nil && rb == nil)
        #expect(server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(ctx.session?.publicKey == key)
    }
}
