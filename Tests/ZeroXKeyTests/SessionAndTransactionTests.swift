import Foundation
import Testing
import ZeroXKey
import ZeroXKeyEncoding
import ZeroXKeyTestSupport

/// Controllable time for timers and polling. Short sleeps (< `instantBelow`) return at once
/// and advance the clock; long sleeps (session timers) return only while `longReleases` > 0,
/// otherwise they park until cancelled.
final class TestTime: @unchecked Sendable {
    private let lock = NSLock()
    private var _now: Date
    private var _longReleases: Int
    private var _longSleeps: [TimeInterval] = []
    let instantBelow: TimeInterval

    init(start: Date = Date(timeIntervalSince1970: 1_763_500_000), longReleases: Int = 0, instantBelow: TimeInterval = 5) {
        _now = start
        _longReleases = longReleases
        self.instantBelow = instantBelow
    }

    var now: Date { lock.withLock { _now } }
    /// Moves the clock without a sleep (the app was suspended).
    func advance(_ seconds: TimeInterval) { lock.withLock { _now = _now.addingTimeInterval(seconds) } }
    var longSleeps: [TimeInterval] { lock.withLock { _longSleeps } }
    var clock: @Sendable () -> Date { { [self] in now } }

    var sleeper: @Sendable (TimeInterval) async throws -> Void {
        { [self] seconds in
            if seconds < instantBelow {
                lock.withLock { _now = _now.addingTimeInterval(max(0, seconds)) }
                await Task.yield()
                return
            }
            let release: Bool = lock.withLock {
                _longSleeps.append(seconds)
                guard _longReleases > 0 else { return false }
                _longReleases -= 1
                _now = _now.addingTimeInterval(seconds)
                return true
            }
            if !release { try await Task.sleep(nanoseconds: 3_600_000_000_000) }
        }
    }
}

@MainActor
func eventually(_ condition: @MainActor () -> Bool) async -> Bool {
    for _ in 0..<400 {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return condition()
}

@Suite("Session lifecycle (refresh / expiry)") @MainActor
struct SessionLifecycleTests {
    let t0: TimeInterval = 1_763_500_000

    func loginRoute(_ server: MockServer, org: String = "org-1", lifetime: TimeInterval = 900, base: TimeInterval) {
        server.on("/public/v1/submit/stamp_login") { req, _ in
            let pk = (req.json["parameters"] as! [String: Any])["publicKey"] as! String
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                organizationId: org, status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
                result: ["stampLoginResult": ["session": APIFixtures.sessionJWT(
                    publicKey: pk, organizationId: org, userId: "u", exp: base + lifetime)]])))
        }
    }

    @Test func manualRefreshRotatesKeyAndStampsWithOldKey() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        let oldKey = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: oldKey, organizationId: "org-1", userId: "u", exp: t0 + 900))
        loginRoute(server, lifetime: 3600, base: t0)

        let jwt = try await ctx.refreshSession(expirationSeconds: "3600")

        let req = try #require(server.requests(to: "/public/v1/submit/stamp_login").first)
        _ = try verifyStamp(req, publicKey: oldKey)
        let params = try #require(req.json["parameters"] as? [String: String])
        #expect(params["expirationSeconds"] == "3600")
        let newKey = try #require(params["publicKey"])
        #expect(newKey != oldKey)
        #expect(ctx.session?.publicKey == newKey && ctx.session?.token == jwt)
        #expect(ctx.session?.expiry == t0 + 3600)
        #expect(try keys.listPublicKeys() == [newKey])   // old key deleted
    }

    @Test func refreshKeepsSessionProfile() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.jwt([
            "exp": t0 + 900, "public_key": key, "session_type": "SESSION_TYPE_READ_WRITE",
            "user_id": "u", "organization_id": "org-1", "session_profile_id": "profile-1"]))
        #expect(ctx.session?.sessionProfileId == "profile-1")
        loginRoute(server, base: t0)
        try await ctx.refreshSession()
        let params = try #require(server.requests(to: "/public/v1/submit/stamp_login").first?.json["parameters"] as? [String: Any])
        #expect(params["sessionProfileId"] as? String == "profile-1")
    }

    @Test func failedRefreshKeepsOldSessionAndDropsNewKey() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        let oldKey = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: oldKey, organizationId: "org-1", userId: "u", exp: t0 + 900))
        server.on("/public/v1/submit/stamp_login", respond: .text("Unauthorized: session expired", status: 401))
        await #expect(throws: ZeroXKeyRequestError.self) { try await ctx.refreshSession() }
        #expect(ctx.session?.publicKey == oldKey)
        #expect(try keys.listPublicKeys() == [oldKey])
    }

    @Test func autoRefreshRunsLeadSecondsBeforeExpiry() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let time = TestTime(longReleases: 1)
        let ctx = makeContext(server, keys: keys, autoRefresh: true, clock: time.clock)
        ctx.sleep = time.sleeper
        loginRoute(server, base: t0 + 840)
        let oldKey = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: oldKey, organizationId: "org-1", userId: "u", exp: t0 + 900))

        #expect(await eventually { ctx.session?.publicKey != oldKey })
        #expect(time.longSleeps.first == 840)          // 900 s lifetime − 60 s lead
        #expect(server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(ctx.authState == .authenticated)
        #expect(try keys.listPublicKeys() == [ctx.session!.publicKey])
        // The refreshed session schedules its own refresh (parked: no releases left).
        #expect(await eventually { time.longSleeps.count == 2 })
        #expect(time.longSleeps.last == 840)
    }

    /// A refresh that yields a session no longer than the lead time (e.g. a short session
    /// profile) must not loop refreshing, and that session still ends at its expiry.
    @Test func refreshedSessionWithinLeadOnlyExpires() async throws {
        let server = MockServer()
        let time = TestTime(longReleases: 2)
        let ctx = makeContext(server, autoRefresh: true, clock: time.clock)
        ctx.sleep = time.sleeper
        var events: [String] = []
        ctx.onSessionEvent = { e in
            switch e {
            case .refreshed: events.append("refreshed")
            case .refreshFailed: events.append("refreshFailed")
            case .expired: events.append("expired")
            }
        }
        loginRoute(server, lifetime: 30, base: t0 + 840)   // new session: 30 s left, lead 60 s
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 900))

        #expect(await eventually { ctx.authState == .unauthenticated })
        #expect(server.requests(to: "/public/v1/submit/stamp_login").count == 1)
        #expect(time.longSleeps == [840, 30])
        #expect(events == ["refreshed", "expired"])
    }

    @Test func expiryClearsSessionWhenRefreshFails() async throws {
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let time = TestTime(longReleases: 2)
        let ctx = makeContext(server, keys: keys, autoRefresh: true, clock: time.clock)
        ctx.sleep = time.sleeper
        var events: [String] = []
        ctx.onSessionEvent = { e in
            switch e {
            case .refreshed: events.append("refreshed")
            case .refreshFailed(let k, _): events.append("refreshFailed:\(k)")
            case .expired(let k): events.append("expired:\(k)")
            }
        }
        server.on("/public/v1/submit/stamp_login", respond: .json(["code": 16, "message": "expired", "details": []], status: 401))
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 900))

        #expect(await eventually { ctx.authState == .unauthenticated })
        #expect(time.longSleeps == [840, 60])
        #expect(events == ["refreshFailed:\(ZeroXKeySessionKey.default)", "expired:\(ZeroXKeySessionKey.default)"])
        // makeContext has an Auth Proxy configuration, so the client falls back to the
        // unauthenticated Auth Proxy client (no stamper); it never keeps the session's.
        #expect(ctx.session == nil)
        #expect(ctx.client != nil && ctx.client?.stamper == nil)
        #expect(try keys.listPublicKeys().isEmpty)
    }

    @Test func withoutAutoRefreshSessionEndsAtExpiry() async throws {
        let server = MockServer()
        let time = TestTime(longReleases: 1)
        let ctx = makeContext(server, autoRefresh: false, clock: time.clock)
        ctx.sleep = time.sleeper
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 900))
        #expect(await eventually { ctx.authState == .unauthenticated })
        #expect(time.longSleeps == [900])
        #expect(server.requests.isEmpty)
    }

    @Test func logoutCancelsTimer() async throws {
        let server = MockServer()
        let time = TestTime(longReleases: 0)
        let ctx = makeContext(server, autoRefresh: true, clock: time.clock)
        ctx.sleep = time.sleeper
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 900))
        #expect(await eventually { time.longSleeps.count == 1 })
        try ctx.logout()
        try await Task.sleep(nanoseconds: 50_000_000)
        #expect(server.requests.isEmpty && ctx.authState == .unauthenticated)
    }

    @Test func currentThrowsWhenUnconfiguredIsNotCrash() throws {
        // `current()` only throws before any configure; after configure it returns the context.
        if let c = try? ZeroXKeyContext.current() { #expect(c === ZeroXKeyContext.shared) }
        else { #expect(throws: ZeroXKeyError.notConfigured) { try ZeroXKeyContext.current() } }
    }
}

@Suite("Transactions") @MainActor
struct TransactionTests {
    let t0: TimeInterval = 1_763_500_000

    func authed(_ server: MockServer, time: TestTime) async throws -> (ZeroXKeyContext, String) {
        let ctx = makeContext(server, clock: time.clock)
        ctx.sleep = time.sleeper
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: t0 + 3600))
        return (ctx, key)
    }

    static func sendResponse(_ type: String) -> MockResponse {
        .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", type: type,
            result: [type == "ACTIVITY_TYPE_ETH_SEND_TRANSACTION" ? "ethSendTransactionResult" : "solSendTransactionResult":
                        ["sendTransactionStatusId": "stx-1"]])))
    }

    @Test func ethSendDropsGasFieldsWhenSponsored() async throws {
        let server = MockServer()
        let (ctx, key) = try await authed(server, time: TestTime())
        server.on("/public/v1/submit/eth_send_transaction", respond: Self.sendResponse("ACTIVITY_TYPE_ETH_SEND_TRANSACTION"))

        let id = try await ctx.ethSendTransaction(TEthSendTransactionBody(
            from: "0xfrom", caip2: "eip155:8453", to: "0xto", sponsor: true, value: "1",
            gasLimit: "21000", maxFeePerGas: "9", maxPriorityFeePerGas: "1", gasStationNonce: "7"))
        #expect(id == "stx-1")
        let req = try #require(server.requests.first)
        _ = try verifyStamp(req, publicKey: key)
        #expect(req.json["type"] as? String == "ACTIVITY_TYPE_ETH_SEND_TRANSACTION")
        let p = try #require(req.json["parameters"] as? [String: Any])
        #expect(Set(p.keys) == ["from", "caip2", "to", "sponsor", "value", "gasStationNonce"])

        _ = try await ctx.ethSendTransaction(TEthSendTransactionBody(
            from: "0xfrom", caip2: "eip155:1", to: "0xto", sponsor: false, gasLimit: "21000", gasStationNonce: "7"))
        let p2 = try #require(server.requests.last?.json["parameters"] as? [String: Any])
        #expect(Set(p2.keys) == ["from", "caip2", "to", "gasLimit"])
    }

    @Test func pollReturnsOnIncluded() async throws {
        let server = MockServer()
        let (ctx, _) = try await authed(server, time: TestTime())
        server.on("/public/v1/query/get_send_transaction_status") { req, n in
            #expect(req.json["sendTransactionStatusId"] as? String == "stx-1")
            return n < 2 ? .json(["txStatus": "PENDING"]) : .json(["txStatus": "INCLUDED", "eth": ["txHash": "0xabc"]])
        }
        let res = try await ctx.pollTransactionStatus(sendTransactionStatusId: "stx-1")
        #expect(res.txStatus == "INCLUDED" && res.eth?.txHash == "0xabc")
        #expect(server.requests(to: "/public/v1/query/get_send_transaction_status").count == 3)
    }

    @Test func pollFailsWithMessage() async throws {
        let server = MockServer()
        let (ctx, _) = try await authed(server, time: TestTime())
        server.on("/public/v1/query/get_send_transaction_status",
                  respond: .json(["txStatus": "FAILED", "error": ["message": "execution reverted"]]))
        await #expect(throws: ZeroXKeyError.transactionFailed(sendTransactionStatusId: "stx-1", status: "FAILED", message: "execution reverted")) {
            try await ctx.pollTransactionStatus(sendTransactionStatusId: "stx-1")
        }
    }

    @Test func pollTimesOut() async throws {
        let server = MockServer()
        let (ctx, _) = try await authed(server, time: TestTime())
        server.on("/public/v1/query/get_send_transaction_status", respond: .json(["txStatus": "BROADCASTING"]))
        await #expect(throws: ZeroXKeyError.transactionPollingTimedOut(sendTransactionStatusId: "stx-1", lastStatus: "BROADCASTING")) {
            try await ctx.pollTransactionStatus(sendTransactionStatusId: "stx-1", pollingInterval: 1, timeout: 3)
        }
        #expect(server.requests(to: "/public/v1/query/get_send_transaction_status").count == 3)
    }

    @Test func signAndSendBroadcastsPerChain() async throws {
        let server = MockServer()
        let (ctx, _) = try await authed(server, time: TestTime())
        server.on("/public/v1/submit/sign_transaction") { req, _ in
            let type = (req.json["parameters"] as! [String: Any])["type"] as! String
            return .json(APIFixtures.activityResponse(APIFixtures.activity(
                status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
                result: ["signTransactionResult": ["signedTransaction": type == "TRANSACTION_TYPE_ETHEREUM" ? "02f8aa" : "0102ff"]])))
        }
        server.on("/rpc") { req, _ in
            req.json["method"] as? String == "eth_sendRawTransaction"
                ? .json(["jsonrpc": "2.0", "id": 1, "result": "0xhash"])
                : .json(["jsonrpc": "2.0", "id": 1, "result": "solSig"])
        }
        server.on("/tron/wallet/broadcasthex", respond: .json(["result": true, "txid": "trontx"]))
        let rpc = server.apiURL.appendingPathComponent("rpc").absoluteString

        #expect(try await ctx.signAndSendTransaction(signWith: "0xa", unsignedTransaction: "02", type: .TRANSACTION_TYPE_ETHEREUM, rpcUrl: rpc) == "0xhash")
        let eth = try #require(server.requests(to: "/rpc").first?.json)
        #expect(eth["method"] as? String == "eth_sendRawTransaction")
        #expect(eth["params"] as? [String] == ["0x02f8aa"])

        #expect(try await ctx.signAndSendTransaction(signWith: "So1", unsignedTransaction: "00", type: .TRANSACTION_TYPE_SOLANA, rpcUrl: rpc) == "solSig")
        let sol = try #require(server.requests(to: "/rpc").last?.json)
        let params = try #require(sol["params"] as? [Any])
        #expect(params.first as? String == "LiA")        // base58(0x0102ff = 66303 = 19·58² + 41·58 + 9), by hand
        #expect((params.last as? [String: String]) == ["encoding": "base58"])

        let tronURL = server.apiURL.appendingPathComponent("tron").absoluteString
        #expect(try await ctx.signAndSendTransaction(signWith: "T1", unsignedTransaction: "00", type: .TRANSACTION_TYPE_TRON, rpcUrl: tronURL) == "trontx")
        #expect(server.requests(to: "/tron/wallet/broadcasthex").first?.json as? [String: String] == ["transaction": "0102ff"])
    }

    @Test func broadcastRpcErrorIsNamed() async throws {
        let server = MockServer()
        let (ctx, _) = try await authed(server, time: TestTime())
        server.on("/public/v1/submit/sign_transaction", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", result: ["signTransactionResult": ["signedTransaction": "02"]]))))
        server.on("/rpc", respond: .json(["jsonrpc": "2.0", "id": 1, "error": ["code": -32000, "message": "nonce too low"]]))
        await #expect(throws: ZeroXKeyError.broadcastFailed("RPC error: nonce too low")) {
            try await ctx.signAndSendTransaction(signWith: "0xa", unsignedTransaction: "02", type: .TRANSACTION_TYPE_ETHEREUM,
                                                 rpcUrl: server.apiURL.appendingPathComponent("rpc").absoluteString)
        }
        await #expect(throws: ZeroXKeyError.invalidArgument("rpcUrl")) {
            try await ctx.signAndSendTransaction(signWith: "0xa", unsignedTransaction: "02", type: .TRANSACTION_TYPE_ETHEREUM, rpcUrl: "ftp://x")
        }
    }

    @Test func rpcUrlMustBeHttpsExceptLoopback() async throws {
        let server = MockServer()
        let (ctx, _) = try await authed(server, time: TestTime())
        for bad in ["http://rpc.example.org", "http://10.0.0.5:8545", "http://localhost.example.org", "ws://localhost", "https://", "rpc.example.org",
                    "http://localhost@rpc.example.org", "http://user:pw@127.0.0.1:8545", "http://127.1:8545"] {
            await #expect(throws: ZeroXKeyError.invalidArgument("rpcUrl"), "\(bad)") {
                try await ctx.signAndSendTransaction(signWith: "0xa", unsignedTransaction: "02", type: .TRANSACTION_TYPE_ETHEREUM, rpcUrl: bad)
            }
        }
        #expect(server.requests.isEmpty)   // rejected before anything is signed
        for ok in ["https://rpc.example.org", "HTTPS://rpc.example.org/v1", "http://localhost:8545", "http://127.0.0.1:8899", "http://127.0.0.2:8899", "http://[::1]:8545"] {
            #expect(ZeroXKeyContext.isAllowedRpcURL(URL(string: ok)!), "\(ok)")
        }
    }

    @Test func walletsFetchedConcurrentlyKeepOrder() async throws {
        let server = MockServer()
        let (ctx, _) = try await authed(server, time: TestTime())
        server.on("/public/v1/query/list_wallets", respond: .json(["wallets": (1...5).map { APIFixtures.wallet(id: "w\($0)", name: "W\($0)") }]))
        server.on("/public/v1/query/list_wallet_accounts") { req, _ in
            let id = req.json["walletId"] as! String
            return .json(["accounts": [APIFixtures.walletAccount(walletId: id, organizationId: "org-1", address: "addr-\(id)")]])
        }
        let wallets = try await ctx.refreshWallets()
        #expect(wallets.map(\.walletId) == ["w1", "w2", "w3", "w4", "w5"])
        #expect(wallets.map { $0.accounts.first?.address } == ["addr-w1", "addr-w2", "addr-w3", "addr-w4", "addr-w5"])
        #expect(server.requests(to: "/public/v1/query/list_wallet_accounts").count == 5)
    }
}
