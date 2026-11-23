import Combine
import Foundation
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyHttp
import ZeroXKeyStamper

/// High-level, observable entry point.
///
/// Flows follow sdk-js `packages/core/src/__clients__/core.ts`. Each method cites
/// the sdk-js function it mirrors. Only endpoints present in 0xkey's swagger are used.
@MainActor
public final class ZeroXKeyContext: ObservableObject {
    // MARK: Singleton

    private static var _shared: ZeroXKeyContext?

    /// The configured shared context. Call `configure(_:)` first.
    public static var shared: ZeroXKeyContext {
        guard let s = _shared else {
            preconditionFailure("ZeroXKeyContext.configure(_:) must be called before using ZeroXKeyContext.shared")
        }
        return s
    }

    /// Non-crashing variant of `shared`: throws `ZeroXKeyError.notConfigured`.
    public static func current() throws -> ZeroXKeyContext {
        guard let s = _shared else { throw ZeroXKeyError.notConfigured }
        return s
    }

    /// Configures `shared` and restores a stored session if there is one.
    public static func configure(_ config: ZeroXKeyConfig) {
        _shared?.cancelSessionTimer()
        let ctx = ZeroXKeyContext(config: config)
        _shared = ctx
        ctx.restoreSession()
        // After the session is restored, so the Auth Proxy request never delays `authState`.
        ctx.startRuntimeConfigFetch()
    }

    // MARK: Published state

    @Published public private(set) var authState: AuthState = .loading
    @Published public private(set) var session: ZeroXKeySession?
    @Published public private(set) var user: v1User?
    @Published public private(set) var wallets: [ZeroXKeyWallet] = []
    /// The client to use right now.
    ///
    /// - Signed in: the session-bound client, which stamps with the session API key and targets the
    ///   session's organization.
    /// - Before login and after logout or expiry: an unauthenticated Auth Proxy client without a
    ///   stamper, so an app can read the remote configuration before anyone signs in:
    ///   `ZeroXKeyContext.shared.client?.proxyGetWalletKitConfig()`. Only Auth Proxy routes work with it.
    /// - `nil` when there is no session and no `authProxyConfigId`.
    ///
    /// `client != nil` therefore does not mean "signed in": use `authState` or `session`. The SDK's own
    /// session methods ignore the unauthenticated client and throw `ZeroXKeyError.noActiveSession`.
    @Published public private(set) var client: ZeroXKeyClient?
    /// The session-bound client of the active session; the only client session methods use (see `sessionClient()`).
    private var activeSessionClient: ZeroXKeyClient?

    public let config: ZeroXKeyConfig
    let now: @Sendable () -> Date
    /// One-time export target key generator; tests inject a fixed key to replay
    /// sdk-js-generated export bundles.
    package var makeTargetKeyPair: @Sendable () -> P256KeyPair = { generateP256KeyPair() }
    /// Platform authenticator installed by the `anchor:` overloads; injected config providers win.
    var platformPasskeyProvider: (any PasskeyAssertionProvider & PasskeyRegistrationProvider)?
    var passkeyAssertionProvider: (any PasskeyAssertionProvider)? { config.passkeyAssertionProvider ?? platformPasskeyProvider }
    var passkeyRegistrationProvider: (any PasskeyRegistrationProvider)? { config.passkeyRegistrationProvider ?? platformPasskeyProvider }
    /// Suspends for the given seconds; tests inject a controllable sleeper.
    package var sleep: @Sendable (TimeInterval) async throws -> Void = { seconds in
        try await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
    }
    /// Randomness for PKCE verifier / state; tests inject fixed bytes.
    package var oauthRandomBytes: @Sendable (Int) -> Data = { ZeroXKeyContext.randomBytes($0) }
    /// Google token endpoint; tests point it at a mock host.
    package var googleTokenURL: URL = ZeroXKeyContext.googleTokenURL
    /// Pending refresh / expiry work for the active session.
    private var sessionTimer: Task<Void, Never>?
    /// The automatic refresh currently running per session key (timer or foreground check), so
    /// they never overlap for one slot; another slot's refresh is a task of its own.
    private var autoRefreshTasks: [String: Task<Bool, Never>] = [:]
    /// The `stamp_login` refresh running per session key, shared by overlapping `refreshSession` calls.
    private var refreshInFlight: [String: (id: UUID, task: Task<String, any Error>)] = [:]
    /// Bumped whenever the active session is (de)activated; a refresh of the active slot started
    /// under another epoch is discarded.
    private var sessionEpoch = 0
    /// JWT most recently stored by a refresh of the active session (see `scheduleSessionTimer`).
    private var justRefreshedToken: String?
    /// Removes the foreground observer when the context goes away.
    private var foregroundObservation: NotificationObservation?
    /// The Auth Proxy configuration and what it resolves to (see `loadRuntimeConfig`).
    var runtimeConfigState: RuntimeConfigState = .notLoaded

    /// Called on the main actor for automatic session lifecycle events: a refresh by the timer or
    /// the foreground check, a failed automatic refresh, and a session cleared at expiry.
    ///
    /// A callback rather than an `AsyncStream`: there is one owner (the app), delivery is
    /// synchronous on the main actor right where the state changes, and nothing is buffered
    /// while nobody listens (a stream needs a single long-lived consumer and buffers otherwise).
    /// For SwiftUI, observe `authState` / `session` as usual and use this for logging or
    /// "please sign in again" prompts.
    public var onSessionEvent: (@MainActor (ZeroXKeySessionEvent) -> Void)?

    /// Notification that means "the app returned to the foreground": UIKit
    /// `willEnterForegroundNotification`, AppKit `didBecomeActiveNotification`.
    public nonisolated static var appForegroundNotification: Notification.Name? {
        #if canImport(UIKit)
        UIApplication.willEnterForegroundNotification
        #elseif canImport(AppKit)
        NSApplication.didBecomeActiveNotification
        #else
        nil
        #endif
    }

    public convenience init(config: ZeroXKeyConfig) {
        self.init(config: config, now: { Date() })
    }

    /// - Parameter foregroundNotification: posted on `notificationCenter` when the app returns
    ///   to the foreground; triggers `checkSessionOnForeground()`. Tests inject their own.
    package init(config: ZeroXKeyConfig, now: @escaping @Sendable () -> Date,
                 notificationCenter: NotificationCenter = .default,
                 foregroundNotification: Notification.Name? = ZeroXKeyContext.appForegroundNotification) {
        self.config = config
        self.now = now
        // The unauthenticated Auth Proxy client exists before login.
        self.client = unauthenticatedClient()
        if let name = foregroundNotification {
            let token = notificationCenter.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    Task { await self.checkSessionOnForeground() }
                }
            }
            foregroundObservation = NotificationObservation(center: notificationCenter, token: token)
        }
    }

    // MARK: Clients

    /// Client without a stamper, used for Auth Proxy calls.
    func baseClient(stamper: (any Stamper)? = nil, organizationId: String? = nil) throws -> ZeroXKeyClient {
        ZeroXKeyClient(apiBaseURL: try config.apiBaseURL, stamper: stamper,
                       organizationId: organizationId ?? config.organizationId,
                       authProxyBaseURL: try config.authProxyBaseURL, authProxyConfigId: config.authProxyConfigId,
                       activityPoller: config.activityPoller, urlSession: config.urlSession, now: now,
                       transportSecurity: config.transportSecurity)
    }

    func proxyClient() throws -> ZeroXKeyClient {
        guard let id = config.authProxyConfigId, !id.isEmpty else { throw ZeroXKeyError.missingAuthProxyConfiguration }
        return try baseClient()
    }

    /// Auth Proxy client without a stamper; `nil` without `authProxyConfigId`.
    func unauthenticatedClient() -> ZeroXKeyClient? {
        guard let id = config.authProxyConfigId, !id.isEmpty else { return nil }
        return try? baseClient()
    }

    /// The session-bound client. Deliberately not `client`, which is the unauthenticated Auth Proxy
    /// client while nobody is signed in: a session call must never go out through it.
    func sessionClient() throws -> ZeroXKeyClient {
        guard let session, let client = activeSessionClient else { throw ZeroXKeyError.noActiveSession }
        if session.isExpired(at: now()) {
            authState = .unauthenticated
            throw ZeroXKeyError.sessionExpired
        }
        return client
    }

    var timestampName: String { String(Int64(now().timeIntervalSince1970 * 1000)) }

    // MARK: - Keys & sessions

    /// Generates a session key pair and returns its compressed public key
    /// (sdk-js `createApiKeyPair`).
    @discardableResult
    public func createKeyPair() throws -> String {
        try config.keyManager.createKeyPair()
    }

    /// Stores a session JWT (e.g. returned by your backend) and makes it active
    /// (sdk-js `storeSession`, core.ts:5566). The JWT's `public_key` must be in the key manager.
    ///
    /// The JWT must be signed by the notarizer of `config.trustAnchors` and not be expired; otherwise
    /// this throws (``ZeroXKeyError/sessionJwtSignatureInvalid``, ``ZeroXKeyError/sessionExpired``) and
    /// nothing is stored. Every sign-in method and `refreshSession` stores through here.
    public func storeSession(jwt: String, sessionKey: String = ZeroXKeySessionKey.default) async throws {
        let parsed = try verifiedSession(jwt)
        let stamper = try config.keyManager.stamper(forPublicKey: parsed.publicKey)
        // A new login under an existing session key replaces it; its old key pair is deleted
        // so re-login does not leak keys (and does not fail, unlike a "key exists" error).
        let replacedKey = (try? config.sessionStore.token(sessionKey: sessionKey))
            .flatMap { $0 }.flatMap { try? ZeroXKeySession.parse(jwt: $0) }?.publicKey
        try config.sessionStore.store(token: jwt, sessionKey: sessionKey)
        try config.sessionStore.setActiveSessionKey(sessionKey)
        activate(parsed, stamper: stamper, sessionKey: sessionKey)
        if let replacedKey, replacedKey != parsed.publicKey, !isKeyInUse(replacedKey) {
            try? config.keyManager.deleteKeyPair(publicKey: replacedKey)
        }
    }

    /// `jwt` decoded and checked against the notarizer of `config.trustAnchors` and the context clock.
    func verifiedSession(_ jwt: String) throws -> ZeroXKeySession {
        try ZeroXKeySession.verified(
            jwt: jwt, dangerouslyOverrideNotarizerPublicKey: config.trustAnchors.dangerouslyOverrideNotarizerPublicKey, at: now())
    }

    /// Whether another stored session still uses `publicKey`.
    func isKeyInUse(_ publicKey: String) -> Bool {
        let keys = (try? config.sessionStore.allSessionKeys()) ?? []
        return keys.contains { key in
            (try? config.sessionStore.token(sessionKey: key)).flatMap { $0 }
                .flatMap { try? ZeroXKeySession.parse(jwt: $0) }?.publicKey == publicKey
        }
    }

    // MARK: Multiple sessions

    /// Keys of all stored sessions (sdk-js `getAllSessions`).
    public func sessionKeys() throws -> [String] {
        try config.sessionStore.allSessionKeys()
    }

    /// A stored session by key without activating it (sdk-js `getSession`). Decoded only, like
    /// ``ZeroXKeySession/parse(jwt:)``: the signature is checked when a session is activated.
    public func storedSession(sessionKey: String) throws -> ZeroXKeySession? {
        try config.sessionStore.token(sessionKey: sessionKey).map { try ZeroXKeySession.parse(jwt: $0) }
    }

    /// The active session key, if any (sdk-js `getActiveSessionKey`).
    public func activeSessionKey() throws -> String? {
        try config.sessionStore.activeSessionKey()
    }

    /// Makes a stored session active (sdk-js `setActiveSession`). Published `user` / `wallets`
    /// are reset when the user changes; call `refreshUser()` / `refreshWallets()` afterwards.
    public func setActiveSession(sessionKey: String) throws {
        guard let jwt = try config.sessionStore.token(sessionKey: sessionKey) else { throw ZeroXKeyError.noActiveSession }
        let parsed = try verifiedSession(jwt)
        let stamper = try config.keyManager.stamper(forPublicKey: parsed.publicKey)
        try config.sessionStore.setActiveSessionKey(sessionKey)
        activate(parsed, stamper: stamper, sessionKey: sessionKey)
    }

    /// Clears every stored session and its key pair (sdk-js `clearAllSessions`).
    public func clearAllSessions() throws {
        for key in try config.sessionStore.allSessionKeys() { try clearSession(sessionKey: key) }
        deactivate()
    }

    /// **Unsafe.** Signs arbitrary bytes with the active session key; returns a DER ECDSA P-256
    /// signature over SHA-256(message).
    ///
    /// The session key is the credential behind every `X-Stamp`, and a stamp is exactly this
    /// signature over the request body. Signing caller-supplied bytes therefore lets whoever
    /// controls `message` mint a valid stamp for any request this session may make (sign
    /// transactions, export wallets, add authenticators). Only use it with bytes you constructed
    /// yourself and that can never parse as a 0xkey request body. Hidden behind
    /// `@_spi(Unsafe) import ZeroXKey` so it is not part of the default API.
    @_spi(Unsafe)
    public func unsafeSignWithSessionKey(_ message: Data) throws -> Data {
        guard let s = session else { throw ZeroXKeyError.noActiveSession }
        let stamper = try config.keyManager.stamper(forPublicKey: s.publicKey)
        return try stamper.sign(data: message, format: .der)
    }

    /// Clears a session and deletes its key pair (sdk-js `clearSession`, core.ts:5596).
    public func clearSession(sessionKey: String = ZeroXKeySessionKey.default) throws {
        let wasActive = try config.sessionStore.activeSessionKey() == sessionKey
        if let token = try config.sessionStore.token(sessionKey: sessionKey),
           let parsed = try? ZeroXKeySession.parse(jwt: token) {
            try config.keyManager.deleteKeyPair(publicKey: parsed.publicKey)
        }
        try config.sessionStore.remove(sessionKey: sessionKey)
        if wasActive { deactivate() }
    }

    /// Re-issues a session with a fresh key pair (sdk-js `refreshSession`, core.ts:5679): the
    /// active session, or the stored one named by `sessionKey`. `stamp_login` is stamped by that
    /// session's own key in its organization; the new JWT replaces it in the same slot and the old
    /// key pair is deleted. Refreshing a non-active slot does not change the active session.
    /// Returns the new JWT.
    ///
    /// Calls that overlap (manual, the refresh timer, the foreground check) share one request per
    /// session key: further calls wait for the running one and return its JWT (or its error); the
    /// running call's parameters apply. The shared request is not cancelled with a caller.
    ///
    /// If the slot was logged out, replaced or switched (to or away from active) while the request
    /// was in flight, the result is discarded, its new key pair deleted, and this throws
    /// `ZeroXKeyError.sessionChanged`.
    @discardableResult
    public func refreshSession(
        expirationSeconds: String? = nil, invalidateExisting: Bool = false, sessionKey: String? = nil
    ) async throws -> String {
        let key = try sessionKey ?? config.sessionStore.activeSessionKey() ?? ZeroXKeySessionKey.default
        if let running = refreshInFlight[key] { return try await running.task.value }
        let id = UUID()
        let task = Task { try await self.performRefresh(expirationSeconds: expirationSeconds,
                                                        invalidateExisting: invalidateExisting, sessionKey: key) }
        refreshInFlight[key] = (id, task)
        defer { if refreshInFlight[key]?.id == id { refreshInFlight[key] = nil } }
        return try await task.value
    }

    private func performRefresh(expirationSeconds: String?, invalidateExisting: Bool, sessionKey key: String) async throws -> String {
        // Resolved before the slot is read: nothing between reading it and writing the result may suspend.
        let lifetime = await resolvedExpirationSeconds(expirationSeconds)
        guard let oldJWT = try config.sessionStore.token(sessionKey: key) else { throw ZeroXKeyError.noActiveSession }
        let old = try ZeroXKeySession.parse(jwt: oldJWT)
        let wasActive = try config.sessionStore.activeSessionKey() == key
        let epoch = sessionEpoch
        let c = try baseClient(stamper: config.keyManager.stamper(forPublicKey: old.publicKey), organizationId: old.organizationId)
        let newKey = try createKeyPair()
        do {
            let res = try await c.stampLogin(TStampLoginBody(
                publicKey: newKey, expirationSeconds: lifetime,
                invalidateExisting: invalidateExisting ? true : nil, sessionProfileId: old.sessionProfileId))
            guard !res.session.isEmpty else { throw ZeroXKeyError.badResponse("stamp_login returned no session") }
            // Nothing may have changed while the request was in flight (logout, re-login, switch).
            let unchanged = (try? config.sessionStore.token(sessionKey: key)) == oldJWT
                && ((try? config.sessionStore.activeSessionKey()) == key) == wasActive
                && (!wasActive || sessionEpoch == epoch)
            guard unchanged else { throw ZeroXKeyError.sessionChanged }
            if wasActive {
                justRefreshedToken = res.session
                try await storeSession(jwt: res.session, sessionKey: key)
            } else {
                let parsed = try verifiedSession(res.session)
                _ = try config.keyManager.stamper(forPublicKey: parsed.publicKey)
                try config.sessionStore.store(token: res.session, sessionKey: key)
            }
        } catch {
            try? config.keyManager.deleteKeyPair(publicKey: newKey)
            throw error
        }
        if old.publicKey != newKey && !isKeyInUse(old.publicKey) { try? config.keyManager.deleteKeyPair(publicKey: old.publicKey) }
        return try config.sessionStore.token(sessionKey: key) ?? ""
    }

    /// Schedules auto-refresh (`config.auth.autoRefreshSession`, `sessionRefreshLeadSeconds`
    /// before expiry) and the expiry cutoff. Mirrors the sdk-js wallet-kit timers
    /// (react-native-wallet-kit ZeroXKeyProvider.tsx:400-489): refresh shortly before expiry;
    /// if refresh is off or fails, clear the session at expiry.
    func scheduleSessionTimer(for s: ZeroXKeySession, sessionKey: String, skipRefresh: Bool = false) {
        cancelSessionTimer()
        let remaining = s.expiry - now().timeIntervalSince1970
        let lead = config.auth.sessionRefreshLeadSeconds
        // A session that a refresh just produced with a lifetime within the lead time is not
        // refreshed again (that would loop); it only gets the expiry cutoff.
        let tooShort = remaining <= lead && s.token == justRefreshedToken
        let refresh = config.auth.autoRefreshSession && !skipRefresh && !tooShort
        let sleep = self.sleep
        let token = s.token
        sessionTimer = Task { [weak self] in
            if refresh {
                try? await sleep(remaining - lead)
                guard let self, !Task.isCancelled, self.session?.token == token else { return }
                // Refreshed into another session: that session's timer takes over. Joining a refresh
                // that ended with this very session (or no change) falls through to the cutoff.
                if await self.autoRefresh(sessionKey: sessionKey), self.session?.token != token { return }
            }
            let left = (self?.session.map { $0.expiry } ?? s.expiry) - (self?.now().timeIntervalSince1970 ?? 0)
            try? await sleep(left)
            guard let self, !Task.isCancelled, self.session?.token == token else { return }
            self.expire(sessionKey: sessionKey)
        }
    }

    /// Runs one automatic refresh of `sessionKey`, or joins the one already running for it.
    /// Reports the outcome via `onSessionEvent`. Returns whether the session was refreshed.
    ///
    /// A refresh that was discarded because the session was logged out, replaced or switched while
    /// it ran (`ZeroXKeyError.sessionChanged`, or any failure after the stored session changed)
    /// is not a failed renewal: nothing is reported, the session the user chose is left alone.
    func autoRefresh(sessionKey: String) async -> Bool {
        if let running = autoRefreshTasks[sessionKey] { return await running.value }
        let startToken = try? config.sessionStore.token(sessionKey: sessionKey)
        let task = Task<Bool, Never> { [weak self] in
            guard let self else { return false }
            do {
                try await self.refreshSession(sessionKey: sessionKey)
                if let s = self.session { self.onSessionEvent?(.refreshed(s)) }
                return true
            } catch {
                let superseded = (error as? ZeroXKeyError) == .sessionChanged
                    || (try? self.config.sessionStore.token(sessionKey: sessionKey)) != startToken
                if !superseded { self.onSessionEvent?(.refreshFailed(sessionKey: sessionKey, error: error)) }
                return false
            }
        }
        autoRefreshTasks[sessionKey] = task
        let ok = await task.value
        autoRefreshTasks[sessionKey] = nil
        return ok
    }

    func expire(sessionKey: String) {
        try? clearSession(sessionKey: sessionKey)
        deactivate()
        onSessionEvent?(.expired(sessionKey: sessionKey))
    }

    /// Re-checks the active session after the app was suspended (timers do not run while the
    /// process is suspended). Called automatically on `appForegroundNotification`; call it
    /// yourself if you manage lifecycle differently.
    /// - expired → the session is cleared (`.expired` event);
    /// - less than `sessionRefreshLeadSeconds` left and auto refresh on → refreshed now
    ///   (`.refreshed`, or `.refreshFailed` and the session is cleared at expiry);
    /// - otherwise the timer is re-armed from the current clock.
    public func checkSessionOnForeground() async {
        guard let s = session else { return }
        let key = (try? config.sessionStore.activeSessionKey()).flatMap { $0 } ?? ZeroXKeySessionKey.default
        let remaining = s.expiry - now().timeIntervalSince1970
        if remaining <= 0 {
            expire(sessionKey: key)
        } else if config.auth.autoRefreshSession, remaining < config.auth.sessionRefreshLeadSeconds {
            if !(await autoRefresh(sessionKey: key)), let current = session, current.token == s.token {
                scheduleSessionTimer(for: current, sessionKey: key, skipRefresh: true)
            }
        } else if autoRefreshTasks[key] == nil {
            scheduleSessionTimer(for: s, sessionKey: key)
        }
    }

    func cancelSessionTimer() {
        sessionTimer?.cancel()
        sessionTimer = nil
    }

    /// Alias of `clearSession()` for the active session.
    public func logout() throws {
        let key = try config.sessionStore.activeSessionKey() ?? ZeroXKeySessionKey.default
        try clearSession(sessionKey: key)
    }

    func restoreSession() {
        guard let key = try? config.sessionStore.activeSessionKey(),
              let token = try? config.sessionStore.token(sessionKey: key),
              let parsed = try? verifiedSession(token),
              let stamper = try? config.keyManager.stamper(forPublicKey: parsed.publicKey)
        else {
            authState = .unauthenticated
            return
        }
        activate(parsed, stamper: stamper, sessionKey: key)
    }

    func activate(_ s: ZeroXKeySession, stamper: ApiKeyStamper, sessionKey: String) {
        // Switching to another user/org must not leave the previous user's data published.
        if session?.userId != s.userId || session?.organizationId != s.organizationId {
            user = nil
            wallets = []
        }
        sessionEpoch += 1
        session = s
        activeSessionClient = try? baseClient(stamper: stamper, organizationId: s.organizationId)
        client = activeSessionClient ?? unauthenticatedClient()
        authState = activeSessionClient == nil ? .unauthenticated : .authenticated
        if activeSessionClient != nil { scheduleSessionTimer(for: s, sessionKey: sessionKey) }
    }

    func deactivate() {
        sessionEpoch += 1
        cancelSessionTimer()
        session = nil
        activeSessionClient = nil
        client = unauthenticatedClient()
        user = nil
        wallets = []
        authState = .unauthenticated
    }

    // MARK: - User & wallets

    /// Updates the user's email; `""` removes it. `verificationToken` from an email OTP
    /// marks it verified (sdk-js `updateUserEmail` / `removeUserEmail`). Returns the user ID.
    @discardableResult
    public func updateUserEmail(_ email: String, verificationToken: String? = nil) async throws -> String {
        let (c, s) = try sessionClientAndSession()
        let id = try await c.updateUserEmail(TUpdateUserEmailBody(
            userId: s.userId, userEmail: email, verificationToken: verificationToken)).userId
        _ = try? await refreshUser()
        return id
    }

    /// Updates the user's phone number (E.164); `""` removes it (sdk-js `updateUserPhoneNumber`).
    @discardableResult
    public func updateUserPhoneNumber(_ phoneNumber: String, verificationToken: String? = nil) async throws -> String {
        let (c, s) = try sessionClientAndSession()
        let id = try await c.updateUserPhoneNumber(TUpdateUserPhoneNumberBody(
            userId: s.userId, userPhoneNumber: phoneNumber, verificationToken: verificationToken)).userId
        _ = try? await refreshUser()
        return id
    }

    /// Renames the user (sdk-js `updateUserName`).
    @discardableResult
    public func updateUserName(_ userName: String) async throws -> String {
        let (c, s) = try sessionClientAndSession()
        let id = try await c.updateUserName(TUpdateUserNameBody(userId: s.userId, userName: userName)).userId
        _ = try? await refreshUser()
        return id
    }

    func sessionClientAndSession() throws -> (ZeroXKeyClient, ZeroXKeySession) {
        let c = try sessionClient()
        guard let s = session else { throw ZeroXKeyError.noActiveSession }
        return (c, s)
    }

    /// Fetches the session user (sdk-js `fetchUser`).
    @discardableResult
    public func refreshUser() async throws -> v1User {
        let c = try sessionClient()
        guard let s = session else { throw ZeroXKeyError.noActiveSession }
        guard let u = try await c.getUser(TGetUserBody(userId: s.userId, organizationId: s.organizationId)).user else {
            throw ZeroXKeyError.badResponse("get_user returned no user")
        }
        user = u
        return u
    }

    /// Fetches wallets and their accounts (sdk-js `fetchWallets` / `fetchWalletAccounts`,
    /// accounts paged with `limit: "100"`).
    @discardableResult
    public func refreshWallets() async throws -> [ZeroXKeyWallet] {
        let c = try sessionClient()
        let list = try await c.getWallets().wallets
        // Accounts are fetched concurrently (sdk-js awaits them one by one); order is kept.
        let accounts = try await withThrowingTaskGroup(of: (Int, [v1WalletAccount]).self) { group in
            for (i, w) in list.enumerated() {
                group.addTask {
                    (i, try await c.getWalletAccounts(TGetWalletAccountsBody(
                        walletId: w.walletId, paginationOptions: v1Pagination(limit: "100"))).accounts)
                }
            }
            var byIndex = [Int: [v1WalletAccount]]()
            for try await (i, a) in group { byIndex[i] = a }
            return byIndex
        }
        let out = list.enumerated().map { i, w in
            ZeroXKeyWallet(walletId: w.walletId, walletName: w.walletName, accounts: accounts[i] ?? [],
                           exported: w.exported, imported: w.imported,
                           createdAt: w.createdAt?.seconds ?? "", updatedAt: w.updatedAt?.seconds ?? "")
        }
        wallets = out
        return out
    }

    /// Creates a wallet (sdk-js `createWallet`, core.ts:4993; default ETH + SOL accounts,
    /// mnemonic length 12). Returns the wallet ID and refreshes `wallets`.
    @discardableResult
    public func createWallet(
        walletName: String, accounts: [v1WalletAccountParams] = AddressFormatDefaults.defaultWalletAccounts,
        mnemonicLength: Int32 = 12
    ) async throws -> String {
        let c = try sessionClient()
        let res = try await c.createWallet(TCreateWalletBody(walletName: walletName, accounts: accounts, mnemonicLength: mnemonicLength))
        guard !res.walletId.isEmpty else { throw ZeroXKeyError.badResponse("create_wallet returned no walletId") }
        _ = try? await refreshWallets()
        return res.walletId
    }

    /// Creates a sub-organization under the session's organization (`create_sub_organization`,
    /// `ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8`).
    public func createSubOrganization(_ body: TCreateSubOrganizationBody) async throws -> TCreateSubOrganizationResponse {
        let res = try await sessionClient().createSubOrganization(body)
        guard !res.subOrganizationId.isEmpty else {
            throw ZeroXKeyError.badResponse("create_sub_organization returned no subOrganizationId")
        }
        return res
    }

    // MARK: - Signing

    /// Signs a message with an embedded wallet account (sdk-js `signMessage`, core.ts:3216).
    /// Encoding and hash function default from the address format. For Ethereum the
    /// EIP-191 prefix is added unless `addEthereumPrefix` is `false`.
    public func signMessage(
        signWith: String, addressFormat: v1AddressFormat, message: String,
        encoding: v1PayloadEncoding? = nil, hashFunction: v1HashFunction? = nil, addEthereumPrefix: Bool? = nil
    ) async throws -> SignRawPayloadResult {
        let enc = try encoding ?? AddressFormatDefaults.encoding(for: addressFormat)
        let hash = try hashFunction ?? AddressFormatDefaults.hashFunction(for: addressFormat)
        let payload = Self.encodeMessage(
            message, encoding: enc,
            ethereumPrefix: addressFormat == .ADDRESS_FORMAT_ETHEREUM && (addEthereumPrefix ?? true))
        return try await signRawPayload(signWith: signWith, payload: payload, encoding: enc, hashFunction: hash)
    }

    /// sdk-js `getEncodedMessage` (utils.ts:488-503) plus the EIP-191 prefix of core.ts:3260-3269.
    nonisolated static func encodeMessage(_ message: String, encoding: v1PayloadEncoding, ethereumPrefix: Bool) -> String {
        var bytes = Data(message.utf8)
        if ethereumPrefix {
            bytes = Data("\u{19}Ethereum Signed Message:\n\(bytes.count)".utf8) + bytes
        }
        if encoding == .PAYLOAD_ENCODING_HEXADECIMAL { return "0x" + Hex.encode(bytes) }
        return String(decoding: bytes, as: UTF8.self)
    }

    public func signRawPayload(
        signWith: String, payload: String, encoding: v1PayloadEncoding, hashFunction: v1HashFunction
    ) async throws -> SignRawPayloadResult {
        let res = try await sessionClient().signRawPayload(
            TSignRawPayloadBody(signWith: signWith, payload: payload, encoding: encoding, hashFunction: hashFunction))
        return SignRawPayloadResult(r: res.r, s: res.s, v: res.v)
    }

    /// Signs a transaction; broadcasting is up to the caller (sdk-js `signTransaction`).
    /// `signMessage` for a wallet account.
    public func signMessage(
        signWith account: v1WalletAccount, message: String,
        encoding: v1PayloadEncoding? = nil, hashFunction: v1HashFunction? = nil, addEthereumPrefix: Bool? = nil
    ) async throws -> SignRawPayloadResult {
        try await signMessage(signWith: account.address, addressFormat: account.addressFormat, message: message,
                              encoding: encoding, hashFunction: hashFunction, addEthereumPrefix: addEthereumPrefix)
    }

    /// `signTransaction` for a wallet account.
    public func signTransaction(signWith account: v1WalletAccount, unsignedTransaction: String, type: v1TransactionType) async throws -> String {
        try await signTransaction(signWith: account.address, unsignedTransaction: unsignedTransaction, type: type)
    }

    public func signTransaction(signWith: String, unsignedTransaction: String, type: v1TransactionType) async throws -> String {
        try await sessionClient().signTransaction(
            TSignTransactionBody(signWith: signWith, unsignedTransaction: unsignedTransaction, type: type)).signedTransaction
    }

    // MARK: - Export / import

    /// Exports a wallet and decrypts the mnemonic locally.
    /// A one-time P-256 target key is generated in memory; the bundle signature is checked
    /// against the 0xkey signer enclave key (`dangerouslyOverrideSignerPublicKey`, else
    /// `config.trustAnchors`). The same applies to the other export and import methods.
    /// `returnMnemonic: false` returns the bundle's raw decrypted payload instead of the mnemonic
    /// text.
    public func exportWallet(
        walletId: String, dangerouslyOverrideSignerPublicKey: String? = nil, returnMnemonic: Bool = true
    ) async throws -> String {
        let c = try sessionClient()
        guard let s = session else { throw ZeroXKeyError.noActiveSession }
        let target = makeTargetKeyPair()
        let res = try await c.exportWallet(TExportWalletBody(walletId: walletId, targetPublicKey: target.publicKeyUncompressed))
        return try decryptExportBundle(
            exportBundle: res.exportBundle, organizationId: s.organizationId, embeddedPrivateKey: target.privateKey,
            returnMnemonic: returnMnemonic,
            dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey ?? config.trustAnchors.dangerouslyOverrideSignerPublicKey)
    }

    /// Exports one wallet account's private key and decrypts it locally.
    public func exportWalletAccount(
        address: String, keyFormat: KeyFormat = .hexadecimal, dangerouslyOverrideSignerPublicKey: String? = nil
    ) async throws -> String {
        let c = try sessionClient()
        guard let s = session else { throw ZeroXKeyError.noActiveSession }
        let target = makeTargetKeyPair()
        let res = try await c.exportWalletAccount(TExportWalletAccountBody(address: address, targetPublicKey: target.publicKeyUncompressed))
        return try decryptExportBundle(
            exportBundle: res.exportBundle, organizationId: s.organizationId, embeddedPrivateKey: target.privateKey,
            keyFormat: keyFormat, returnMnemonic: false,
            dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey ?? config.trustAnchors.dangerouslyOverrideSignerPublicKey)
    }

    /// Imports a wallet from a mnemonic (sdk-js `importWallet`, core.ts:5351):
    /// `init_import_wallet` → HPKE-encrypt to the enclave target → `import_wallet`.
    @discardableResult
    public func importWallet(
        walletName: String, mnemonic: String,
        accounts: [v1WalletAccountParams] = AddressFormatDefaults.defaultWalletAccounts,
        dangerouslyOverrideSignerPublicKey: String? = nil
    ) async throws -> String {
        let c = try sessionClient()
        guard let s = session else { throw ZeroXKeyError.noActiveSession }
        let initRes = try await c.initImportWallet(TInitImportWalletBody(userId: s.userId))
        let encrypted = try encryptWalletToBundle(
            mnemonic: mnemonic, importBundle: initRes.importBundle, userId: s.userId, organizationId: s.organizationId,
            dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey ?? config.trustAnchors.dangerouslyOverrideSignerPublicKey)
        let res = try await c.importWallet(
            TImportWalletBody(userId: s.userId, walletName: walletName, encryptedBundle: encrypted, accounts: accounts))
        _ = try? await refreshWallets()
        return res.walletId
    }

    /// Imports a raw private key (sdk-js `importPrivateKey`, core.ts:5440).
    @discardableResult
    public func importPrivateKey(
        privateKey: String, privateKeyName: String, keyFormat: KeyFormat, curve: v1Curve,
        addressFormats: [v1AddressFormat], dangerouslyOverrideSignerPublicKey: String? = nil
    ) async throws -> String {
        let c = try sessionClient()
        guard let s = session else { throw ZeroXKeyError.noActiveSession }
        let initRes = try await c.initImportPrivateKey(TInitImportPrivateKeyBody(userId: s.userId))
        let encrypted = try encryptPrivateKeyToBundle(
            privateKey: privateKey, keyFormat: keyFormat, importBundle: initRes.importBundle, userId: s.userId,
            organizationId: s.organizationId,
            dangerouslyOverrideSignerPublicKey: dangerouslyOverrideSignerPublicKey ?? config.trustAnchors.dangerouslyOverrideSignerPublicKey)
        return try await c.importPrivateKey(
            TImportPrivateKeyBody(userId: s.userId, privateKeyName: privateKeyName, encryptedBundle: encrypted,
                                  curve: curve, addressFormats: addressFormats)).privateKeyId
    }
}

/// Owns a block-based NotificationCenter observer and removes it on deinit.
final class NotificationObservation: @unchecked Sendable {
    private let center: NotificationCenter
    private let token: any NSObjectProtocol
    init(center: NotificationCenter, token: any NSObjectProtocol) {
        self.center = center
        self.token = token
    }
    deinit { center.removeObserver(token) }
}
