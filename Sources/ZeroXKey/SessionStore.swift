import Foundation

/// Persists session JWTs by session key and remembers the active one
/// (sdk-js `StorageBase`: `storeSession`, `getSession`, `getActiveSessionKey`, `clearSession`).
public protocol ZeroXKeySessionStore: Sendable {
    func store(token: String, sessionKey: String) throws
    func token(sessionKey: String) throws -> String?
    func remove(sessionKey: String) throws
    func allSessionKeys() throws -> [String]
    func activeSessionKey() throws -> String?
    func setActiveSessionKey(_ key: String?) throws
}

public enum ZeroXKeySessionKey {
    /// sdk-js `SessionKey.DefaultSessionkey` (sdk-js `packages/core/src/__types__/enums.ts:12-14`).
    public static let `default` = "@0xkey-io/session/v3"
}

public final class InMemorySessionStore: ZeroXKeySessionStore, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: [String: String] = [:]
    private var active: String?

    public init() {}

    public func store(token: String, sessionKey: String) throws { lock.withLock { tokens[sessionKey] = token } }
    public func token(sessionKey: String) throws -> String? { lock.withLock { tokens[sessionKey] } }
    public func remove(sessionKey: String) throws {
        lock.withLock {
            tokens[sessionKey] = nil
            if active == sessionKey { active = nil }
        }
    }
    public func allSessionKeys() throws -> [String] { lock.withLock { tokens.keys.sorted() } }
    public func activeSessionKey() throws -> String? { lock.withLock { active } }
    public func setActiveSessionKey(_ key: String?) throws { lock.withLock { active = key } }
}

/// Keychain-backed session storage. The active key is stored as the reserved account
/// `__active__`.
public struct KeychainSessionStore: ZeroXKeySessionStore {
    static let activeAccount = "__active__"
    public let service: String
    public let accessGroup: String?

    public init(service: String = "io.0xkey.sdk.sessions", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func store(token: String, sessionKey: String) throws {
        try Keychain.set(Data(token.utf8), service: service, account: sessionKey, accessGroup: accessGroup)
    }
    public func token(sessionKey: String) throws -> String? {
        try Keychain.get(service: service, account: sessionKey, accessGroup: accessGroup).map { String(decoding: $0, as: UTF8.self) }
    }
    public func remove(sessionKey: String) throws {
        try Keychain.delete(service: service, account: sessionKey, accessGroup: accessGroup)
        if try activeSessionKey() == sessionKey { try setActiveSessionKey(nil) }
    }
    public func allSessionKeys() throws -> [String] {
        try Keychain.accounts(service: service, accessGroup: accessGroup).filter { $0 != Self.activeAccount }
    }
    public func activeSessionKey() throws -> String? {
        try Keychain.get(service: service, account: Self.activeAccount, accessGroup: accessGroup).map { String(decoding: $0, as: UTF8.self) }
    }
    public func setActiveSessionKey(_ key: String?) throws {
        if let key {
            try Keychain.set(Data(key.utf8), service: service, account: Self.activeAccount, accessGroup: accessGroup)
        } else {
            try Keychain.delete(service: service, account: Self.activeAccount, accessGroup: accessGroup)
        }
    }
}
