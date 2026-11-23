import Foundation
import ZeroXKeyStamper

/// Activity polling settings (sdk-js `activityPoller`, defaults 1000 ms × 3).
public struct ActivityPollerConfig: Sendable, Equatable {
    public var intervalMs: Int
    public var numRetries: Int

    public init(intervalMs: Int = 1000, numRetries: Int = 3) {
        self.intervalMs = intervalMs
        self.numRetries = numRetries
    }
}

/// HTTP client for the 0xkey public API and Auth Proxy.
///
/// Request semantics follow `ZeroXKeySDKClientBase` in
/// sdk-js `packages/core/src/__generated__/sdk-client-base.ts`:
/// - every call is a JSON `POST`; the body string is serialized **once**, stamped, and the
///   same bytes are sent;
/// - headers `Content-Type: application/json`, `X-Client-Version`, plus the stamp header;
/// - activities are polled with `get_activity` until a terminal status
///   (`TERMINAL_ACTIVITY_STATUSES`), then the result is flattened.
///
/// Endpoint methods (`getWhoami`, `signRawPayload`, …) are generated into
/// `Sources/ZeroXKeyHttp/Generated` from 0xkey's swagger.
public struct ZeroXKeyClient: Sendable {
    public static let defaultApiBaseURL = URL(string: "https://api.0xkey.io")!
    public static let defaultAuthProxyBaseURL = URL(string: "https://authproxy.0xkey.io")!
    /// `X-Client-Version` value, `0xkey-swift/<version>` (sdk-js sends `@0xkey-io/core@<version>`).
    /// Never carries an upstream SDK prefix, which the server uses to detect upstream SDKs.
    public static let clientVersion = "0xkey-swift/\(ZeroXKeySDKVersion.current)"

    public let apiBaseURL: URL
    public let stamper: (any Stamper)?
    public let organizationId: String?
    public let authProxyBaseURL: URL
    public let authProxyConfigId: String?
    public let activityPoller: ActivityPollerConfig
    public let urlSession: URLSession
    /// URLs this client sends requests to; checked before every request
    /// (``ZeroXKeyHttpError/insecureURL(_:)``). `.requireHTTPS` unless given to the initializer.
    public let transportSecurity: ZeroXKeyTransportSecurity
    let now: @Sendable () -> Date

    public init(
        apiBaseURL: URL = ZeroXKeyClient.defaultApiBaseURL,
        stamper: (any Stamper)? = nil,
        organizationId: String? = nil,
        authProxyBaseURL: URL = ZeroXKeyClient.defaultAuthProxyBaseURL,
        authProxyConfigId: String? = nil,
        activityPoller: ActivityPollerConfig = .init(),
        urlSession: URLSession = .shared
    ) {
        self.init(apiBaseURL: apiBaseURL, stamper: stamper, organizationId: organizationId,
                  authProxyBaseURL: authProxyBaseURL, authProxyConfigId: authProxyConfigId,
                  activityPoller: activityPoller, urlSession: urlSession, now: { Date() })
    }

    /// - Parameter transportSecurity: `.requireHTTPS` (what the other initializers use), or
    ///   `.dangerouslyAllowInsecureLoopback` for a server on the development machine.
    public init(
        apiBaseURL: URL = ZeroXKeyClient.defaultApiBaseURL,
        stamper: (any Stamper)? = nil,
        organizationId: String? = nil,
        authProxyBaseURL: URL = ZeroXKeyClient.defaultAuthProxyBaseURL,
        authProxyConfigId: String? = nil,
        activityPoller: ActivityPollerConfig = .init(),
        urlSession: URLSession = .shared,
        transportSecurity: ZeroXKeyTransportSecurity
    ) {
        self.init(apiBaseURL: apiBaseURL, stamper: stamper, organizationId: organizationId,
                  authProxyBaseURL: authProxyBaseURL, authProxyConfigId: authProxyConfigId,
                  activityPoller: activityPoller, urlSession: urlSession, now: { Date() },
                  transportSecurity: transportSecurity)
    }

    package init(
        apiBaseURL: URL, stamper: (any Stamper)?, organizationId: String?, authProxyBaseURL: URL,
        authProxyConfigId: String?, activityPoller: ActivityPollerConfig, urlSession: URLSession,
        now: @escaping @Sendable () -> Date, transportSecurity: ZeroXKeyTransportSecurity = .requireHTTPS
    ) {
        self.transportSecurity = transportSecurity
        self.apiBaseURL = apiBaseURL
        self.stamper = stamper
        self.organizationId = organizationId
        self.authProxyBaseURL = authProxyBaseURL
        self.authProxyConfigId = authProxyConfigId
        self.activityPoller = activityPoller
        self.urlSession = urlSession
        self.now = now
    }

    /// Convenience: a client that stamps every request with `stamper`.
    public init(stamper: any Stamper) {
        self.init(stamper: stamper, organizationId: nil)
    }

    /// Copy with a different stamper (e.g. a passkey or attested stamper for one call).
    public func with(stamper: (any Stamper)?) -> ZeroXKeyClient {
        ZeroXKeyClient(apiBaseURL: apiBaseURL, stamper: stamper, organizationId: organizationId,
                       authProxyBaseURL: authProxyBaseURL, authProxyConfigId: authProxyConfigId,
                       activityPoller: activityPoller, urlSession: urlSession, now: now,
                       transportSecurity: transportSecurity)
    }

    /// Copy with a different default organization.
    public func with(organizationId: String?) -> ZeroXKeyClient {
        ZeroXKeyClient(apiBaseURL: apiBaseURL, stamper: stamper, organizationId: organizationId,
                       authProxyBaseURL: authProxyBaseURL, authProxyConfigId: authProxyConfigId,
                       activityPoller: activityPoller, urlSession: urlSession, now: now,
                       transportSecurity: transportSecurity)
    }

    // MARK: - Encoding

    static func encode<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }

    static func decode<R: Decodable>(_ type: R.Type, from data: Data) throws -> R {
        do {
            return try JSONDecoder().decode(R.self, from: data)
        } catch {
            throw ZeroXKeyHttpError.decodingFailed(type: String(describing: R.self), message: "\(error)")
        }
    }

    func url(base: URL, path: String) throws -> URL {
        var s = base.absoluteString
        while s.hasSuffix("/") { s.removeLast() }
        guard let url = URL(string: s + path) else { throw ZeroXKeyHttpError.invalidURL(s + path) }
        return url
    }

    var timestampMs: String { String(Int64((now().timeIntervalSince1970 * 1000).rounded(.down))) }

    // MARK: - Signing

    /// Serializes `body`, stamps it with `stamper` (if any) and returns the request unsent.
    func sign<B: Encodable>(path: String, body: B) async throws -> SignedRequest {
        let url = try url(base: apiBaseURL, path: path)
        let json = try Self.encode(body)
        guard let stamper else {
            return SignedRequest(url: url, body: json, stamp: Stamp(stampHeaderName: "", stampHeaderValue: ""))
        }
        return SignedRequest(url: url, body: json, stamp: try await stamper.stamp(payload: json))
    }

    // MARK: - Transport

    func post(url: URL, body: String, headers: [String: String]) async throws -> Data {
        try transportSecurity.validate(url)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = Data(body.utf8)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ZeroXKeyHttpError.notHTTPResponse }
        guard (200..<300).contains(http.statusCode) else {
            throw ZeroXKeyRequestError.parse(
                httpStatus: http.statusCode, body: data, retryAfter: http.value(forHTTPHeaderField: "Retry-After"))
        }
        return data
    }

    /// Sends a pre-signed request (sdk-js `sendSignedRequest`) and returns the raw body.
    public func send(_ signed: SignedRequest) async throws -> Data {
        var headers = ["X-Client-Version": Self.clientVersion]
        if !signed.stamp.stampHeaderName.isEmpty {
            headers[signed.stamp.stampHeaderName] = signed.stamp.stampHeaderValue
        }
        return try await post(url: signed.url, body: signed.body, headers: headers)
    }

    // MARK: - Query

    public func query<B: ZeroXKeyQueryBody, R: Decodable & Sendable>(_ path: String, body: B, as: R.Type) async throws -> R {
        try Self.decode(R.self, from: await send(stampQuery(path, body: body)))
    }

    public func stampQuery<B: ZeroXKeyQueryBody>(_ path: String, body: B) async throws -> SignedRequest {
        var b = body
        if b.organizationId == nil { b.organizationId = organizationId }
        return try await sign(path: path, body: b)
    }

    // MARK: - Activity

    struct ActivityEnvelope<P: Encodable>: Encodable {
        let parameters: P
        let organizationId: String?
        let timestampMs: String
        let type: String
    }

    public func stampActivity<B: ZeroXKeyActivityBody>(_ path: String, type: String, body: B) async throws -> SignedRequest {
        let envelope = ActivityEnvelope(
            parameters: body, organizationId: body.organizationId ?? organizationId,
            timestampMs: body.timestampMs ?? timestampMs, type: type)
        return try await sign(path: path, body: envelope)
    }

    public func activity<B: ZeroXKeyActivityBody, R: Decodable & Sendable>(
        _ path: String, type: String, body: B, resultKey: String, as: R.Type
    ) async throws -> R {
        let data = try await send(stampActivity(path, type: type, body: body))
        let (activity, polls) = try await settle(try Self.activityObject(data))
        do {
            return try Self.flatten(activity: activity, resultKey: resultKey, polls: polls, as: R.self)
        } catch ZeroXKeyActivityError.authenticatorsNeeded(let id, _) {
            // Report which MFA policies are open. A request the
            // server refuses (HTTP error) leaves the list empty; a response that cannot be decoded
            // is thrown, so an empty list never hides a decoding problem.
            let statuses: [v1MfaStatus]
            do {
                statuses = try await getMfaStatus(TGetMfaStatusBody(
                    activityId: id, organizationId: activity["organizationId"] as? String)).mfaStatuses
            } catch is ZeroXKeyRequestError {
                statuses = []
            }
            throw ZeroXKeyActivityError.authenticatorsNeeded(activityId: id, mfaStatuses: statuses)
        }
    }

    /// `approveActivity` / `rejectActivity`: no polling; result fields are flattened.
    public func activityDecision<B: ZeroXKeyActivityBody, R: Decodable & Sendable>(
        _ path: String, type: String, body: B, as: R.Type
    ) async throws -> R {
        let data = try await send(stampActivity(path, type: type, body: body))
        let activity = try Self.activityObject(data)
        var merged = (activity["result"] as? [String: Any]) ?? [:]
        merged["activity"] = activity
        return try Self.decode(R.self, from: JSONSerialization.data(withJSONObject: merged))
    }

    /// sdk-js `TERMINAL_ACTIVITY_STATUSES` (sdk-js `packages/core/src/__types__/http.ts:21-26`).
    public static let terminalActivityStatuses: Set<String> = [
        "ACTIVITY_STATUS_COMPLETED", "ACTIVITY_STATUS_FAILED",
        "ACTIVITY_STATUS_REJECTED", "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED",
    ]

    static func activityObject(_ data: Data) throws -> [String: Any] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let activity = obj["activity"] as? [String: Any] else {
            throw ZeroXKeyHttpError.decodingFailed(type: "v1ActivityResponse", message: "missing \"activity\"")
        }
        return activity
    }

    /// Polls `get_activity` while the status is not terminal, up to `numRetries` times.
    func settle(_ initial: [String: Any]) async throws -> ([String: Any], Int) {
        var activity = initial
        var attempts = 0
        while !Self.terminalActivityStatuses.contains(activity["status"] as? String ?? ""),
              attempts < activityPoller.numRetries {
            if activityPoller.intervalMs > 0 {
                try await Task.sleep(nanoseconds: UInt64(activityPoller.intervalMs) * 1_000_000)
            }
            attempts += 1
            let poll = PollBody(activityId: activity["id"] as? String ?? "",
                                organizationId: activity["organizationId"] as? String)
            activity = try Self.activityObject(try await send(stampQuery("/public/v1/query/get_activity", body: poll)))
        }
        return (activity, attempts)
    }

    struct PollBody: ZeroXKeyQueryBody {
        let activityId: String
        var organizationId: String?
    }

    /// Maps a settled activity to a result or a named error. sdk-js returns non-completed
    /// activities as-is; here every non-`COMPLETED` status becomes a `ZeroXKeyActivityError`.
    static func flatten<R: Decodable>(activity: [String: Any], resultKey: String, polls: Int, as: R.Type) throws -> R {
        let id = activity["id"] as? String ?? ""
        let status = activity["status"] as? String ?? ""
        switch status {
        case "ACTIVITY_STATUS_COMPLETED":
            break
        case "ACTIVITY_STATUS_FAILED":
            let failure = (activity["failure"]).flatMap { try? JSONSerialization.data(withJSONObject: $0, options: .fragmentsAllowed) }
                .flatMap { try? JSONDecoder().decode(JSONValue.self, from: $0) }
            throw ZeroXKeyActivityError.failed(activityId: id, status: status, failure: failure)
        case "ACTIVITY_STATUS_REJECTED":
            throw ZeroXKeyActivityError.rejected(activityId: id)
        case "ACTIVITY_STATUS_CONSENSUS_NEEDED":
            throw ZeroXKeyActivityError.consensusNeeded(activityId: id, fingerprint: activity["fingerprint"] as? String)
        case "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED":
            throw ZeroXKeyActivityError.authenticatorsNeeded(activityId: id, mfaStatuses: [])
        default:
            throw ZeroXKeyActivityError.pollingTimedOut(activityId: id, status: status, attempts: polls)
        }
        guard let result = activity["result"] as? [String: Any] else {
            throw ZeroXKeyActivityError.missingResult(activityId: id, resultKey: resultKey)
        }
        // sdk-js handleActivityResponse: the requested key first, then any `…Result(Vn)` key.
        var fields: [String: Any]? = result[resultKey] as? [String: Any]
        if fields == nil {
            for key in result.keys.sorted() where key.range(of: #"Result(V\d+)?$"#, options: .regularExpression) != nil {
                if let f = result[key] as? [String: Any] { fields = f; break }
            }
        }
        guard var merged = fields else {
            throw ZeroXKeyActivityError.missingResult(activityId: id, resultKey: resultKey)
        }
        merged["activity"] = activity
        return try decode(R.self, from: JSONSerialization.data(withJSONObject: merged))
    }

    // MARK: - Auth Proxy

    /// Auth Proxy routes that accept `X-Captcha-Token` (sdk-client-base.ts `authProxyRequest`).
    public static let captchaProtectedAuthProxyPaths: Set<String> = [
        "/v1/otp_init", "/v1/otp_init_v2", "/v1/signup", "/v1/signup_v2",
    ]

    public func authProxy<B: ZeroXKeyProxyBody, R: Decodable & Sendable>(
        _ path: String, body: B, captchaToken: String?, as: R.Type
    ) async throws -> R {
        guard let configId = authProxyConfigId, !configId.isEmpty else {
            throw ZeroXKeyHttpError.missingAuthProxyConfiguration
        }
        var url = try url(base: authProxyBaseURL, path: path)
        var headers = ["X-Auth-Proxy-Config-ID": configId]
        if let captchaToken {
            guard Self.captchaProtectedAuthProxyPaths.contains(path) else {
                throw ZeroXKeyHttpError.captchaNotSupported(path: path)
            }
            headers["X-Captcha-Token"] = captchaToken
            var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            components?.queryItems = [URLQueryItem(name: "captcha_config_id", value: configId)]
            guard let withQuery = components?.url else { throw ZeroXKeyHttpError.invalidURL(url.absoluteString) }
            url = withQuery
        }
        let data = try await post(url: url, body: try Self.encode(body), headers: headers)
        return try Self.decode(R.self, from: data)
    }
}

public enum ZeroXKeySDKVersion {
    public static let current = "0.1.0"
}
