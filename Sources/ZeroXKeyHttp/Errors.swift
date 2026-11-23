import Foundation

/// Error returned by the 0xkey API or Auth Proxy with a non-2xx status.
///
/// Two body shapes are handled:
/// 1. gRPC status JSON `{"code":16,"message":"…","details":[…]}` (sdk-js `ZeroXKeyRequestError`,
///    sdk-js `packages/core/src/__types__/error.ts`; planned gateway shape with `ErrorInfo` details).
/// 2. Plain text, e.g. today's api-gateway 401 `Unauthorized: RP ID hash mismatch`
///    written with `http.Error` (services `go/cmd/api-gateway/main.go:287-381`).
///    sdk-js turns those into a `ZeroXKeyHttpError` (sdk-js `packages/core/src/__clients__/response-error.ts:19-27`);
///    here they become a structured error with `kind == .plainText` (or `.empty` for an empty body)
///    and a gRPC code derived from the HTTP status. Only a body that is not JSON at all is
///    `ZeroXKeyHttpError` in sdk-js: JSON without `code` / `message` is `kind == .plainText` here but
///    still a `ZeroXKeyRequestError` there, which is why `ZeroXKeyContext.isAttestedLoginUnavailable`
///    looks at `rawBody` for those kinds.
public struct ZeroXKeyRequestError: Error, Sendable, Equatable, CustomStringConvertible {
    public enum Kind: Sendable, Equatable {
        case grpcStatus
        case plainText
        case empty
    }

    /// Stable failure reasons the gateway may report (0xkey WebAuthn RP design, `ErrorInfo.reason`).
    public enum Reason: Sendable, Equatable {
        /// `google.rpc.ErrorInfo.reason == "WEBAUTHN_RP_ID_NOT_ALLOWED"` (allowlist policy),
        /// or today's plain-text `RP ID hash mismatch`.
        case webAuthnRpIdNotAllowed
        /// `WEBAUTHN_ORIGIN_NOT_ALLOWED`.
        case webAuthnOriginNotAllowed
        /// Any other `ErrorInfo.reason`.
        case other(String)
    }

    public let httpStatus: Int
    public let kind: Kind
    /// gRPC code from the body, or derived from `httpStatus` for plain-text bodies.
    public let code: Int
    public let message: String
    public let details: [JSONValue]
    public let retryAfter: String?
    public let rawBody: String

    public init(httpStatus: Int, kind: Kind, code: Int, message: String, details: [JSONValue], retryAfter: String?, rawBody: String) {
        self.httpStatus = httpStatus
        self.kind = kind
        self.code = code
        self.message = message
        self.details = details
        self.retryAfter = retryAfter
        self.rawBody = rawBody
    }

    /// Parses an error response body.
    public static func parse(httpStatus: Int, body: Data, retryAfter: String? = nil) -> ZeroXKeyRequestError {
        let raw = String(decoding: body, as: UTF8.self)
        if let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
           obj["code"] != nil || obj["message"] != nil {
            let code = (obj["code"] as? NSNumber)?.intValue ?? grpcCode(forHTTPStatus: httpStatus)
            let message = obj["message"] as? String ?? ""
            var details: [JSONValue] = []
            if let d = obj["details"], let data = try? JSONSerialization.data(withJSONObject: d),
               let parsed = try? JSONDecoder().decode([JSONValue].self, from: data) {
                details = parsed
            }
            return ZeroXKeyRequestError(httpStatus: httpStatus, kind: .grpcStatus, code: code, message: message,
                                        details: details, retryAfter: retryAfter, rawBody: raw)
        }
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return ZeroXKeyRequestError(
            httpStatus: httpStatus, kind: text.isEmpty ? .empty : .plainText, code: grpcCode(forHTTPStatus: httpStatus),
            message: text.isEmpty ? HTTPURLResponse.localizedString(forStatusCode: httpStatus) : text,
            details: [], retryAfter: retryAfter, rawBody: raw)
    }

    /// `google.rpc.ErrorInfo.reason` values found in `details`.
    public var errorInfoReasons: [String] {
        details.compactMap { d in
            guard let type = d["@type"]?.stringValue, type.hasSuffix("google.rpc.ErrorInfo") else { return nil }
            return d["reason"]?.stringValue
        }
    }

    /// Named reason, if any.
    public var reason: Reason? {
        if let r = errorInfoReasons.first {
            switch r {
            case "WEBAUTHN_RP_ID_NOT_ALLOWED": return .webAuthnRpIdNotAllowed
            case "WEBAUTHN_ORIGIN_NOT_ALLOWED": return .webAuthnOriginNotAllowed
            default: return .other(r)
            }
        }
        if kind == .plainText, message.localizedCaseInsensitiveContains("RP ID hash mismatch") {
            return .webAuthnRpIdNotAllowed
        }
        return nil
    }

    /// True for HTTP 401 or gRPC `UNAUTHENTICATED` (16).
    public var isUnauthenticated: Bool { httpStatus == 401 || code == 16 }

    public var description: String {
        var s = "0xkey error \(code) (HTTP \(httpStatus)): \(message)"
        if !details.isEmpty, let data = try? JSONEncoder().encode(details) {
            s += " (Details: \(String(decoding: data, as: UTF8.self)))"
        }
        return s
    }

    /// HTTP → gRPC code mapping (grpc-gateway convention, reversed).
    public static func grpcCode(forHTTPStatus status: Int) -> Int {
        switch status {
        case 400: return 3   // INVALID_ARGUMENT
        case 401: return 16  // UNAUTHENTICATED
        case 403: return 7   // PERMISSION_DENIED
        case 404: return 5   // NOT_FOUND
        case 409: return 6   // ALREADY_EXISTS
        case 412: return 9   // FAILED_PRECONDITION
        case 413: return 11  // OUT_OF_RANGE
        case 429: return 8   // RESOURCE_EXHAUSTED
        case 499: return 1   // CANCELLED
        case 501: return 12  // UNIMPLEMENTED
        case 503: return 14  // UNAVAILABLE
        case 504: return 4   // DEADLINE_EXCEEDED
        case 500...599: return 13  // INTERNAL
        default: return 2    // UNKNOWN
        }
    }
}

/// An activity that did not reach `ACTIVITY_STATUS_COMPLETED` with a result.
public enum ZeroXKeyActivityError: Error, Sendable, Equatable {
    case failed(activityId: String, status: String, failure: JSONValue?)
    case rejected(activityId: String)
    case consensusNeeded(activityId: String, fingerprint: String?)
    /// MFA is required. `mfaStatuses` comes from a best-effort `get_mfa_status` call (empty if
    /// that call failed); approve with a second factor, then poll / resubmit.
    case authenticatorsNeeded(activityId: String, mfaStatuses: [v1MfaStatus])
    /// Still `CREATED`/`PENDING` after `ActivityPollerConfig.numRetries` polls.
    case pollingTimedOut(activityId: String, status: String, attempts: Int)
    case missingResult(activityId: String, resultKey: String)
}

/// Transport / decoding problems.
public enum ZeroXKeyHttpError: Error, Sendable, Equatable {
    case invalidURL(String)
    case notHTTPResponse
    case decodingFailed(type: String, message: String)
    case missingAuthProxyConfiguration
    case captchaNotSupported(path: String)
    /// The URL is not allowed by the ``ZeroXKeyTransportSecurity`` in effect (not `https`, or `http`
    /// to a host that is not loopback). Nothing was sent. Carries the URL without credentials.
    case insecureURL(String)
}
