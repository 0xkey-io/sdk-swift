import Foundation
import ZeroXKeyStamper

/// Body of a `/public/v1/query/*` request. Encoded flat; a `nil` `organizationId`
/// is filled from the client's default (sdk-js `request()` semantics).
public protocol ZeroXKeyQueryBody: Encodable, Sendable {
    var organizationId: String? { get set }
}

/// Body of a `/public/v1/submit/*` activity. Its `Encodable` conformance encodes only the
/// intent fields; the client wraps them as
/// `{"parameters":…, "organizationId":…, "timestampMs":…, "type":…}`
/// (`activity()` in sdk-js `packages/core/src/__generated__/sdk-client-base.ts`).
public protocol ZeroXKeyActivityBody: Encodable, Sendable {
    var organizationId: String? { get }
    var timestampMs: String? { get }
}

/// Body of an Auth Proxy request (`authProxyRequest` in sdk-client-base.ts).
public protocol ZeroXKeyProxyBody: Encodable, Sendable {}

/// A stamped request that has not been sent (sdk-js `TSignedRequest`).
/// `body` is exactly the string the stamp was computed over.
public struct SignedRequest: Sendable, Equatable {
    public let url: URL
    public let body: String
    public let stamp: Stamp

    public init(url: URL, body: String, stamp: Stamp) {
        self.url = url
        self.body = body
        self.stamp = stamp
    }
}

/// 64-bit integer that decodes from a JSON number or a JSON string (protojson encodes
/// int64 as a string) and encodes as a number.
public struct ZeroXKeyInt64: Codable, Sendable, Hashable, ExpressibleByIntegerLiteral, CustomStringConvertible {
    public var value: Int64

    public init(_ value: Int64) { self.value = value }
    public init(integerLiteral value: Int64) { self.value = value }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let v = try? c.decode(Int64.self) {
            value = v
        } else if let s = try? c.decode(String.self), let v = Int64(s) {
            value = v
        } else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "expected int64 as number or string")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(value)
    }

    public var description: String { String(value) }
}
