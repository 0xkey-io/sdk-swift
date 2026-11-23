import Foundation

/// A request stamp: the HTTP header to attach to a signed 0xkey API request.
/// Field names follow sdk-js `createStampResult`
/// (sdk-js `packages/api-key-stamper/src/_kernel/stamping.ts`).
public struct Stamp: Sendable, Equatable {
    public let stampHeaderName: String
    public let stampHeaderValue: String

    public init(stampHeaderName: String, stampHeaderValue: String) {
        self.stampHeaderName = stampHeaderName
        self.stampHeaderValue = stampHeaderValue
    }
}

/// Anything that can stamp a request body. The payload is the exact JSON body string
/// that will be sent; the server verifies the stamp over those bytes.
public protocol Stamper: Sendable {
    func stamp(payload: String) async throws -> Stamp
}

/// Header names (sdk-js `STAMP_HEADER_API_KEY` / `STAMP_HEADER_WEBAUTHN`).
public enum StampHeader {
    public static let apiKey = "X-Stamp"
    public static let webAuthn = "X-Stamp-Webauthn"
    /// sdk-js `packages/attested-stamper/src/attested-stamper.ts:25`.
    public static let attested = "X-Stamp-Attested"
}

public enum ZeroXKeyStamperError: Error, Equatable, Sendable {
    case publicKeyMismatch(expected: String, derived: String)
    case invalidPrivateKey
    case authenticatorFailed(String)
}
