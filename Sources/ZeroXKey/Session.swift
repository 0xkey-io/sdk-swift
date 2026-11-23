import Foundation
import ZeroXKeyCrypto
import ZeroXKeyEncoding

/// A 0xkey session decoded from its JWT (sdk-js `parseSession`,
/// sdk-js `packages/core/src/utils.ts:429-466`).
public struct ZeroXKeySession: Sendable, Equatable, Codable {
    public let sessionType: String
    public let userId: String
    public let organizationId: String
    /// `exp` claim, seconds since epoch.
    public let expiry: TimeInterval
    /// Compressed public key of the session API key.
    public let publicKey: String
    public let token: String
    /// `session_profile_id` claim of scoped sessions; kept across `refreshSession`.
    public let sessionProfileId: String?
    /// `scope` claim of scoped sessions (the session profile's scope), if present.
    public let scope: String?

    public init(sessionType: String, userId: String, organizationId: String, expiry: TimeInterval, publicKey: String,
                token: String, sessionProfileId: String? = nil, scope: String? = nil) {
        self.sessionProfileId = sessionProfileId
        self.scope = scope
        self.sessionType = sessionType
        self.userId = userId
        self.organizationId = organizationId
        self.expiry = expiry
        self.publicKey = publicKey
        self.token = token
    }

    /// Decodes the JWT payload without verifying the signature or the expiry (same as sdk-js).
    /// Use ``verified(jwt:dangerouslyOverrideNotarizerPublicKey:at:)`` for a JWT you are about to rely
    /// on; `ZeroXKeyContext` does that before it stores or activates a session.
    public static func parse(jwt: String) throws -> ZeroXKeySession {
        let claims = try JWTPayload.decode(jwt)
        guard let exp = (claims["exp"] as? NSNumber)?.doubleValue,
              let publicKey = claims["public_key"] as? String, !publicKey.isEmpty,
              let sessionType = claims["session_type"] as? String, !sessionType.isEmpty,
              let userId = claims["user_id"] as? String, !userId.isEmpty,
              let organizationId = claims["organization_id"] as? String, !organizationId.isEmpty
        else { throw ZeroXKeyError.invalidSessionToken("JWT payload missing required fields") }
        return ZeroXKeySession(sessionType: sessionType, userId: userId, organizationId: organizationId,
                               expiry: exp, publicKey: publicKey, token: jwt,
                               sessionProfileId: (claims["session_profile_id"] as? String).flatMap { $0.isEmpty ? nil : $0 },
                               scope: (claims["scope"] as? String).flatMap { $0.isEmpty ? nil : $0 })
    }

    /// Decodes `jwt` and checks it: the signature must be the 0xkey notarizer's (ECDSA P-256 over
    /// SHA-256(SHA-256(`header.payload`)), 64-byte `r||s`) and the session must not be expired at `date`.
    ///
    /// - Parameters:
    ///   - dangerouslyOverrideNotarizerPublicKey: uncompressed P-256 key (hex) of a non-production
    ///     notarizer instead of ``ZeroXKeyTrustAnchors/productionNotarizerSignPublicKey``. The
    ///     signature is checked either way.
    ///   - date: the current time (injectable for tests).
    /// - Throws: ``ZeroXKeyError/invalidSessionToken(_:)`` for a JWT that does not decode,
    ///   ``ZeroXKeyError/sessionJwtSignatureInvalid`` for a missing, malformed or wrong signature,
    ///   ``ZeroXKeyError/sessionExpired`` when `exp` is not after `date`, and
    ///   ``ZeroXKeyCryptoError/invalidPublicKey`` when the override is not a P-256 key.
    public static func verified(
        jwt: String, dangerouslyOverrideNotarizerPublicKey: String? = nil, at date: Date = Date()
    ) throws -> ZeroXKeySession {
        let session = try parse(jwt: jwt)
        let valid: Bool
        do {
            valid = try verifySessionJwtSignature(jwt, dangerouslyOverrideNotarizerPublicKey: dangerouslyOverrideNotarizerPublicKey)
        } catch ZeroXKeyCryptoError.invalidPublicKey {
            throw ZeroXKeyCryptoError.invalidPublicKey
        } catch {
            throw ZeroXKeyError.sessionJwtSignatureInvalid
        }
        guard valid else { throw ZeroXKeyError.sessionJwtSignatureInvalid }
        if session.isExpired(at: date) { throw ZeroXKeyError.sessionExpired }
        return session
    }

    public func isExpired(at date: Date = Date()) -> Bool { date.timeIntervalSince1970 >= expiry }

    /// Seconds until expiry (sdk-js `expirationSeconds`, `ceil`).
    public func expirationSeconds(at date: Date = Date()) -> Int {
        Int((expiry - date.timeIntervalSince1970).rounded(.up))
    }

    /// Verifies the JWT signature against the 0xkey notarizer key (or an override).
    public func verifySignature(dangerouslyOverrideNotarizerPublicKey: String? = nil) throws -> Bool {
        try verifySessionJwtSignature(token, dangerouslyOverrideNotarizerPublicKey: dangerouslyOverrideNotarizerPublicKey)
    }
}

/// Verification token claims used by the OTP flows (sdk-js `decodeVerificationToken`,
/// utils.ts:1499-1509).
public struct VerificationTokenClaims: Sendable, Equatable {
    public let id: String
    public let publicKey: String?
    public let contact: String?
    public let verificationType: String?

    public static func decode(_ token: String) throws -> VerificationTokenClaims {
        let claims = try JWTPayload.decode(token)
        guard let id = claims["id"] as? String else {
            throw ZeroXKeyError.invalidVerificationToken("missing id")
        }
        return VerificationTokenClaims(
            id: id, publicKey: claims["public_key"] as? String,
            contact: claims["contact"] as? String, verificationType: claims["verification_type"] as? String)
    }
}

enum JWTPayload {
    static func decode(_ jwt: String) throws -> [String: Any] {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2, !parts[1].isEmpty else { throw ZeroXKeyError.invalidSessionToken("missing payload") }
        // Accept both base64url and padded/standard base64 like `atob` after replacement.
        var s = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s = s.trimmingCharacters(in: CharacterSet(charactersIn: "="))
        while s.count % 4 != 0 { s += "=" }
        guard let data = Data(base64Encoded: s),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ZeroXKeyError.invalidSessionToken("payload is not base64 JSON")
        }
        return obj
    }
}

/// Automatic session lifecycle events (see `ZeroXKeyContext.onSessionEvent`).
public enum ZeroXKeySessionEvent: Sendable {
    /// The session was refreshed automatically; carries the new session.
    case refreshed(ZeroXKeySession)
    /// An automatic refresh failed. The current session stays valid until it expires. Not sent for a
    /// refresh that a logout or session switch made obsolete while it ran.
    case refreshFailed(sessionKey: String, error: any Error)
    /// The session reached its expiry and was cleared.
    case expired(sessionKey: String)
}
