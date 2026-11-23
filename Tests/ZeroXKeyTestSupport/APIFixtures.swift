import CryptoKit
import Foundation

/// Builders for 0xkey response bodies in mocks. Shapes follow the swagger
/// `v1Activity` / `v1Wallet` / `v1WalletAccount` required fields.
public enum APIFixtures {
    public static var timestamp: [String: Any] { ["seconds": "1763500000", "nanos": "0"] }

    public static func activity(
        id: String = "act-1", organizationId: String = "org-1", status: String,
        type: String = "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", result: [String: Any] = [:], failure: Any? = nil,
        fingerprint: String = "fp-1"
    ) -> [String: Any] {
        var a: [String: Any] = [
            "id": id, "organizationId": organizationId, "status": status, "type": type,
            "intent": [String: Any](), "result": result, "votes": [Any](), "fingerprint": fingerprint,
            "canApprove": false, "canReject": false, "createdAt": timestamp, "updatedAt": timestamp,
            "timestampMs": "1763500000000",
        ]
        if let failure { a["failure"] = failure }
        return a
    }

    public static func user(id: String, name: String = "user") -> [String: Any] {
        ["userId": id, "userName": name, "authenticators": [Any](), "apiKeys": [Any](), "userTags": [Any](),
         "oauthProviders": [Any](), "createdAt": timestamp, "updatedAt": timestamp, "mfaPolicies": [Any]()]
    }

    public static func activityResponse(_ activity: [String: Any]) -> [String: Any] { ["activity": activity] }

    public static func wallet(id: String, name: String) -> [String: Any] {
        ["walletId": id, "walletName": name, "createdAt": timestamp, "updatedAt": timestamp, "exported": false, "imported": false]
    }

    public static func walletAccount(walletId: String, organizationId: String, address: String,
                                     addressFormat: String = "ADDRESS_FORMAT_ETHEREUM",
                                     curve: String = "CURVE_SECP256K1", path: String = "m/44'/60'/0'/0/0") -> [String: Any] {
        ["walletAccountId": "wa-\(address)", "organizationId": organizationId, "walletId": walletId, "curve": curve,
         "pathFormat": "PATH_FORMAT_BIP32", "path": path, "addressFormat": addressFormat, "address": address,
         "createdAt": timestamp, "updatedAt": timestamp]
    }

    /// Synthetic notarizer that signs `jwt(_:)`. Contexts in tests trust it through
    /// `ZeroXKeyConfig.TrustAnchors.dangerouslyOverrideNotarizerPublicKey`.
    public static let notarizerKey = try! P256.Signing.PrivateKey(
        rawRepresentation: Data(SHA256.hash(data: Data("0xkey-sdk-swift-test:notarizer".utf8))))
    /// Uncompressed hex public key of `notarizerKey`.
    public static var notarizerPublicKey: String {
        notarizerKey.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
    }

    public static func base64URL(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// JWT with the given claims, signed like the 0xkey notarizer signs session JWTs (ECDSA P-256 over
    /// SHA-256(SHA-256(`header.payload`)), 64-byte `r||s`), by `signer` (default `notarizerKey`).
    public static func jwt(_ claims: [String: Any], signer: P256.Signing.PrivateKey = notarizerKey) -> String {
        let header = base64URL(Data(#"{"alg":"ES256","typ":"JWT"}"#.utf8))
        let payload = base64URL(try! JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys]))
        let digest = SHA256.hash(data: Data(SHA256.hash(data: Data("\(header).\(payload)".utf8))))
        return "\(header).\(payload).\(base64URL(try! signer.signature(for: digest).rawRepresentation))"
    }

    public static func sessionJWT(publicKey: String, organizationId: String, userId: String, exp: TimeInterval,
                                  signer: P256.Signing.PrivateKey = notarizerKey) -> String {
        jwt(["exp": exp, "public_key": publicKey, "session_type": "SESSION_TYPE_READ_WRITE",
             "user_id": userId, "organization_id": organizationId], signer: signer)
    }
}
