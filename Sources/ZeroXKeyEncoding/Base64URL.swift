import Foundation

/// RFC 4648 §5 base64url without padding.
///
/// Matches `stringToBase64urlString` / `base64StringToBase64UrlEncodedString`
/// (sdk-js `internal/codec/src/formats/base64.ts`) and `bufferToBase64url`
/// (sdk-js `packages/webauthn-stamper/src/webauthn-json/base64url.ts`):
/// `+` → `-`, `/` → `_`, `=` removed.
public enum Base64URL {
    public static func encode<D: DataProtocol>(_ data: D) -> String {
        Data(data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Encodes the UTF-8 bytes of `string`.
    public static func encode(string: String) -> String {
        encode(Data(string.utf8))
    }

    /// Decodes base64url (padding optional). Standard base64 characters are rejected.
    public static func decode(_ string: String) throws -> Data {
        var s = string
        while s.hasSuffix("=") { s.removeLast() }
        guard s.utf8.allSatisfy({ c in
            (c >= UInt8(ascii: "A") && c <= UInt8(ascii: "Z"))
                || (c >= UInt8(ascii: "a") && c <= UInt8(ascii: "z"))
                || (c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9"))
                || c == UInt8(ascii: "-") || c == UInt8(ascii: "_")
        }), s.utf8.count % 4 != 1 else {
            throw ZeroXKeyEncodingError.invalidBase64URL
        }
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b64 += String(repeating: "=", count: (4 - b64.utf8.count % 4) % 4)
        guard let data = Data(base64Encoded: b64) else { throw ZeroXKeyEncodingError.invalidBase64URL }
        return data
    }
}

extension Data {
    /// Unpadded base64url representation (`Base64URL.encode`).
    public var base64URLEncodedString: String { Base64URL.encode(self) }
}
