import Foundation

/// Errors raised by the encoding helpers.
public enum ZeroXKeyEncodingError: Error, Equatable, Sendable {
    case invalidHex(String)
    case hexTooLong(byteLength: Int, maximum: Int)
    case invalidBase64URL
    case invalidBase58Character(Character)
    case invalidBase58Checksum
    case base58PayloadTooShort
}

/// Lowercase hexadecimal encoding.
///
/// Behaviour follows `uint8ArrayToHexString` / `uint8ArrayFromHexString` in
/// sdk-js `internal/codec/src/formats/hex.ts`:
/// - encoding is lowercase, two characters per byte;
/// - decoding rejects empty input, odd length and non-hex characters
///   (a `0x` prefix is rejected unless `allowPrefix` is `true`);
/// - an optional `length` left-pads with zero bytes and rejects overflow.
public enum Hex {
    private static let digits: [UInt8] = Array("0123456789abcdef".utf8)

    public static func encode<D: DataProtocol>(_ data: D) -> String {
        var out = [UInt8]()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func decode(_ string: String, length: Int? = nil, allowPrefix: Bool = false) throws -> Data {
        var hex = Substring(string)
        if allowPrefix, hex.hasPrefix("0x") || hex.hasPrefix("0X") {
            hex = hex.dropFirst(2)
        }
        let utf8 = Array(hex.utf8)
        guard !utf8.isEmpty, utf8.count % 2 == 0 else {
            throw ZeroXKeyEncodingError.invalidHex(string)
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(utf8.count / 2)
        var index = 0
        while index < utf8.count {
            guard let hi = nibble(utf8[index]), let lo = nibble(utf8[index + 1]) else {
                throw ZeroXKeyEncodingError.invalidHex(string)
            }
            bytes.append(hi << 4 | lo)
            index += 2
        }
        guard let length, length > 0 else { return Data(bytes) }
        guard bytes.count <= length else {
            throw ZeroXKeyEncodingError.hexTooLong(byteLength: bytes.count, maximum: length)
        }
        return Data(repeating: 0, count: length - bytes.count) + Data(bytes)
    }

    private static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}

extension Data {
    /// Lowercase hex representation (`Hex.encode`).
    public var hexString: String { Hex.encode(self) }

    /// Strict hex decoding (`Hex.decode`). Returns `nil` on invalid input.
    public init?(hexString: String) {
        guard let data = try? Hex.decode(hexString) else { return nil }
        self = data
    }
}
