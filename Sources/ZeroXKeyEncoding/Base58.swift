import CryptoKit
import Foundation

/// Bitcoin-alphabet base58, as used by sdk-js through the `bs58` package
/// (sdk-js `internal/codec/src/formats/bs58.ts`). Leading zero bytes map
/// to leading `1` characters.
public enum Base58 {
    static let alphabet: [UInt8] = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    private static let reverse: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (i, c) in alphabet.enumerated() { table[Int(c)] = Int8(i) }
        return table
    }()

    public static func encode<D: DataProtocol>(_ data: D) -> String {
        let bytes = [UInt8](data)
        let zeros = bytes.prefix(while: { $0 == 0 }).count
        // Base-256 -> base-58 long division on a little-endian digit buffer.
        var digits = [UInt8]()
        digits.reserveCapacity(bytes.count * 138 / 100 + 1)
        for byte in bytes[zeros...] {
            var carry = Int(byte)
            for i in 0..<digits.count {
                carry += Int(digits[i]) << 8
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        var out = [UInt8](repeating: alphabet[0], count: zeros)
        out.append(contentsOf: digits.reversed().map { alphabet[Int($0)] })
        return String(decoding: out, as: UTF8.self)
    }

    public static func decode(_ string: String) throws -> Data {
        let chars = Array(string.utf8)
        let ones = chars.prefix(while: { $0 == alphabet[0] }).count
        var bytes = [UInt8]()  // little-endian base-256
        for c in chars[ones...] {
            guard c < 128, reverse[Int(c)] >= 0 else {
                throw ZeroXKeyEncodingError.invalidBase58Character(Character(Unicode.Scalar(c)))
            }
            var carry = Int(reverse[Int(c)])
            for i in 0..<bytes.count {
                carry += Int(bytes[i]) * 58
                bytes[i] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xff))
                carry >>= 8
            }
        }
        return Data(repeating: 0, count: ones) + Data(bytes.reversed())
    }
}

/// Base58Check: payload || first 4 bytes of SHA-256(SHA-256(payload)).
/// Matches the `bs58check` package used by sdk-js
/// (sdk-js `internal/codec/src/formats/bs58check.ts`); credential bundles
/// are transported in this format (`decryptCredentialBundle` in
/// sdk-js `packages/crypto/src/0xkey.ts`).
public enum Base58Check {
    public static func encode<D: DataProtocol>(_ payload: D) -> String {
        let bytes = Data(payload)
        return Base58.encode(bytes + checksum(bytes))
    }

    public static func decode(_ string: String) throws -> Data {
        let raw = try Base58.decode(string)
        guard raw.count >= 4 else { throw ZeroXKeyEncodingError.base58PayloadTooShort }
        let payload = raw.prefix(raw.count - 4)
        guard checksum(payload) == raw.suffix(4) else { throw ZeroXKeyEncodingError.invalidBase58Checksum }
        return Data(payload)
    }

    private static func checksum(_ data: Data) -> Data {
        let first = SHA256.hash(data: data)
        let second = SHA256.hash(data: Data(first))
        return Data(second.prefix(4))
    }
}
