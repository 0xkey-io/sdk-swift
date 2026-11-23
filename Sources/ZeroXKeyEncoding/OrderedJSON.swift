import Foundation

/// Minimal JSON object writer that reproduces JavaScript's
/// `JSON.stringify({...})` byte-for-byte for flat objects whose values are
/// strings: keys keep insertion order, there is no whitespace, `/` and
/// non-ASCII characters are emitted verbatim, and only `"`, `\` and C0 control
/// characters are escaped (ECMA-262 `QuoteJSONString`; lone surrogates cannot
/// occur in a Swift `String`).
///
/// sdk-js relies on `JSON.stringify` key order for wire formats, e.g. the
/// `X-Stamp` payload (sdk-js `packages/api-key-stamper/src/_kernel/stamper.ts`),
/// the `X-Stamp-Webauthn` value (sdk-js `packages/webauthn-stamper/src/index.ts`)
/// and `formatHpkeBuf` (sdk-js `internal/crypto-core/src/primitives/crypto.ts`).
/// Foundation's `JSONEncoder` cannot guarantee those orders, so this writer is used instead.
public enum OrderedJSON {
    public static func stringify(_ pairs: KeyValuePairs<String, String>) -> String {
        stringify(pairs.map { ($0.key, $0.value) })
    }

    public static func stringify(_ pairs: [(String, String)]) -> String {
        var out = "{"
        for (index, pair) in pairs.enumerated() {
            if index > 0 { out += "," }
            out += quote(pair.0)
            out += ":"
            out += quote(pair.1)
        }
        out += "}"
        return out
    }

    public static func quote(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    let hex = String(scalar.value, radix: 16)
                    out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
        return out
    }
}
