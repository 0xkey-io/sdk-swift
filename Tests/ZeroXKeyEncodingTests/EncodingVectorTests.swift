import Foundation
import Testing
import ZeroXKeyEncoding
import ZeroXKeyTestSupport

private struct EncodingFixture: Decodable {
    struct Case: Decodable { let hex: String; let base64url: String; let base58: String; let base58check: String }
    struct StringCase: Decodable { let input: String; let base64url: String }
    struct Padding: Decodable { let input: String; let length: Int; let padded: String }
    let _meta: FixtureMeta
    let cases: [Case]
    let stringToBase64url: [StringCase]
    let hexPadding: [Padding]
    let invalidHex: [String]
}

@Suite("Encoding vectors (sdk-js @0xkey-io/encoding)")
struct EncodingVectorTests {
    private let fixture: EncodingFixture = try! Fixtures.load("encoding")

    @Test func fixtureProvenance() {
        #expect(fixture._meta.generator == "Scripts/vectors/gen-fixtures.mjs")
        #expect(fixture._meta.sdk_js_commit.count == 40)
        #expect(fixture.cases.count >= 8)
    }

    @Test func hexRoundTrip() throws {
        for c in fixture.cases {
            let bytes = try Hex.decode(c.hex)
            #expect(Hex.encode(bytes) == c.hex)
            #expect(try Hex.decode(c.hex.uppercased()) == bytes)
        }
    }

    @Test func base64url() throws {
        for c in fixture.cases {
            let bytes = try Hex.decode(c.hex)
            #expect(Base64URL.encode(bytes) == c.base64url)
            #expect(try Base64URL.decode(c.base64url) == bytes)
            #expect(!c.base64url.contains("="))
        }
        for c in fixture.stringToBase64url {
            #expect(Base64URL.encode(string: c.input) == c.base64url)
        }
    }

    @Test func base58AndBase58Check() throws {
        for c in fixture.cases {
            let bytes = try Hex.decode(c.hex)
            #expect(Base58.encode(bytes) == c.base58)
            #expect(try Base58.decode(c.base58) == bytes)
            #expect(Base58Check.encode(bytes) == c.base58check)
            #expect(try Base58Check.decode(c.base58check) == bytes)
        }
    }

    @Test func hexLengthPadding() throws {
        for p in fixture.hexPadding {
            #expect(Hex.encode(try Hex.decode(p.input, length: p.length)) == p.padded)
        }
        #expect(throws: ZeroXKeyEncodingError.self) { try Hex.decode("abcdef", length: 2) }
    }

    @Test func invalidHexRejectedLikeSdkJs() {
        #expect(fixture.invalidHex.contains("0x00"))
        for s in fixture.invalidHex {
            #expect(throws: ZeroXKeyEncodingError.self) { try Hex.decode(s) }
        }
        #expect(try! Hex.decode("0x00", allowPrefix: true) == Data([0]))
    }

    @Test func base58CheckRejectsCorruption() throws {
        let good = fixture.cases[3].base58check
        var chars = Array(good)
        chars[chars.count - 1] = chars.last == "2" ? "3" : "2"
        #expect(throws: ZeroXKeyEncodingError.self) { try Base58Check.decode(String(chars)) }
        #expect(throws: ZeroXKeyEncodingError.self) { try Base58.decode("0OIl") }
    }

    @Test func base64urlRejectsStandardAlphabet() {
        #expect(throws: ZeroXKeyEncodingError.self) { try Base64URL.decode("ab+/") }
        #expect(throws: ZeroXKeyEncodingError.self) { try Base64URL.decode("a") }
    }
}

@Suite("OrderedJSON matches JSON.stringify")
struct OrderedJSONTests {
    @Test func escapes() {
        // Expected strings are what V8's JSON.stringify produces for these inputs.
        #expect(OrderedJSON.stringify([("b", "1"), ("a", "2")]) == #"{"b":"1","a":"2"}"#)
        #expect(OrderedJSON.quote("a/b") == #""a/b""#)
        #expect(OrderedJSON.quote("q\"\\") == #""q\"\\""#)
        #expect(OrderedJSON.quote("\n\t\u{01}\u{1f}") == #""\n\t\u0001\u001f""#)
        #expect(OrderedJSON.quote("héllo 世界") == "\"héllo 世界\"")
    }
}
