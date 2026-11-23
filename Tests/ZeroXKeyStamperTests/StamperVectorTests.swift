import CryptoKit
import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyStamper
import ZeroXKeyTestSupport

private struct ApiKeyFixture: Decodable {
    struct Case: Decodable {
        let privateKey: String; let publicKey: String; let payload: String
        let stampHeaderName: String; let stampHeaderValue: String
        let decodedStamp: String; let signatureDer: String; let rawSignature: String
    }
    let _meta: FixtureMeta
    let cases: [Case]
}

private struct BodyDigestFixture: Decodable {
    struct Case: Decodable {
        let payload: String; let utf8Hex: String; let sha256Hex: String
        let webauthnChallengeUtf8: String; let clientDataChallenge: String
    }
    let _meta: FixtureMeta
    let cases: [Case]
}

private struct WebAuthnFixture: Decodable {
    struct Case: Decodable {
        let rpId: String; let payload: String; let capturedRpId: String
        let challengeHex: String; let challengeUtf8: String
        let credentialIdHex: String; let authenticatorDataHex: String; let clientDataJSON: String; let signatureHex: String
        let passkeyPublicKeyUncompressed: String
        let stampHeaderName: String; let stampHeaderValue: String
    }
    let _meta: FixtureMeta
    let cases: [Case]
}

@Suite("X-Stamp (API key) vectors")
struct ApiKeyStampTests {
    private let f: ApiKeyFixture = try! Fixtures.load("api-key-stamp")

    @Test func assemblyMatchesSdkJsByteForByte() async throws {
        #expect(f.cases.count == 8)
        for c in f.cases {
            // Inject sdk-js's deterministic signature so the whole header can be compared.
            let der = try Hex.decode(c.signatureDer)
            let stamper = ApiKeyStamper(apiPublicKey: c.publicKey, privateKey: try Hex.decode(c.privateKey)) { _ in der }
            let stamp = try await stamper.stamp(payload: c.payload)
            #expect(stamp.stampHeaderName == c.stampHeaderName)
            #expect(stamp.stampHeaderValue == c.stampHeaderValue)
            #expect(String(decoding: try Base64URL.decode(stamp.stampHeaderValue), as: UTF8.self) == c.decodedStamp)
            #expect(try stamper.sign(payload: c.payload, format: .raw) == c.rawSignature)
        }
    }

    @Test func sdkJsSignaturesVerifyInSwift() throws {
        for c in f.cases {
            #expect(try verifyStampSignature(publicKey: c.publicKey, signature: c.signatureDer, signedData: c.payload))
            #expect(try !verifyStampSignature(publicKey: c.publicKey, signature: c.signatureDer, signedData: c.payload + " "))
        }
    }

    @Test func realStamperProducesVerifiableStampWithSameShape() async throws {
        for c in f.cases {
            let stamper = try ApiKeyStamper(apiPublicKey: c.publicKey, apiPrivateKey: c.privateKey)
            let stamp = try await stamper.stamp(payload: c.payload)
            let json = String(decoding: try Base64URL.decode(stamp.stampHeaderValue), as: UTF8.self)
            let obj = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: String]
            let signature = obj["signature"]!
            // Everything except the (randomized) signature is identical to sdk-js.
            #expect(json == c.decodedStamp.replacingOccurrences(of: c.signatureDer, with: signature))
            #expect(try verifyStampSignature(publicKey: c.publicKey, signature: signature, signedData: c.payload))
            #expect(ECDSASignatureCodec.isLowS(try ECDSASignatureCodec.fromDER(Hex.decode(signature))))
        }
    }

    @Test func rejectsMismatchedKeys() {
        let a = generateP256KeyPair(), b = generateP256KeyPair()
        #expect(throws: ZeroXKeyStamperError.self) { try ApiKeyStamper(apiPublicKey: b.publicKey, apiPrivateKey: a.privateKey) }
        #expect(throws: ZeroXKeyStamperError.self) { try ApiKeyStamper(apiPublicKey: a.publicKeyUncompressed, apiPrivateKey: a.privateKey) }
    }
}

@Suite("Request body signing inputs")
struct BodyDigestTests {
    private let f: BodyDigestFixture = try! Fixtures.load("body-digest")

    @Test func digestAndChallenge() {
        #expect(f.cases.count == 4)
        for c in f.cases {
            #expect(Hex.encode(Data(c.payload.utf8)) == c.utf8Hex)
            #expect(String(decoding: WebAuthnStamp.challenge(for: c.payload), as: UTF8.self) == c.webauthnChallengeUtf8)
            #expect(c.webauthnChallengeUtf8 == c.sha256Hex)
            #expect(WebAuthnStamp.clientDataChallenge(for: c.payload) == c.clientDataChallenge)
        }
    }
}

/// Fake authenticator: records the request and replays a fixed assertion.
private final class RecordingProvider: PasskeyAssertionProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var _requests: [PasskeyAssertionRequest] = []
    let assertion: PasskeyAssertion
    init(assertion: PasskeyAssertion) { self.assertion = assertion }
    var requests: [PasskeyAssertionRequest] { lock.withLock { _requests } }
    func assert(_ request: PasskeyAssertionRequest) async throws -> PasskeyAssertion {
        lock.withLock { _requests.append(request) }
        return assertion
    }
}

@Suite("X-Stamp-Webauthn vectors")
struct WebAuthnStampTests {
    private let f: WebAuthnFixture = try! Fixtures.load("webauthn-stamp")

    @Test func assemblyAndChallengeMatchSdkJsByteForByte() async throws {
        #expect(f.cases.count == 4)
        for c in f.cases {
            let assertion = PasskeyAssertion(
                credentialId: try Hex.decode(c.credentialIdHex),
                authenticatorData: try Hex.decode(c.authenticatorDataHex),
                clientDataJSON: Data(c.clientDataJSON.utf8),
                signature: try Hex.decode(c.signatureHex))
            let provider = RecordingProvider(assertion: assertion)
            let stamper = WebAuthnStamper(rpId: c.rpId, provider: provider)
            let stamp = try await stamper.stamp(payload: c.payload)

            #expect(stamp.stampHeaderName == c.stampHeaderName)
            #expect(stamp.stampHeaderValue == c.stampHeaderValue)
            let request = try #require(provider.requests.first)
            #expect(Hex.encode(request.challenge) == c.challengeHex)
            #expect(String(decoding: request.challenge, as: UTF8.self) == c.challengeUtf8)
            // RP ID passes through untouched, exactly as sdk-js passes it to navigator.credentials.get.
            #expect(request.rpId == c.rpId)
            #expect(request.rpId == c.capturedRpId)
        }
    }

    @Test func tenantRpIdIsNeverRewritten() async throws {
        let assertion = PasskeyAssertion(credentialId: Data([1]), authenticatorData: Data([2]), clientDataJSON: Data([3]), signature: Data([4]))
        for rpId in ["login.example.org", "staging.login.example.org", "wallet.example.com", "localhost"] {
            let provider = RecordingProvider(assertion: assertion)
            _ = try await WebAuthnStamper(rpId: rpId, allowCredentials: [Data([9, 9])], provider: provider).stamp(payload: "{}")
            #expect(provider.requests.map(\.rpId) == [rpId])
            #expect(provider.requests.first?.allowCredentials == [Data([9, 9])])
            #expect(!rpId.contains("0xkey") && provider.requests.first?.rpId.contains("0xkey") == false)
        }
    }

    @Test func fixtureAssertionSignatureIsValidES256() throws {
        // The synthetic authenticator signed authenticatorData || SHA-256(clientDataJSON).
        for c in f.cases {
            var signed = try Hex.decode(c.authenticatorDataHex)
            signed.append(Data(SHA256.hash(data: Data(c.clientDataJSON.utf8))))
            #expect(try P256Signer.verifyDER(signature: Hex.decode(c.signatureHex), message: signed,
                                             publicKey: Hex.decode(c.passkeyPublicKeyUncompressed)))
            #expect(c.clientDataJSON.contains("\"challenge\":\"\(WebAuthnStamp.clientDataChallenge(for: c.payload))\""))
        }
    }
}
