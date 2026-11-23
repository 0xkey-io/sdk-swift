import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyStamper

@Suite("AttestedStamper redaction")
struct AttestedStamperRedactionTests {
    @Test func neverPrintsTheAttestedIdentity() throws {
        let key = generateP256KeyPair()
        let secret = "eyJhbGciOiJFUzI1NiJ9.verification-token-payload.signature"
        let stamper = AttestedStamper(
            attestedIdentity: secret, apiKey: try ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey))
        var dumped = ""
        dump(stamper, to: &dumped)
        for text in [String(describing: stamper), String(reflecting: stamper), "\(stamper)", dumped] {
            #expect(!text.contains(secret), "\(text)")
            #expect(text.contains("<redacted>") && text.contains(key.publicKey))
        }
        // The value itself is still readable and still stamped.
        #expect(stamper.attestedIdentity == secret)
    }
}
