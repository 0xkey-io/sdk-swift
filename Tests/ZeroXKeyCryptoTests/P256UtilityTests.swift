import CryptoKit
import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyEncoding

@Suite("P-256 utilities")
struct P256UtilityTests {
    @Test func keyPairShape() throws {
        let kp = generateP256KeyPair()
        #expect(kp.privateKey.count == 64)
        #expect(kp.publicKey.count == 66)
        #expect(kp.publicKeyUncompressed.count == 130 && kp.publicKeyUncompressed.hasPrefix("04"))
        #expect(try P256PublicKeyCodec.compress(Hex.decode(kp.publicKeyUncompressed)) == Hex.decode(kp.publicKey))
        #expect(try P256PublicKeyCodec.uncompress(Hex.decode(kp.publicKey)) == Hex.decode(kp.publicKeyUncompressed))
        #expect(try P256KeyPair(privateKey: kp.privateKey) == kp)
    }

    @Test func rejectsInvalidPoints() {
        #expect(throws: ZeroXKeyCryptoError.invalidPublicKey) { try P256PublicKeyCodec.uncompress(Data([0x04] + [UInt8](repeating: 1, count: 32))) }
        #expect(throws: ZeroXKeyCryptoError.invalidPublicKey) { try P256PublicKeyCodec.compress(Data([0x04] + [UInt8](repeating: 1, count: 64))) }
        #expect(throws: ZeroXKeyCryptoError.invalidPrivateKey) { try P256KeyPair(privateKey: String(repeating: "0", count: 64)) }
    }

    @Test func derRoundTripAndLowS() throws {
        for _ in 0..<64 {
            let key = P256.Signing.PrivateKey()
            let raw = try key.signature(for: Data("m".utf8)).rawRepresentation
            #expect(try ECDSASignatureCodec.fromDER(ECDSASignatureCodec.toDER(raw)) == raw)
            let low = try ECDSASignatureCodec.normalizeLowS(raw)
            #expect(ECDSASignatureCodec.isLowS(low))
            #expect(key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: low), for: Data("m".utf8)))
            let der = try P256Signer.signDER(message: Data("m".utf8), privateKey: key.rawRepresentation)
            #expect(ECDSASignatureCodec.isLowS(try ECDSASignatureCodec.fromDER(der)))
            #expect(try P256Signer.verifyDER(signature: der, message: Data("m".utf8), publicKey: key.publicKey.compressedRepresentation))
            #expect(try !P256Signer.verifyDER(signature: der, message: Data("n".utf8), publicKey: key.publicKey.compressedRepresentation))
        }
    }

    @Test func derMatchesCryptoKitEncoding() throws {
        let key = P256.Signing.PrivateKey()
        let sig = try key.signature(for: Data("x".utf8))
        #expect(try ECDSASignatureCodec.toDER(sig.rawRepresentation) == sig.derRepresentation)
    }

    @Test func fromDERRejectsMalformed() {
        #expect(throws: ZeroXKeyCryptoError.self) { try ECDSASignatureCodec.fromDER(Data([0x31, 0x00])) }
        #expect(throws: ZeroXKeyCryptoError.self) { try ECDSASignatureCodec.fromDER(Data([0x30, 0x81, 0x00])) }
        #expect(throws: ZeroXKeyCryptoError.self) { try ECDSASignatureCodec.fromDER(Data([0x30])) }
    }
}
