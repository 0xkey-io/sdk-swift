import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyTestSupport

private struct ConstantsFixture: Decodable {
    struct Set: Decodable {
        let hpkeInfo: String?
        let productionSignerSignPublicKey: String
        let productionNotarizerSignPublicKey: String
        let productionTlsFetcherEncryptPublicKey: String
        let productionOnRampCredentialsEncryptionPublicKey: String
    }
    let _meta: FixtureMeta
    let zeroxkey: Set
    let upstream: Set
}

@Suite("0xkey trust anchors and HPKE info")
struct TrustAnchorTests {
    private let fixture: ConstantsFixture = try! Fixtures.load("constants")

    @Test func hpkeInfoIsZeroXKey() {
        #expect(ZeroXKeyHPKEConstants.info == "0xkey_hpke")
        #expect(ZeroXKeyHPKEConstants.info == fixture.zeroxkey.hpkeInfo)
    }

    @Test func anchorsEqualSdkJs() {
        #expect(ZeroXKeyTrustAnchors.productionSignerSignPublicKey == fixture.zeroxkey.productionSignerSignPublicKey)
        #expect(ZeroXKeyTrustAnchors.productionNotarizerSignPublicKey == fixture.zeroxkey.productionNotarizerSignPublicKey)
        #expect(ZeroXKeyTrustAnchors.productionTlsFetcherEncryptPublicKey == fixture.zeroxkey.productionTlsFetcherEncryptPublicKey)
    }

    @Test func enclaveAnchorsDifferFromUpstream() {
        #expect(fixture.upstream.productionSignerSignPublicKey.hasPrefix("04cf288f"))
        #expect(ZeroXKeyTrustAnchors.productionSignerSignPublicKey != fixture.upstream.productionSignerSignPublicKey)
        #expect(ZeroXKeyTrustAnchors.productionNotarizerSignPublicKey != fixture.upstream.productionNotarizerSignPublicKey)
        #expect(ZeroXKeyTrustAnchors.productionTlsFetcherEncryptPublicKey != fixture.upstream.productionTlsFetcherEncryptPublicKey)
    }

    /// Recorded drift: sdk-js pins the upstream on-ramp encryption key. The Swift SDK does not carry
    /// it (`productionOnRampCredentialsEncryptionPublicKey` is unavailable); this test notices
    /// when sdk-js changes.
    @Test func sdkJsOnRampKeyIsStillUpstreams() {
        #expect(fixture.zeroxkey.productionOnRampCredentialsEncryptionPublicKey
            == fixture.upstream.productionOnRampCredentialsEncryptionPublicKey)
    }

    /// No upstream production key may appear anywhere in the SDK sources (constants, defaults,
    /// generated code): a value encrypted to or verified with it would not work with 0xkey.
    @Test func noUpstreamProductionKeyInSources() throws {
        let keys = [fixture.upstream.productionSignerSignPublicKey, fixture.upstream.productionNotarizerSignPublicKey,
                    fixture.upstream.productionTlsFetcherEncryptPublicKey,
                    fixture.upstream.productionOnRampCredentialsEncryptionPublicKey].map { $0.lowercased() }
        #expect(keys.allSatisfy { $0.count >= 66 })
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Sources")
        let files = try #require(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil))
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
        #expect(files.count > 20)
        for file in files {
            let text = try String(contentsOf: file, encoding: .utf8).lowercased()
            for key in keys {
                // Also the compressed form's x coordinate inside an uncompressed key, and vice versa.
                let x = String(key.dropFirst(2).prefix(64))
                #expect(!text.contains(x), "\(file.lastPathComponent) contains an upstream production key")
            }
        }
    }

    @Test func anchorsAreValidPoints() throws {
        for key in [ZeroXKeyTrustAnchors.productionSignerSignPublicKey,
                    ZeroXKeyTrustAnchors.productionTlsFetcherEncryptPublicKey] {
            #expect(try P256PublicKeyCodec.uncompressed(Data(hexString: key)!).count == 65)
        }
    }
}
