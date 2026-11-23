import Foundation

/// 0xkey production trust anchors.
///
/// Source of truth (copied value-for-value, verified by
/// `Tests/ZeroXKeyCryptoTests/TrustAnchorTests.swift` against the generated
/// fixture `Tests/Fixtures/constants.json`):
/// sdk-js `internal/crypto-core/src/primitives/constants.ts` lines 30-40,
/// re-exported by sdk-js `packages/crypto/src/constants.ts`.
///
/// These are not the upstream service's values; a bundle signed by the 0xkey enclave can only be
/// verified with the keys below.
public enum ZeroXKeyTrustAnchors {
    /// Uncompressed P-256 public key of the 0xkey signer enclave. Export and import
    /// bundles (`enclaveQuorumPublic` / `dataSignature`) are verified against it.
    /// sdk-js: `PRODUCTION_SIGNER_SIGN_PUBLIC_KEY` (constants.ts:30-31).
    public static let productionSignerSignPublicKey =
        "046d10ba0b618a5fd338a39e95e0236bb50fa323804952da886aa3768cd6b603747d606778096d5eb24644600f6f7d4a634a93043a8a5db99081068e1e03a9f201"

    /// Uncompressed P-256 public key of the 0xkey notarizer enclave (session JWT
    /// signatures). In 0xkey it is the same key as the signer.
    /// sdk-js: `PRODUCTION_NOTARIZER_SIGN_PUBLIC_KEY` (constants.ts:33-34).
    public static let productionNotarizerSignPublicKey =
        "046d10ba0b618a5fd338a39e95e0236bb50fa323804952da886aa3768cd6b603747d606778096d5eb24644600f6f7d4a634a93043a8a5db99081068e1e03a9f201"

    /// Uncompressed P-256 encryption key of the 0xkey TLS fetcher enclave
    /// (OAuth2 client secret upload).
    /// sdk-js: `PRODUCTION_TLS_FETCHER_ENCRYPT_PUBLIC_KEY` (constants.ts:36-37).
    public static let productionTlsFetcherEncryptPublicKey =
        "0438c11ab9353df275dd2f3b99a47c64fe37c820775e352cb2746221d9eb458bc513aedae91a662d3a57de88d708c04dd494fc99dfe3ea91b6b4e9fcbca12e78e6"

    /// Not provided. sdk-js pins an upstream on-ramp credential encryption key under this name
    /// (`PRODUCTION_ON_RAMP_CREDENTIALS_ENCRYPTION_PUBLIC_KEY`), but 0xkey publishes no such key:
    /// the 0xkey enclave decrypts on-ramp credentials with its own quorum key, so ciphertext for
    /// the upstream key could not be read by 0xkey. Encrypt `encryptedSecretApiKey` /
    /// `encryptedPrivateApiKey` of `createFiatOnRampCredential` / `updateFiatOnRampCredential` to
    /// a key 0xkey gives you explicitly.
    @available(*, unavailable, message: "0xkey publishes no on-ramp credential encryption key; pass the key 0xkey provides explicitly")
    public static var productionOnRampCredentialsEncryptionPublicKey: String { fatalError("unavailable") }
}

/// HPKE parameters used by 0xkey.
public enum ZeroXKeyHPKEConstants {
    /// HPKE `info` string for every 0xkey bundle (export, import, credential, OTP).
    ///
    /// sdk-js: `ZEROXKEY_HPKE_INFO = "0xkey_hpke"` in
    /// sdk-js `packages/crypto/src/0xkey.ts` lines 31-36 and the OTP path
    /// `encryptOtpAttemptBundle` in sdk-js `packages/core/src/__clients__/core.ts`
    /// line 278. The enclave uses the same value (hybrid-compatibility-architecture §5.1).
    /// The legacy upstream info string (fixed schedule) is deliberately not supported.
    public static let info = "0xkey_hpke"

    /// RFC 9180 suite: DHKEM(P-256, HKDF-SHA256) = 0x0010, HKDF-SHA256 = 0x0001,
    /// AES-256-GCM = 0x0002 (`SUITE_ID_1` / `SUITE_ID_2` in crypto-core constants.ts:1-2).
    static let kemSuiteID = Data("KEM".utf8) + Data([0x00, 0x10])
    static let hpkeSuiteID = Data("HPKE".utf8) + Data([0x00, 0x10, 0x00, 0x01, 0x00, 0x02])
    static let version = Data("HPKE-v1".utf8)
}
