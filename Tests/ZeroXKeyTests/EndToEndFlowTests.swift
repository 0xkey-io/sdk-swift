import Foundation
import Testing
import ZeroXKey
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

struct ExportFixture: Decodable {
    struct Case: Decodable { let label: String; let bundle: String; let keyFormat: String; let returnMnemonic: Bool; let expected: String }
    let organizationId: String
    let embedded: KeyPairFixture
    let signerPublicKey: String
    let cases: [Case]
}

struct OtpFixture: Decodable {
    let target: KeyPairFixture
    let signerPublicKey: String
    let otpEncryptionTargetBundle: String
    let otpCode: String
}

func verifyStamp(_ req: RecordedRequest, header: String = "X-Stamp", publicKey: String) throws -> [String: String] {
    let value = try #require(req.header(header))
    let json = try JSONSerialization.jsonObject(with: Base64URL.decode(value)) as! [String: String]
    #expect(json["publicKey"] == publicKey)
    #expect(try verifyStampSignature(publicKey: publicKey, signature: json["signature"]!, signedData: req.bodyString))
    return json
}

/// Trust anchors of the synthetic enclave that signed the fixture bundles and of the notarizer
/// that signs `APIFixtures.jwt`.
let fixtureTrustAnchors: ZeroXKeyConfig.TrustAnchors = {
    let otp: OtpFixture = try! Fixtures.load("otp-bundle")
    return .init(dangerouslyOverrideSignerPublicKey: otp.signerPublicKey,
                 dangerouslyOverrideNotarizerPublicKey: APIFixtures.notarizerPublicKey)
}()

extension ZeroXKeyConfig {
    /// This configuration with `fixtureTrustAnchors`.
    func trustingFixtures() -> ZeroXKeyConfig {
        var copy = self
        copy.trustAnchors = fixtureTrustAnchors
        return copy
    }
}

@MainActor
func makeContext(_ server: MockServer, keys: InMemoryKeyManager = InMemoryKeyManager(),
                 sessions: InMemorySessionStore = InMemorySessionStore(), rpId: String? = nil,
                 assertion: (any PasskeyAssertionProvider)? = nil, registration: (any PasskeyRegistrationProvider)? = nil,
                 now: Date = Date(timeIntervalSince1970: 1_763_500_000), autoRefresh: Bool = false,
                 clock: (@Sendable () -> Date)? = nil,
                 notificationCenter: NotificationCenter = NotificationCenter(),
                 foregroundNotification: Notification.Name? = nil,
                 authProxyConfigId: String? = "cfg-e2e", sessionExpirationSeconds: String? = nil,
                 trustAnchors: ZeroXKeyConfig.TrustAnchors = fixtureTrustAnchors) -> ZeroXKeyContext {
    // Auto-refresh is off by default here so session timers never make unplanned requests;
    // SessionLifecycleTests turns it on with a controlled sleeper.
    var config = ZeroXKeyConfig(
        apiUrl: server.apiURL.absoluteString, authProxyUrl: server.authProxyURL.absoluteString, authProxyConfigId: authProxyConfigId,
        rpId: rpId, rpName: "Wallet", organizationId: "org-parent",
        auth: .init(autoRefreshSession: autoRefresh), activityPoller: .init(intervalMs: 0, numRetries: 3),
        sessionExpirationSeconds: sessionExpirationSeconds,
        keyManager: keys, sessionStore: sessions, passkeyAssertionProvider: assertion,
        passkeyRegistrationProvider: registration, urlSession: server.session)
    config.trustAnchors = trustAnchors
    return ZeroXKeyContext(config: config, now: clock ?? { now },
                           notificationCenter: notificationCenter, foregroundNotification: foregroundNotification)
}

@Suite("End-to-end mock flow") @MainActor
struct EndToEndFlowTests {
    /// OTP sign-up → session stored → list wallets → sign message → export (sdk-js vector) → mnemonic.
    @Test func otpSignupThroughExport() async throws {
        let exportFx: ExportFixture = try Fixtures.load("export-bundle")
        let otpFx: OtpFixture = try Fixtures.load("otp-bundle")
        let mnemonicCase = try #require(exportFx.cases.first { $0.label == "mnemonic" })
        let org = exportFx.organizationId
        let server = MockServer()
        let keys = InMemoryKeyManager()
        let ctx = makeContext(server, keys: keys)
        #expect(ctx.authState == .loading)

        // The session key is created up front so the mocked verification token can bind it.
        let sessionKey = try ctx.createKeyPair()
        let verificationToken = APIFixtures.jwt([
            "id": "vt-1", "public_key": sessionKey, "contact": "alice@example.org", "verification_type": "OTP_TYPE_EMAIL",
        ])
        let jwt = APIFixtures.sessionJWT(publicKey: sessionKey, organizationId: org, userId: "user-1", exp: 1_763_503_600)

        server.on("/v1/otp_init_v2", respond: .json(["otpId": "otp-1", "otpEncryptionTargetBundle": otpFx.otpEncryptionTargetBundle]))
        server.on("/v1/otp_verify_v2", respond: .json(["verificationToken": verificationToken]))
        server.on("/v1/account", respond: .json(["organizationId": ""]))
        server.on("/v1/signup_v2", respond: .json(["organizationId": org, "userId": "user-1"]))
        server.on("/public/v1/submit/stamp_login", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            organizationId: org, status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_STAMP_LOGIN",
            result: ["stampLoginResult": ["session": jwt]]))))
        server.on("/public/v1/query/list_wallets", respond: .json(["wallets": [APIFixtures.wallet(id: "w-1", name: "Default")]]))
        server.on("/public/v1/query/list_wallet_accounts", respond: .json(["accounts": [
            APIFixtures.walletAccount(walletId: "w-1", organizationId: org, address: "0x00000000000000000000000000000000000000e1"),
        ]]))
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            organizationId: org, status: "ACTIVITY_STATUS_COMPLETED",
            result: ["signRawPayloadResult": ["r": "11", "s": "22", "v": "1b"]]))))
        server.on("/public/v1/submit/export_wallet", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            organizationId: org, status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_EXPORT_WALLET",
            result: ["exportWalletResult": ["walletId": "w-1", "exportBundle": mnemonicCase.bundle]]))))

        // 1. OTP
        let otp = try await ctx.initOtp(contact: "alice@example.org", otpType: .email)
        #expect(otp.otpId == "otp-1")
        let auth = try await ctx.completeOtp(
            otpId: otp.otpId, otpCode: otpFx.otpCode, otpEncryptionTargetBundle: otp.otpEncryptionTargetBundle,
            contact: "alice@example.org", otpType: .email, publicKey: sessionKey)
        #expect(auth.action == .signup)
        #expect(auth.sessionToken == jwt)

        // The encrypted OTP attempt decrypts (with the target key) to sdk-js's plaintext shape.
        let verifyReq = try #require(server.requests(to: "/v1/otp_verify_v2").first)
        #expect(verifyReq.header("X-Auth-Proxy-Config-ID") == "cfg-e2e")
        let encBundle = try #require(verifyReq.json["encryptedOtpBundle"] as? String)
        let parsed = try JSONSerialization.jsonObject(with: Data(encBundle.utf8)) as! [String: String]
        let plain = try ZeroXKeyHPKE.decrypt(
            ciphertext: Hex.decode(parsed["ciphertext"]!), encappedPublicKey: Hex.decode(parsed["encappedPublic"]!),
            recipientPrivateKey: Hex.decode(otpFx.target.privateKey))
        #expect(String(decoding: plain, as: UTF8.self) == #"{"otp_code":"\#(otpFx.otpCode)","public_key":"\#(sessionKey)"}"#)

        // account lookup uses the EMAIL filter and the verification token.
        let account = try #require(server.requests(to: "/v1/account").first).json as? [String: String]
        #expect(account == ["filterType": "EMAIL", "filterValue": "alice@example.org", "verificationToken": verificationToken])

        // signup_v2 carries a raw P-256 client signature over the token-usage message.
        let signup = try #require(server.requests(to: "/v1/signup_v2").first).json
        #expect(signup["userEmail"] as? String == "alice@example.org")
        #expect(signup["verificationToken"] as? String == verificationToken)
        let cs = try #require(signup["clientSignature"] as? [String: String])
        #expect(cs["scheme"] == "CLIENT_SIGNATURE_SCHEME_API_P256")
        #expect(cs["publicKey"] == sessionKey)
        #expect(cs["message"] == #"{"signup":{"apiKeys":[],"authenticators":[],"oauthProviders":[],"email":"alice@example.org"},"tokenId":"vt-1","type":"USAGE_TYPE_SIGNUP"}"#)
        let rawSig = try Hex.decode(cs["signature"]!)
        #expect(rawSig.count == 64)
        #expect(try P256Signer.verifyDER(
            signature: ECDSASignatureCodec.toDER(rawSig), message: Data(cs["message"]!.utf8),
            publicKey: P256PublicKeyCodec.uncompress(Hex.decode(sessionKey))))

        // stamp_login is stamped with X-Stamp-Attested bound to the verification token.
        let login = try #require(server.requests(to: "/public/v1/submit/stamp_login").first)
        #expect(login.header("X-Stamp") == nil)
        let attested = try verifyStamp(login, header: "X-Stamp-Attested", publicKey: sessionKey)
        #expect(attested["publicKeyAttestation"] == verificationToken)
        #expect(attested["scheme"] == "STAMP_ATTESTED_SCHEME_P256_VERIFICATION_TOKEN")
        #expect(login.json["organizationId"] as? String == org)
        #expect((login.json["parameters"] as? [String: String]) == ["publicKey": sessionKey, "expirationSeconds": "900"], "\(login.bodyString)")

        // 2. Session stored
        #expect(ctx.authState == .authenticated)
        #expect(ctx.session?.organizationId == org && ctx.session?.userId == "user-1")
        #expect(ctx.client != nil)

        // 3. Wallets
        let wallets = try await ctx.refreshWallets()
        #expect(wallets.map(\.walletId) == ["w-1"])
        #expect(ctx.wallets.first?.accounts.first?.address == "0x00000000000000000000000000000000000000e1")
        let listAccounts = try #require(server.requests(to: "/public/v1/query/list_wallet_accounts").first)
        #expect((listAccounts.json["paginationOptions"] as? [String: String]) == ["limit": "100"])
        _ = try verifyStamp(listAccounts, publicKey: sessionKey)

        // 4. Sign message (Ethereum: EIP-191 prefix, hex, keccak256)
        let sig = try await ctx.signMessage(signWith: "0x00000000000000000000000000000000000000e1",
                                            addressFormat: .ADDRESS_FORMAT_ETHEREUM, message: "hello")
        #expect(sig == SignRawPayloadResult(r: "11", s: "22", v: "1b"))
        let signReq = try #require(server.requests(to: "/public/v1/submit/sign_raw_payload").first)
        _ = try verifyStamp(signReq, publicKey: sessionKey)
        #expect((signReq.json["parameters"] as? [String: String]) == [
            "signWith": "0x00000000000000000000000000000000000000e1",
            // "\x19Ethereum Signed Message:\n5hello"
            "payload": "0x19457468657265756d205369676e6564204d6573736167653a0a3568656c6c6f",
            "encoding": "PAYLOAD_ENCODING_HEXADECIMAL", "hashFunction": "HASH_FUNCTION_KECCAK256",
        ])

        // 5. Export: replay the sdk-js bundle encrypted to the fixture's embedded key.
        let embedded = try P256KeyPair(privateKey: exportFx.embedded.privateKey)
        ctx.makeTargetKeyPair = { embedded }
        let mnemonic = try await ctx.exportWallet(walletId: "w-1", dangerouslyOverrideSignerPublicKey: exportFx.signerPublicKey)
        #expect(mnemonic == mnemonicCase.expected)
        let exportReq = try #require(server.requests(to: "/public/v1/submit/export_wallet").first)
        #expect((exportReq.json["parameters"] as? [String: String]) == ["walletId": "w-1", "targetPublicKey": exportFx.embedded.publicKeyUncompressed])

        // Without a per-call key, config.trustAnchors applies; a per-call key wins over it.
        #expect(try await ctx.exportWallet(walletId: "w-1") == mnemonicCase.expected)
        await #expect(throws: ZeroXKeyCryptoError.signerKeyMismatch(
            expected: ZeroXKeyTrustAnchors.productionSignerSignPublicKey, found: exportFx.signerPublicKey)) {
            try await ctx.exportWallet(walletId: "w-1", dangerouslyOverrideSignerPublicKey: ZeroXKeyTrustAnchors.productionSignerSignPublicKey)
        }

        #expect(server.requests.allSatisfy { $0.url.host == server.apiHost || $0.url.host == server.authProxyHost })
    }

    @Test func otpLoginForExistingAccount() async throws {
        let otpFx: OtpFixture = try Fixtures.load("otp-bundle")
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-2", "public_key": key, "contact": "+15550001", "verification_type": "OTP_TYPE_SMS"])
        server.on("/v1/otp_verify_v2", respond: .json(["verificationToken": vt]))
        server.on("/v1/account", respond: .json(["organizationId": "org-existing"]))
        server.on("/public/v1/submit/stamp_login", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", result: ["stampLoginResult": ["session":
                APIFixtures.sessionJWT(publicKey: key, organizationId: "org-existing", userId: "u", exp: 1_763_503_600)]]))))
        let res = try await ctx.completeOtp(otpId: "o", otpCode: "000000", otpEncryptionTargetBundle: otpFx.otpEncryptionTargetBundle,
                                            contact: "+15550001", otpType: .sms, publicKey: key)
        #expect(res.action == .login)
        #expect(server.requests(to: "/v1/signup_v2").isEmpty)
        #expect((server.requests(to: "/v1/account").first?.json["filterType"] as? String) == "PHONE_NUMBER")
        #expect(ctx.session?.organizationId == "org-existing")
    }

    /// Gateways without `X-Stamp-Attested` support reject `stamp_login`; the session then comes
    /// from Auth Proxy `otp_login_v2` with a client signature by the verification-token key.
    @Test func otpLoginFallsBackToAuthProxyWhenAttestedStampIsRejected() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-3", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
        let jwt = APIFixtures.sessionJWT(publicKey: key, organizationId: "org-existing", userId: "u", exp: 1_763_503_600)
        server.on("/public/v1/submit/stamp_login", respond: .text("Unauthorized\n", status: 401))
        server.on("/v1/otp_login_v2", respond: .json(["session": jwt]))
        let session = try await ctx.loginWithOtp(verificationToken: vt, organizationId: "org-existing")
        #expect(session == jwt)
        #expect(ctx.session?.organizationId == "org-existing")

        let req = try #require(server.requests(to: "/v1/otp_login_v2").first)
        #expect(req.header("X-Auth-Proxy-Config-ID") == "cfg-e2e")
        #expect(req.json["verificationToken"] as? String == vt)
        #expect(req.json["publicKey"] as? String == key)
        #expect(req.json["organizationId"] as? String == "org-existing")
        let cs = try #require(req.json["clientSignature"] as? [String: String])
        #expect(cs["scheme"] == "CLIENT_SIGNATURE_SCHEME_API_P256" && cs["publicKey"] == key)
        #expect(cs["message"] == #"{"login":{"publicKey":"\#(key)"},"tokenId":"vt-3","type":"USAGE_TYPE_LOGIN"}"#)
        #expect(try P256Signer.verifyDER(
            signature: ECDSASignatureCodec.toDER(Hex.decode(cs["signature"]!)), message: Data(cs["message"]!.utf8),
            publicKey: P256PublicKeyCodec.uncompress(Hex.decode(key))))
    }

    @Test func otpLoginDoesNotFallBackOnOtherErrors() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        let vt = APIFixtures.jwt(["id": "vt-4", "public_key": key, "contact": "a@b.c", "verification_type": "OTP_TYPE_EMAIL"])
        server.on("/public/v1/submit/stamp_login", respond: .text("bad request\n", status: 400))
        await #expect(throws: ZeroXKeyRequestError.self) { try await ctx.loginWithOtp(verificationToken: vt, organizationId: "o") }
        #expect(server.requests(to: "/v1/otp_login_v2").isEmpty)
        #expect(ctx.authState != .authenticated)
    }
}
