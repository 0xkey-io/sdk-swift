import CryptoKit
import Foundation
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyHttp
import ZeroXKeyStamper

/// Supplies an OIDC ID token whose `nonce` claim is the given value. Apps implement this
/// with native Sign in with Apple, Google Sign-In, etc. (0xkey has no hosted OAuth page.)
public protocol OIDCTokenProvider: Sendable {
    func idToken(nonce: String) async throws -> String
}

extension ZeroXKeyContext {
    // MARK: - OTP (Auth Proxy)

    /// Sends an OTP (sdk-js `initOtp` → `proxyInitOtpV2`, core.ts:1924-1964).
    public func initOtp(contact: String, otpType: OtpType, captchaToken: String? = nil) async throws -> InitOtpResult {
        let res = try await proxyClient().proxyInitOtpV2(
            ProxyTInitOtpV2Body(otpType: otpType.rawValue, contact: contact), captchaToken: captchaToken)
        guard !res.otpId.isEmpty, !res.otpEncryptionTargetBundle.isEmpty else {
            throw ZeroXKeyError.badResponse("otp_init_v2 returned no otpId or otpEncryptionTargetBundle")
        }
        return InitOtpResult(otpId: res.otpId, otpEncryptionTargetBundle: res.otpEncryptionTargetBundle)
    }

    /// Verifies an OTP code (sdk-js `verifyOtp`, core.ts:1984-2055): the code and
    /// `publicKey` are HPKE-encrypted (`0xkey_hpke`) to the target bundle, sent to
    /// `otp_verify_v2`, then `account` resolves the sub-organization.
    ///
    /// The target bundle must be signed by the signer enclave of `config.trustAnchors`; otherwise
    /// this throws a ``ZeroXKeyCryptoError`` before anything is encrypted or sent.
    public func verifyOtp(
        otpId: String, otpCode: String, otpEncryptionTargetBundle: String,
        contact: String, otpType: OtpType, publicKey: String
    ) async throws -> VerifyOtpResult {
        let token = try await verifyOtpToken(
            otpId: otpId, otpCode: otpCode, otpEncryptionTargetBundle: otpEncryptionTargetBundle, publicKey: publicKey)
        let account = try await proxyClient().proxyGetAccount(ProxyTGetAccountBody(
            filterType: otpType.accountFilterType, filterValue: contact, verificationToken: token))
        return VerifyOtpResult(subOrganizationId: account.organizationId ?? "", verificationToken: token)
    }

    /// The `otp_verify_v2` half of `verifyOtp`, without the `account` lookup (so it needs no contact):
    /// HPKE-encrypts the code and `publicKey` to the target bundle and returns the verification token,
    /// which carries `publicKey`.
    package func verifyOtpToken(
        otpId: String, otpCode: String, otpEncryptionTargetBundle: String, publicKey: String
    ) async throws -> String {
        let proxy = try proxyClient()
        let bundle = try encryptOtpAttemptBundle(
            otpCode: otpCode, publicKey: publicKey, otpEncryptionTargetBundle: otpEncryptionTargetBundle,
            dangerouslyOverrideSignerPublicKey: config.trustAnchors.dangerouslyOverrideSignerPublicKey)
        let verify = try await proxy.proxyVerifyOtpV2(ProxyTVerifyOtpV2Body(otpId: otpId, encryptedOtpBundle: bundle))
        guard !verify.verificationToken.isEmpty else { throw ZeroXKeyError.badResponse("otp_verify_v2 returned no verificationToken") }
        return verify.verificationToken
    }

    /// Verifies the code, then logs in or signs up (sdk-js `completeOtp`, core.ts:2349-2450).
    public func completeOtp(
        otpId: String, otpCode: String, otpEncryptionTargetBundle: String, contact: String, otpType: OtpType,
        publicKey: String? = nil, createSubOrgParams: CreateSubOrgParams? = nil, invalidateExisting: Bool = false,
        sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> AuthResult {
        let key = try publicKey ?? createKeyPair()
        let verified = try await verifyOtp(otpId: otpId, otpCode: otpCode, otpEncryptionTargetBundle: otpEncryptionTargetBundle,
                                           contact: contact, otpType: otpType, publicKey: key)
        if verified.subOrganizationId.isEmpty {
            let token = try await signUpWithOtp(verificationToken: verified.verificationToken, contact: contact, otpType: otpType,
                                                createSubOrgParams: createSubOrgParams, invalidateExisting: invalidateExisting,
                                                sessionKey: sessionKey)
            return AuthResult(sessionToken: token, action: .signup)
        }
        let token = try await loginWithOtp(verificationToken: verified.verificationToken, organizationId: verified.subOrganizationId,
                                           invalidateExisting: invalidateExisting, sessionKey: sessionKey)
        return AuthResult(sessionToken: token, action: .login)
    }

    /// OTP login (sdk-js `loginWithOtp`, core.ts:2057-2190): `stamp_login` is stamped with
    /// `X-Stamp-Attested` (verification-token attested key); the verification-token key
    /// becomes the session key.
    ///
    /// If an MFA policy holds the login, this throws `ZeroXKeyActivityError.authenticatorsNeeded`.
    @discardableResult
    public func loginWithOtp(
        verificationToken: String, organizationId: String? = nil, invalidateExisting: Bool = false,
        expirationSeconds: String? = nil, sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> String {
        try await otpLogin(verificationToken: verificationToken, organizationId: organizationId,
                           invalidateExisting: invalidateExisting, expirationSeconds: expirationSeconds,
                           sessionProfileId: nil, sessionKey: sessionKey)
    }

    /// **Experimental.** OTP login requesting a scoped session (session profile).
    ///
    /// The 0xkey servers do not support this yet: the enclave rejects an attested `stamp_login`
    /// with a `sessionProfileId`, and the Auth Proxy rejects OTP logins with a profile. Scoped
    /// logins never fall back to `otp_login_v2`. Kept behind `@_spi(Experimental)` until 0xkey
    /// supports it.
    @_spi(Experimental)
    @discardableResult
    public func loginWithOtp(
        verificationToken: String, organizationId: String? = nil, invalidateExisting: Bool = false,
        expirationSeconds: String? = nil, sessionProfileId: String, sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> String {
        try await otpLogin(verificationToken: verificationToken, organizationId: organizationId,
                           invalidateExisting: invalidateExisting, expirationSeconds: expirationSeconds,
                           sessionProfileId: sessionProfileId, sessionKey: sessionKey)
    }

    func otpLogin(
        verificationToken: String, organizationId: String?, invalidateExisting: Bool,
        expirationSeconds: String?, sessionProfileId: String?, sessionKey: String
    ) async throws -> String {
        let login = try await prepareOtpLogin(verificationToken: verificationToken, organizationId: organizationId)
        let lifetime = await resolvedExpirationSeconds(expirationSeconds)
        let session: String
        do {
            let res = try await baseClient(stamper: login.attested, organizationId: login.organizationId).stampLogin(TStampLoginBody(
                publicKey: login.publicKey, expirationSeconds: lifetime,
                invalidateExisting: invalidateExisting ? true : nil, sessionProfileId: sessionProfileId,
                organizationId: login.organizationId))
            session = res.session
        } catch let error as ZeroXKeyRequestError
                    where config.authProxyConfigId != nil && sessionProfileId == nil
                    && Self.isAttestedLoginUnavailable(error) {
            session = try await loginWithOtpViaAuthProxy(
                verificationToken: verificationToken, tokenId: login.claims.id, publicKey: login.publicKey, apiKey: login.apiKey,
                organizationId: login.organizationId, invalidateExisting: invalidateExisting)
        }
        guard !session.isEmpty else { throw ZeroXKeyError.badResponse("OTP login returned no session") }
        try await storeSession(jwt: session, sessionKey: sessionKey)
        return session
    }

    /// Verification-token key, attested stamper and target organization of an OTP login.
    struct OtpLoginContext {
        let claims: VerificationTokenClaims
        let publicKey: String
        let apiKey: ApiKeyStamper
        let attested: AttestedStamper
        let organizationId: String
    }

    func prepareOtpLogin(verificationToken: String, organizationId: String?) async throws -> OtpLoginContext {
        let claims = try VerificationTokenClaims.decode(verificationToken)
        guard let publicKey = claims.publicKey, !publicKey.isEmpty else {
            throw ZeroXKeyError.invalidVerificationToken("missing public_key")
        }
        let apiKey = try config.keyManager.stamper(forPublicKey: publicKey)
        var orgId = organizationId
        if orgId == nil {
            guard let contact = claims.contact, !contact.trimmingCharacters(in: .whitespaces).isEmpty,
                  let type = claims.verificationType.flatMap(OtpType.init(rawValue:)) else {
                throw ZeroXKeyError.invalidVerificationToken("missing contact selector")
            }
            orgId = try await proxyClient().proxyGetAccount(ProxyTGetAccountBody(
                filterType: type.accountFilterType, filterValue: contact, verificationToken: verificationToken)).organizationId
        }
        guard let resolved = orgId, !resolved.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw ZeroXKeyError.missingOrganizationId
        }
        let attested = AttestedStamper(attestedIdentity: verificationToken, scheme: .p256VerificationToken, apiKey: apiKey)
        return OtpLoginContext(claims: claims, publicKey: publicKey, apiKey: apiKey, attested: attested, organizationId: resolved)
    }

    /// Whether a failed attested `stamp_login` means the server cannot take attested logins at all, as
    /// opposed to refusing this login. Only the former may fall back to Auth Proxy `otp_login_v2`.
    /// Rule for rule the same as sdk-js `isAttestedLoginUnavailable`
    /// (sdk-js `packages/core/src/utils.ts:1232-1269`), whose `ZeroXKeyHttpError` / `ZeroXKeyRequestError`
    /// split is mirrored below:
    ///
    /// - A body that is not JSON (empty, or text such as the production gateway's `Unauthorized`) is
    ///   sdk-js's `ZeroXKeyHttpError` (sdk-js `packages/core/src/__clients__/response-error.ts:19-27`): HTTP
    ///   401, 404, 501 and 503 fall back, any other status does not. A gateway that does not know
    ///   `X-Stamp-Attested` answers 401 in plain text.
    /// - Any JSON body is a `ZeroXKeyRequestError`, which is what `kind == .grpcStatus` is and also
    ///   what a JSON body without `code` / `message` is (sdk-js accepts any JSON; only `null` is not
    ///   a body). Then:
    ///   - without an HTTP status, or with 403: no fallback (403 can be an MFA requirement that
    ///     the fallback would bypass);
    ///   - a `reason` (any `details` entry that is an object with a string `reason`, whatever its
    ///     `@type`) starting with `ATTESTED_LOGIN_`: no fallback (can be an MFA requirement);
    ///   - a `reason` of `ATTESTED_STAMP_NOT_ENABLED`: fallback;
    ///   - any other `reason` starting with `ATTESTED_`: no fallback (the server checked the stamp
    ///     and refused it);
    ///   - otherwise HTTP 404, 501 and 503 fall back, any other status (400, 401, 500, ...) does not.
    ///
    /// The `otp_login_v2` fallback is further limited to a configured Auth Proxy and an unscoped login
    /// (see `otpLogin`).
    nonisolated package static func isAttestedLoginUnavailable(_ error: ZeroXKeyRequestError) -> Bool {
        func unavailableStatus(_ status: Int) -> Bool { status == 404 || status == 501 || status == 503 }
        let status = error.httpStatus
        let details: [JSONValue]
        switch error.kind {
        case .grpcStatus:
            details = error.details
        case .plainText, .empty:
            guard let body = try? JSONDecoder().decode(JSONValue.self, from: Data(error.rawBody.utf8)), body != .null else {
                return status == 401 || unavailableStatus(status)
            }
            if case .array(let list)? = body["details"] { details = list } else { details = [] }
        }
        guard status > 0, status != 403 else { return false }
        let reasons = details.compactMap { $0["reason"]?.stringValue }
        if reasons.contains(where: { $0.hasPrefix("ATTESTED_LOGIN_") }) { return false }
        if reasons.contains("ATTESTED_STAMP_NOT_ENABLED") { return true }
        if reasons.contains(where: { $0.hasPrefix("ATTESTED_") }) { return false }
        return unavailableStatus(status)
    }

    /// Auth Proxy `otp_login_v2`: the proxy creates the session from the verification token and
    /// a raw P-256 client signature over the `USAGE_TYPE_LOGIN` message. The session lifetime is
    /// the Auth Proxy configuration's, not `expirationSeconds`.
    func loginWithOtpViaAuthProxy(
        verificationToken: String, tokenId: String, publicKey: String, apiKey: ApiKeyStamper,
        organizationId: String, invalidateExisting: Bool
    ) async throws -> String {
        let message = SignUpBody.loginClientSignatureMessage(tokenId: tokenId, sessionPublicKey: publicKey)
        let res = try await proxyClient().proxyOtpLoginV2(ProxyTOtpLoginV2Body(
            verificationToken: verificationToken, publicKey: publicKey,
            clientSignature: v1ClientSignature(
                publicKey: publicKey, scheme: .CLIENT_SIGNATURE_SCHEME_API_P256, message: message,
                signature: try apiKey.sign(payload: message, format: .raw)),
            invalidateExisting: invalidateExisting ? true : nil, organizationId: organizationId))
        guard !res.session.isEmpty else { throw ZeroXKeyError.badResponse("otp_login_v2 returned no session") }
        return res.session
    }

    /// OTP sign-up (sdk-js `signUpWithOtp`, core.ts:2208-2324): `signup_v2` with a client
    /// signature (raw P-256 over the token-usage JSON) by the verification-token key.
    @discardableResult
    public func signUpWithOtp(
        verificationToken: String, contact: String, otpType: OtpType, createSubOrgParams: CreateSubOrgParams? = nil,
        invalidateExisting: Bool = false, sessionKey: String = ZeroXKeySessionKey.default, captchaToken: String? = nil
    ) async throws -> String {
        let claims = try VerificationTokenClaims.decode(verificationToken)
        guard let publicKey = claims.publicKey, !publicKey.isEmpty else {
            throw ZeroXKeyError.invalidVerificationToken("missing public_key")
        }
        let apiKey = try config.keyManager.stamper(forPublicKey: publicKey)
        var params = (createSubOrgParams ?? CreateSubOrgParams()).merged(over: config.auth.createSuborgParams)
        if otpType == .email { params.userEmail = contact } else { params.userPhoneNumber = contact }
        var body = SignUpBody.build(params, verificationToken: verificationToken, now: now())
        let message = SignUpBody.clientSignatureMessage(
            tokenId: claims.id, email: body.userEmail, phoneNumber: body.userPhoneNumber,
            apiKeys: body.apiKeys, authenticators: body.authenticators, oauthProviders: params.oauthProviders)
        body.clientSignature = v1ClientSignature(
            publicKey: publicKey, scheme: .CLIENT_SIGNATURE_SCHEME_API_P256, message: message,
            signature: try apiKey.sign(payload: message, format: .raw))
        let res = try await proxyClient().proxySignupV2(body, captchaToken: captchaToken)
        guard !res.organizationId.isEmpty else { throw ZeroXKeyError.badResponse("signup_v2 returned no organizationId") }
        return try await loginWithOtp(verificationToken: verificationToken, organizationId: res.organizationId,
                                      invalidateExisting: invalidateExisting, sessionKey: sessionKey)
    }

    // MARK: - OAuth (Auth Proxy)

    /// OIDC nonce the ID token must carry for `publicKey`: lowercase hex SHA-256 of the
    /// compressed public key hex string, i.e. `bytesToHex(sha256(publicKey))`
    /// (sdk-js `packages/react-native-wallet-kit/src/utils/oauth-flow.ts:389`; core.ts:2441).
    nonisolated public static func oidcNonce(forPublicKey publicKey: String) -> String {
        Hex.encode(Data(SHA256.hash(data: Data(publicKey.utf8))))
    }

    /// Completes OAuth with an OIDC token: login if the token's subject already has a
    /// sub-org, otherwise sign up (sdk-js `completeOauth`, core.ts:2452-2577).
    public func completeOAuth(
        oidcToken: String, publicKey: String, providerName: String? = nil,
        createSubOrgParams: CreateSubOrgParams? = nil, invalidateExisting: Bool = false,
        sessionKey: String = ZeroXKeySessionKey.default, captchaToken: String? = nil
    ) async throws -> AuthResult {
        let proxy = try proxyClient()
        let account = try await proxy.proxyGetAccount(ProxyTGetAccountBody(filterType: "OIDC_TOKEN", filterValue: oidcToken))
        if let org = account.organizationId, !org.isEmpty {
            let token = try await loginWithOAuth(oidcToken: oidcToken, publicKey: publicKey,
                                                 invalidateExisting: invalidateExisting, sessionKey: sessionKey)
            return AuthResult(sessionToken: token, action: .login)
        }
        // sdk-js signUpWithOauth (core.ts:2658-2733): signup with the OIDC provider, then oauth_login.
        var params = (createSubOrgParams ?? CreateSubOrgParams()).merged(over: config.auth.createSuborgParams)
        params.oauthProviders = [v1OauthProviderParams(
            providerName: providerName ?? "OpenID Connect Provider \(timestampName)", oidcToken: oidcToken)]
        let body = SignUpBody.buildV1(params, now: now())
        _ = try await proxy.proxySignup(body, captchaToken: captchaToken)
        let token = try await loginWithOAuth(oidcToken: oidcToken, publicKey: publicKey,
                                             invalidateExisting: invalidateExisting, sessionKey: sessionKey)
        return AuthResult(sessionToken: token, action: .signup)
    }

    /// sdk-js `loginWithOauth` (core.ts:2579-2656) → Auth Proxy `oauth_login`.
    @discardableResult
    public func loginWithOAuth(
        oidcToken: String, publicKey: String, organizationId: String? = nil, invalidateExisting: Bool = false,
        sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> String {
        let res = try await proxyClient().proxyOAuthLogin(ProxyTOAuthLoginBody(
            oidcToken: oidcToken, publicKey: publicKey, invalidateExisting: invalidateExisting, organizationId: organizationId))
        guard !res.session.isEmpty else { throw ZeroXKeyError.badResponse("oauth_login returned no session") }
        try await storeSession(jwt: res.session, sessionKey: sessionKey)
        return res.session
    }

    /// Native Sign in with Apple: creates a session key, asks `tokenProvider` for an Apple
    /// ID token with `nonce = oidcNonce(publicKey)`, then `completeOAuth`.
    public func handleAppleOAuth(
        tokenProvider: any OIDCTokenProvider, createSubOrgParams: CreateSubOrgParams? = nil,
        sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> AuthResult {
        let publicKey = try createKeyPair()
        do {
            let idToken = try await tokenProvider.idToken(nonce: Self.oidcNonce(forPublicKey: publicKey))
            return try await completeOAuth(oidcToken: idToken, publicKey: publicKey, providerName: "apple",
                                           createSubOrgParams: createSubOrgParams, sessionKey: sessionKey)
        } catch {
            try? config.keyManager.deleteKeyPair(publicKey: publicKey)
            throw error
        }
    }

    // MARK: - Passkeys

    /// Passkey login (sdk-js `loginWithPasskey`, core.ts:1022-1113): `stamp_login`
    /// stamped with `X-Stamp-Webauthn` against `config.organizationId`.
    @discardableResult
    public func loginWithPasskey(
        organizationId: String? = nil, expirationSeconds: String? = nil, allowCredentials: [Data] = [],
        sessionKey: String = ZeroXKeySessionKey.default, publicKey sessionPublicKey: String? = nil
    ) async throws -> String {
        guard let provider = passkeyAssertionProvider else { throw ZeroXKeyError.missingPasskeyProvider }
        guard let rpId = config.rpId, !rpId.isEmpty else { throw ZeroXKeyError.missingRpId }
        guard let org = organizationId ?? config.organizationId else { throw ZeroXKeyError.missingOrganizationId }
        let lifetime = await resolvedExpirationSeconds(expirationSeconds)
        // A caller-supplied key (its private half must be in the key manager) is the caller's to clean up.
        let created = sessionPublicKey == nil
        let publicKey = try sessionPublicKey ?? createKeyPair()
        do {
            let stamper = WebAuthnStamper(rpId: rpId, allowCredentials: allowCredentials, provider: provider)
            let res = try await baseClient(stamper: stamper, organizationId: org).stampLogin(TStampLoginBody(
                publicKey: publicKey, expirationSeconds: lifetime, organizationId: org))
            try await storeSession(jwt: res.session, sessionKey: sessionKey)
            return res.session
        } catch {
            if created { try? config.keyManager.deleteKeyPair(publicKey: publicKey) }
            throw error
        }
    }

    /// Passkey sign-up (sdk-js `signUpWithPasskey`, core.ts:1115-1255): create a passkey,
    /// `signup` a sub-org with it plus a 60 s bootstrap API key, then `stamp_login` with
    /// that bootstrap key for a fresh session key.
    @discardableResult
    public func signUpWithPasskey(
        passkeyDisplayName: String? = nil, createSubOrgParams: CreateSubOrgParams? = nil,
        expirationSeconds: String? = nil, sessionKey: String = ZeroXKeySessionKey.default, captchaToken: String? = nil
    ) async throws -> String {
        try await signUpWithPasskeyDetailed(
            passkeyDisplayName: passkeyDisplayName, createSubOrgParams: createSubOrgParams,
            expirationSeconds: expirationSeconds, sessionKey: sessionKey, captchaToken: captchaToken).session
    }

    /// `signUpWithPasskey` that also reports the new passkey's credential ID.
    package func signUpWithPasskeyDetailed(
        passkeyDisplayName: String? = nil, createSubOrgParams: CreateSubOrgParams? = nil,
        expirationSeconds: String? = nil, sessionKey: String = ZeroXKeySessionKey.default, captchaToken: String? = nil
    ) async throws -> (session: String, credentialId: String) {
        guard let provider = passkeyRegistrationProvider else { throw ZeroXKeyError.missingPasskeyProvider }
        guard let rpId = config.rpId, !rpId.isEmpty else { throw ZeroXKeyError.missingRpId }
        let proxy = try proxyClient()
        let bootstrapKey = try createKeyPair()
        defer { try? config.keyManager.deleteKeyPair(publicKey: bootstrapKey) }

        let name = passkeyDisplayName ?? "passkey-\(timestampName)"
        let request = PasskeyRegistrationRequest(
            rpId: rpId, rpName: config.rpName, challenge: Self.randomBytes(32), userId: Self.randomBytes(32),
            userName: name, displayName: name)
        let encoded = EncodedPasskeyRegistration(request: request, registration: try await provider.register(request))

        var params = (createSubOrgParams ?? CreateSubOrgParams()).merged(over: config.auth.createSuborgParams)
        params.authenticators.append(Self.authenticatorParams(name: name, encoded: encoded))
        params.apiKeys = [v1ApiKeyParamsV2(apiKeyName: "passkey-auth-\(bootstrapKey)", publicKey: bootstrapKey,
                                           curveType: .API_KEY_CURVE_P256, expirationSeconds: "60")]
        let signup = try await proxy.proxySignup(SignUpBody.buildV1(params, now: now()), captchaToken: captchaToken)

        let lifetime = await resolvedExpirationSeconds(expirationSeconds)
        let sessionPublicKey = try createKeyPair()
        do {
            let res = try await baseClient(stamper: try config.keyManager.stamper(forPublicKey: bootstrapKey),
                                           organizationId: signup.organizationId)
                .stampLogin(TStampLoginBody(publicKey: sessionPublicKey, expirationSeconds: lifetime,
                                            organizationId: signup.organizationId))
            try await storeSession(jwt: res.session, sessionKey: sessionKey)
            return (res.session, encoded.credentialId)
        } catch {
            try? config.keyManager.deleteKeyPair(publicKey: sessionPublicKey)
            throw error
        }
    }

    /// Registers a new passkey for an already signed-in user and returns its authenticator ID
    /// (sdk-js `addPasskey`, core.ts:4858-4911, with `createPasskey`, core.ts:897-970).
    ///
    /// Use it to move a user from a backend-held API key to a passkey: after login, call
    /// `addPasskey()`, then remove the API key server-side.
    ///
    /// - The passkey is created for `config.rpId`, used as is (tenant domains are fine). Challenge
    ///   and WebAuthn user handle are 32 random bytes each, encoded like `signUpWithPasskey`.
    /// - `CREATE_AUTHENTICATORS_V2` is stamped with the current session and targets
    ///   `organizationId` (default: the session's organization) for `userId` (default: the
    ///   session's user).
    /// - `name`: 1-64 of letters, digits, space, `_ - : / .` (sdk-js `isValidPasskeyName`);
    ///   default `0xkey Passkey-<ms>` (as sdk-js `addPasskey`).
    @discardableResult
    public func addPasskey(name: String? = nil, userId: String? = nil, organizationId: String? = nil) async throws -> String {
        let (c, s) = try sessionClientAndSession()
        guard let provider = passkeyRegistrationProvider else { throw ZeroXKeyError.missingPasskeyProvider }
        guard let rpId = config.rpId, !rpId.isEmpty else { throw ZeroXKeyError.missingRpId }
        let passkeyName = try Self.validPasskeyName(name ?? "0xkey Passkey-\(timestampName)")
        let request = PasskeyRegistrationRequest(
            rpId: rpId, rpName: config.rpName, challenge: Self.randomBytes(32), userId: Self.randomBytes(32),
            userName: passkeyName, displayName: passkeyName)
        let encoded = EncodedPasskeyRegistration(request: request, registration: try await provider.register(request))
        let res = try await c.createAuthenticators(TCreateAuthenticatorsBody(
            authenticators: [Self.authenticatorParams(name: passkeyName, encoded: encoded)],
            userId: userId ?? s.userId, organizationId: organizationId ?? s.organizationId))
        guard let id = res.authenticatorIds.first, !id.isEmpty else {
            throw ZeroXKeyError.badResponse("create_authenticators returned no authenticator ID")
        }
        return id
    }

    nonisolated static func validPasskeyName(_ name: String) throws -> String {
        guard name.range(of: #"^[a-zA-Z0-9 _\-:/.]{1,64}$"#, options: .regularExpression) != nil else {
            throw ZeroXKeyError.invalidArgument(
                "passkey name must be 1-64 letters, digits, spaces, dashes, underscores, colons, slashes or dots")
        }
        return name
    }

    nonisolated static func authenticatorParams(name: String, encoded: EncodedPasskeyRegistration) -> v1AuthenticatorParamsV2 {
        v1AuthenticatorParamsV2(
            authenticatorName: name, challenge: encoded.encodedChallenge,
            attestation: v1Attestation(credentialId: encoded.credentialId, clientDataJson: encoded.clientDataJson,
                                       attestationObject: encoded.attestationObject,
                                       transports: encoded.transports.map(v1AuthenticatorTransport.init(rawValue:))))
    }

    nonisolated static func randomBytes(_ n: Int) -> Data {
        Data(SymmetricKey(size: .init(bitCount: n * 8)).withUnsafeBytes { Array($0) })
    }
}

/// Sign-up body construction (sdk-js `buildSignUpBody`, utils.ts:722-800, and
/// `getClientSignatureMessageForSignup`, utils.ts:1552-1600).
package enum SignUpBody {
    static func ms(_ d: Date) -> String { String(Int64(d.timeIntervalSince1970 * 1000)) }

    static func buildV1(_ p: CreateSubOrgParams, verificationToken: String? = nil, now: Date) -> ProxyTSignupBody {
        ProxyTSignupBody(
            apiKeys: p.apiKeys, authenticators: p.authenticators, oauthProviders: p.oauthProviders,
            userEmail: p.userEmail, userPhoneNumber: p.userPhoneNumber, userTag: p.userTag,
            userName: p.userName ?? p.userEmail ?? "user-\(ms(now))",
            organizationName: p.subOrgName ?? "sub-org-\(ms(now))",
            verificationToken: verificationToken, wallet: p.customWallet)
    }

    static func build(_ p: CreateSubOrgParams, verificationToken: String, now: Date) -> ProxyTSignupV2Body {
        ProxyTSignupV2Body(
            apiKeys: p.apiKeys, authenticators: p.authenticators,
            oauthProviders: p.oauthProviders.map { v1OauthProviderParamsV2(providerName: $0.providerName, oidcToken: $0.oidcToken) },
            userEmail: p.userEmail, userPhoneNumber: p.userPhoneNumber, userTag: p.userTag,
            userName: p.userName ?? p.userEmail ?? "user-\(ms(now))",
            organizationName: p.subOrgName ?? "sub-org-\(ms(now))",
            verificationToken: verificationToken, wallet: p.customWallet)
    }

    /// `JSON.stringify({signup: {apiKeys?, authenticators?, oauthProviders?, email?, phoneNumber?}, tokenId, type})`.
    /// sdk-js always passes the arrays (possibly empty), so they are always present.
    package static func clientSignatureMessage(
        tokenId: String, email: String?, phoneNumber: String?, apiKeys: [v1ApiKeyParamsV2],
        authenticators: [v1AuthenticatorParamsV2], oauthProviders: [v1OauthProviderParams]
    ) -> String {
        var signup: [String] = []
        signup.append("\"apiKeys\":" + jsonArray(apiKeys.map { k in
            var f: [(String, String)] = [("apiKeyName", k.apiKeyName), ("publicKey", k.publicKey), ("curveType", k.curveType.rawValue)]
            if let e = k.expirationSeconds { f.append(("expirationSeconds", e)) }
            return OrderedJSON.stringify(f)
        }))
        signup.append("\"authenticators\":" + jsonArray(authenticators.map { a in
            let head = "{\"authenticatorName\":\(OrderedJSON.quote(a.authenticatorName)),\"challenge\":\(OrderedJSON.quote(a.challenge))"
            // JSON.stringify drops an undefined `attestation`, so an absent one is omitted here too.
            guard let at = a.attestation else { return head + "}" }
            let att = "{\"credentialId\":\(OrderedJSON.quote(at.credentialId)),\"clientDataJson\":\(OrderedJSON.quote(at.clientDataJson)),\"attestationObject\":\(OrderedJSON.quote(at.attestationObject)),\"transports\":\(jsonArray(at.transports.map { OrderedJSON.quote($0.rawValue) }))}"
            return head + ",\"attestation\":\(att)}"
        }))
        signup.append("\"oauthProviders\":" + jsonArray(oauthProviders.map {
            OrderedJSON.stringify([("providerName", $0.providerName), ("oidcToken", $0.oidcToken)])
        }))
        if let email, !email.isEmpty { signup.append("\"email\":" + OrderedJSON.quote(email)) }
        if let phoneNumber, !phoneNumber.isEmpty { signup.append("\"phoneNumber\":" + OrderedJSON.quote(phoneNumber)) }
        return "{\"signup\":{\(signup.joined(separator: ","))},\"tokenId\":\(OrderedJSON.quote(tokenId)),\"type\":\"USAGE_TYPE_SIGNUP\"}"
    }

    /// `JSON.stringify({login: {publicKey}, tokenId, type: "USAGE_TYPE_LOGIN"})`
    /// (sdk-js `getClientSignatureMessageForLogin`, utils.ts:1511-1545).
    package static func loginClientSignatureMessage(tokenId: String, sessionPublicKey: String) -> String {
        "{\"login\":{\"publicKey\":\(OrderedJSON.quote(sessionPublicKey))},\"tokenId\":\(OrderedJSON.quote(tokenId)),\"type\":\"USAGE_TYPE_LOGIN\"}"
    }

    static func jsonArray(_ items: [String]) -> String { "[" + items.joined(separator: ",") + "]" }
}
