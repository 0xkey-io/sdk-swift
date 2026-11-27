# Changelog

## 0.2.0 (2026-11-27)

Contains breaking changes to generated types (0.x: minor release) and a change in how error bodies
are parsed. Depend on `.upToNextMinor(from: "0.2.0")` and read the two sections below before updating.

### Breaking: removed generated types

The generated models were regenerated from the cleaned public OpenAPI document. These public
declarations no longer exist:

- `v1ImportedRootAuthenticatorParams` and the property `CreateOrganizationIntentV2.importedRootAuthenticator`
  (with its coding key); the field is no longer in the public OpenAPI document.
- `v1ValidateSessionRequest` and `v1ValidateSessionResponse`.

Code that references a removed name stops compiling. The SDK's own sign-in, session, wallet and
signing APIs do not use them.

### Changed: error parsing

- `ZeroXKeyRequestError.parse` now reads Auth Proxy error bodies of the form
  `{"error":"…","code":"OIDC_…"}`:
  - `message` falls back to `error` when it is missing or empty; `message` still wins when present.
  - A string `code` that is not a plain number is kept in the new `errorCode` property
    (sdk-js and sdk-kotlin use the same name). Only strings of digits count as numbers: `"7"` is the
    gRPC code 7, while `"+7"` and `"-7"` become `errorCode`.
  - `reason` has a new value for these bodies: when the `details` carry no `ErrorInfo` reason, a string
    `code` is reported as `reason` — `.webAuthnRpIdNotAllowed` for `WEBAUTHN_RP_ID_NOT_ALLOWED`,
    `.webAuthnOriginNotAllowed` for `WEBAUTHN_ORIGIN_NOT_ALLOWED`, otherwise `.other(code)`. Before, such
    bodies had `reason == nil`. `ErrorInfo` reasons in `details` still take precedence.
  - `code` stays the gRPC code derived from the HTTP status, and `description` shows the string code.
  - `ZeroXKeyRequestError.init` gains an optional trailing `errorCode` parameter, so existing callers
    still compile.

## 0.1.0 (2026-11-23)

First release. Products `ZeroXKey`, `ZeroXKeyHttp`, `ZeroXKeyPasskeys`, `ZeroXKeyStamper`,
`ZeroXKeyCrypto` and `ZeroXKeyEncoding`; iOS 17+ / macOS 14+, Swift 6, no third-party dependencies.

- Sign-in: passkeys (sign-up, login, adding a passkey to a signed-in user; any tenant RP ID), email
  and SMS OTP, Sign in with Apple, Google through 0xkey's hosted pages (web client ID, or an iOS client
  with PKCE), Discord and X (PKCE), and any OIDC token via `completeOAuth(oidcToken:publicKey:)`.
- Sessions: session keys in the Secure Enclave, session JWTs in the Keychain, several sessions side by
  side, automatic refresh (also when the app returns to the foreground) with `onSessionEvent`.
  Session lifetime: `expirationSeconds` argument, else the Dashboard setting, else
  `ZeroXKeyConfig.sessionExpirationSeconds`, else 900 seconds.
- Wallets: list, create, derive accounts; export (decrypted on the device, bundle verified against
  the 0xkey signer key) and import of mnemonics and private keys (`importWallet`, `importPrivateKey`),
  which keeps existing addresses.
- Signing: `signTransaction`, `signRawPayload`, `signMessage` with the session key, or with a
  `PasskeyStamper` per request; transaction sending through 0xkey (`ethSendTransaction` and status
  polling) or your own RPC (`signAndSendTransaction`, `https` only, plus `http` to localhost).
- `ZeroXKeyClient`: every public API endpoint and Auth Proxy route, request stamping for later
  submission, activity polling. Activities that do not complete are thrown as
  `ZeroXKeyActivityError` (`failed`, `rejected`, `consensusNeeded`, `authenticatorsNeeded` with MFA
  status, `pollingTimedOut`); server errors as `ZeroXKeyRequestError`.
- Verification tokens are redacted in `description`, `debugDescription` and `dump`.
- Experimental, behind `@_spi(Experimental) import ZeroXKey`: scoped session recovery (OTP login with
  a session profile, MFA approval, resume). Not yet supported by the 0xkey servers; the API may change.

### Security

- `verifyOtp` / `completeOtp` and `encryptOtpAttemptBundle` verify the OTP encryption target bundle
  before encrypting the code: `enclaveQuorumPublic` must be the 0xkey signer key
  (`ZeroXKeyTrustAnchors.productionSignerSignPublicKey`) and `dataSignature` must verify over `data`.
  A bundle that fails throws `ZeroXKeyCryptoError` (`signerKeyMismatch`, `enclaveSignatureInvalid`,
  `invalidBundle`) and nothing is sent.
- New `ZeroXKeyConfig.trustAnchors` (`.production` by default) with
  `dangerouslyOverrideSignerPublicKey` for non-production enclaves. It applies to OTP and to export /
  import calls that pass no key of their own. There is no option to skip verification.
- New overload `encryptOtpAttemptBundle(otpCode:publicKey:otpEncryptionTargetBundle:dangerouslyOverrideSignerPublicKey:)`.
- Session JWTs are verified before they are stored or activated: after passkey / OTP / OAuth login
  and sign-up, `refreshSession`, `storeSession`, `setActiveSession` and when `configure` restores the
  stored session. The signature must be the notarizer's (`ZeroXKeyTrustAnchors.productionNotarizerSignPublicKey`,
  or `ZeroXKeyConfig.trustAnchors.dangerouslyOverrideNotarizerPublicKey`) and `exp` must lie ahead;
  otherwise the call throws the new `ZeroXKeyError.sessionJwtSignatureInvalid` or
  `ZeroXKeyError.sessionExpired`, nothing is stored, and a stored session that fails is not restored.
  sdk-js only decodes the JWT.
- New `ZeroXKeySession.verified(jwt:dangerouslyOverrideNotarizerPublicKey:at:)`: decode, signature
  and expiry check in one call, for JWTs your backend hands to the app.
- `apiUrl` and `authProxyUrl` must be `https`, and `ZeroXKeyClient` checks every request URL: other
  URLs throw the new `ZeroXKeyHttpError.insecureURL` before anything is sent. The new
  `ZeroXKeyTransportSecurity` (`ZeroXKeyConfig.transportSecurity`, `ZeroXKeyClient.transportSecurity`,
  new `ZeroXKeyClient.init(…, transportSecurity:)`) defaults to `.requireHTTPS`;
  `.dangerouslyAllowInsecureLoopback` additionally accepts `http` to `localhost`, `127.0.0.0/8` and
  `::1` without user name or password, for local development. The `signAndSendTransaction` RPC URL
  check uses the same loopback rule (now also `127.0.0.0/8`; `http` URLs with a user name or password
  are refused).
- Export / import bundles whose `data`, `dataSignature` or `enclaveQuorumPublic` is empty or not hex
  now throw `ZeroXKeyCryptoError.invalidBundle` instead of `ZeroXKeyEncodingError`.
