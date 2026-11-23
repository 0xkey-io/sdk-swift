# Authentication

Sign users in with passkeys, email or SMS codes, Sign in with Apple, or Google, Discord and X in an in-app browser.

## Overview

Every sign-in method creates a session key pair, obtains a session JWT from 0xkey, stores it and makes it the active session, which flips ``ZeroXKeyContext/authState`` to ``AuthState/authenticated``. The `loginWith…` / `signUpWith…` methods return the session JWT; the `handle…OAuth` methods and ``ZeroXKeyContext/completeOtp(otpId:otpCode:otpEncryptionTargetBundle:contact:otpType:publicKey:createSubOrgParams:invalidateExisting:sessionKey:)`` return an ``AuthResult`` that says whether the user logged in or signed up (``AuthAction``).

All methods accept a `sessionKey` to store the session under, defaulting to ``ZeroXKeySessionKey/default``. See <doc:SessionsAndRefresh>.

OTP, OAuth and passkey sign-up go through the Auth Proxy, so set ``ZeroXKeyConfig/authProxyConfigId``. Without it those methods throw ``ZeroXKeyError/missingAuthProxyConfiguration``. Methods that create a sub-organization at sign-up take ``CreateSubOrgParams``, merged over the defaults in ``ZeroXKeyConfig/AuthConfig/createSuborgParams``.

## Passkeys

Set ``ZeroXKeyConfig/rpId`` (and ``ZeroXKeyConfig/rpName``) and ``ZeroXKeyConfig/organizationId``, and complete the Associated Domains setup from <doc:GettingStarted>. The RP ID is passed to AuthenticationServices unchanged, so any domain in the app's `webcredentials:` entitlements works on the device, for example `wallet.example.com` or `login.example.org`. The SDK never defaults it to a 0xkey domain.

```swift
let ctx = ZeroXKeyContext.shared

// Existing user.
try await ctx.loginWithPasskey(anchor: window)

// New user: creates a passkey and a sub-organization.
try await ctx.signUpWithPasskey(anchor: window, passkeyDisplayName: "Alice")

// Signed-in user: register one more passkey, returns the authenticator ID.
let authenticatorId = try await ctx.addPasskey(anchor: window, name: "Alice's iPhone")
```

- ``ZeroXKeyContext/loginWithPasskey(anchor:organizationId:expirationSeconds:sessionKey:)`` stamps `stamp_login` with `X-Stamp-Webauthn` against `config.organizationId` (or the `organizationId` argument).
- ``ZeroXKeyContext/signUpWithPasskey(anchor:passkeyDisplayName:createSubOrgParams:expirationSeconds:sessionKey:)`` creates the passkey, signs up a sub-organization with it, then logs in.
- ``ZeroXKeyContext/addPasskey(anchor:name:userId:organizationId:)`` needs an active session. `name` must be 1 to 64 letters, digits, spaces or `_ - : / .`.

The `anchor:` overloads use the platform authenticator (`PlatformPasskeyProvider`). The overloads without `anchor:` use the providers you inject through ``ZeroXKeyConfig/passkeyAssertionProvider`` and ``ZeroXKeyConfig/passkeyRegistrationProvider`` (tests, custom UI) and throw ``ZeroXKeyError/missingPasskeyProvider`` if there are none.

Whether the 0xkey gateway accepts a given RP ID is a server-side policy. A rejected RP ID surfaces as a `ZeroXKeyRequestError` with `reason == .webAuthnRpIdNotAllowed` (see [Errors](#Errors)).

## Email and SMS one-time codes

`initOtp` sends the code. `completeOtp` verifies it and then logs in, or signs up if the contact has no sub-organization yet.

```swift
let ctx = ZeroXKeyContext.shared
let otp = try await ctx.initOtp(contact: "alice@example.com", otpType: .email)

// Show a code entry screen, then:
let result = try await ctx.completeOtp(
    otpId: otp.otpId, otpCode: code,
    otpEncryptionTargetBundle: otp.otpEncryptionTargetBundle,
    contact: "alice@example.com", otpType: .email)
// result.action is .login or .signup
```

- ``ZeroXKeyContext/initOtp(contact:otpType:captchaToken:)`` returns an ``InitOtpResult``. The code is later encrypted to its `otpEncryptionTargetBundle` (HPKE, `0xkey_hpke`), so pass both values back unchanged. The SDK first checks that the bundle is signed by the 0xkey signer enclave (``ZeroXKeyConfig/trustAnchors``) and throws a ``ZeroXKeyCryptoError`` otherwise, before the code leaves the device. ``OtpType`` is `.email` or `.sms` (E.164 phone number as `contact`).
- ``ZeroXKeyContext/verifyOtp(otpId:otpCode:otpEncryptionTargetBundle:contact:otpType:publicKey:)`` verifies only and returns a ``VerifyOtpResult``. `subOrganizationId` is empty when the contact is new. `publicKey` is a session key from ``ZeroXKeyContext/createKeyPair()``.
- ``ZeroXKeyContext/loginWithOtp(verificationToken:organizationId:invalidateExisting:expirationSeconds:sessionKey:)`` and ``ZeroXKeyContext/signUpWithOtp(verificationToken:contact:otpType:createSubOrgParams:invalidateExisting:sessionKey:captchaToken:)`` take the verification token from `verifyOtp`. Call them yourself when you need the two steps apart.

If the gateway rejects the attested `stamp_login` used by `loginWithOtp` because the server cannot handle attested logins at all, and an Auth Proxy config is set, the SDK falls back to the Auth Proxy `otp_login_v2` route (same rule as sdk-js `isAttestedLoginUnavailable`). The session lifetime is then the Auth Proxy configuration's, not `expirationSeconds`. The fallback applies to:

- a plain-text gateway answer with HTTP 401, 404, 501 or 503;
- a structured error whose `reason` contains `ATTESTED_STAMP_NOT_ENABLED`;
- any other structured error with HTTP 404, 501 or 503 that carries no `ATTESTED_*` reason.

It never applies to HTTP 403 (it can be an MFA requirement), to an error without HTTP status, to a `reason` starting with `ATTESTED_LOGIN_`, or to any other `ATTESTED_*` reason (the server checked the stamp and rejected it); the original error is thrown. Scoped logins never fall back.

### Scoped recovery (experimental)

The scoped-recovery flow (OTP login with a session profile, held by MFA, approved by a second factor, then resumed) is not supported by the 0xkey servers yet: the enclave rejects an attested `stamp_login` that carries a `sessionProfileId`, and the Auth Proxy rejects OTP logins with a profile. The client side exists for evaluation only behind `@_spi(Experimental) import ZeroXKey` (`beginOtpLogin`, `approvePendingLogin`, `resumeOtpLogin`) and is not part of the supported API.

## Sign in with Apple

Enable the "Sign in with Apple" capability, then:

```swift
let result = try await ZeroXKeyContext.shared.handleAppleOAuth(anchor: window)
```

``ZeroXKeyContext/handleAppleOAuth(anchor:createSubOrgParams:sessionKey:)`` runs the native `ASAuthorizationAppleIDProvider` flow. The ID token carries a nonce derived from the new session public key (``ZeroXKeyContext/oidcNonce(forPublicKey:)``) and the provider is registered as `apple`. To supply the token yourself (Google Sign-In, another OIDC provider, a custom UI), implement ``OIDCTokenProvider`` and call ``ZeroXKeyContext/handleAppleOAuth(tokenProvider:createSubOrgParams:sessionKey:)``, or use ``ZeroXKeyContext/completeOAuth(oidcToken:publicKey:providerName:createSubOrgParams:invalidateExisting:sessionKey:captchaToken:)`` with a token whose `nonce` claim is `oidcNonce(forPublicKey: publicKey)`.

## Browser OAuth

Google runs through 0xkey's hosted pages by default, as in the Kotlin and JS SDKs: `ASWebAuthenticationSession` opens `https://oauth-origin.0xkey.io`, Google signs the user in with your *web* client ID, and `https://oauth-redirect.0xkey.io` returns the ID token to `<appScheme>://`. The nonce of that ID token is bound to the new session public key (``ZeroXKeyContext/oidcNonce(forPublicKey:)``). Only a call that passes an explicit `client:` (a Google *iOS* client) takes the installed-app Authorization Code + PKCE path instead.

Discord and X always run an installed-app Authorization Code flow with PKCE. Their redirect URI is owned by your app and must use a custom URL scheme that you register with the provider; `http` and `https` redirect URIs are rejected with ``ZeroXKeyOAuthError/invalidRedirectUri(_:)``.

Set up the clients in the configuration:

```swift
let config = ZeroXKeyConfig(
    authProxyConfigId: "<auth proxy config id>",
    rpId: "wallet.example.com",
    organizationId: "<parent organization id>",
    auth: ZeroXKeyConfig.AuthConfig(oauth: ZeroXKeyConfig.OAuthConfig(
        googleWebClientId: "<id>.apps.googleusercontent.com",   // or set oauthClientIds.google in the Dashboard
        discord: OAuthClient(clientId: "<discord client id>", redirectUri: "exampleapp://oauth"),
        x: OAuthClient(clientId: "<x client id>", redirectUri: "exampleapp://oauth"),
        appScheme: "exampleapp")))                               // registered as a URL type of the app
```

Register `https://oauth-redirect.0xkey.io/?scheme=exampleapp` as an authorized redirect URI of the Google web client. Then start a flow:

```swift
let ctx = ZeroXKeyContext.shared
let result = try await ctx.handleGoogleOAuth(anchor: window)
// also: handleDiscordOAuth(anchor:), handleXOAuth(anchor:)
// Google with an iOS client (PKCE): handleGoogleOAuth(anchor: window, client: OAuthClient(
//     clientId: "<id>.apps.googleusercontent.com", redirectUri: "com.googleusercontent.apps.<id>:/oauth2redirect"))
```

- Google web client ID, in this order: ``ZeroXKeyConfig/OAuthConfig/googleWebClientId``, then the Dashboard's `oauthClientIds.google` (read from the Auth Proxy's `wallet_kit_config`). Without either, and without `client:`, ``ZeroXKeyOAuthError/missingClient(_:)`` is thrown; without ``ZeroXKeyConfig/OAuthConfig/appScheme``, ``ZeroXKeyOAuthError/missingAppScheme``. ``ZeroXKeyConfig/OAuthConfig/redirectUri`` and ``ZeroXKeyConfig/OAuthConfig/originUri`` override the hosted pages (`https` only).
- ``ZeroXKeyContext/handleDiscordOAuth(anchor:client:createSubOrgParams:sessionKey:)`` and ``ZeroXKeyContext/handleXOAuth(anchor:client:createSubOrgParams:sessionKey:)`` use the client you pass as `client:`, else the one from ``ZeroXKeyConfig/AuthConfig/oauth``, else the Dashboard's `oauthClientIds` entry together with its `oauthRedirectUrl` (the redirect must use a custom URL scheme your app owns). With no client at all they throw ``ZeroXKeyOAuthError/missingClient(_:)``.
- The hosted callback is validated strictly (app scheme, a single matching `state`, a single non-empty `id_token`, no `error`, no security fields in the fragment); the PKCE callback likewise (exact redirect base, a single matching `state`, a single `code`). A user who dismisses the sheet gets ``ZeroXKeyOAuthError/canceled``.
- On the PKCE path Google's code is exchanged at Google's token endpoint; Discord and X codes are exchanged through the Auth Proxy.
- To intercept the token before logging in, call ``ZeroXKeyContext/authorizeOAuth(_:client:authenticator:)`` (returns an ``OAuthSuccess``) and then `completeOAuth`. ``ZeroXKeyContext/handleOAuth(_:client:authenticator:createSubOrgParams:sessionKey:)`` does both with any ``WebAuthenticator``; ``ASWebAuthenticator`` is the `ASWebAuthenticationSession` implementation.

## Errors

- ``ZeroXKeyError`` covers SDK-level problems: ``ZeroXKeyError/notConfigured``, ``ZeroXKeyError/missingAuthProxyConfiguration``, ``ZeroXKeyError/missingRpId``, ``ZeroXKeyError/missingOrganizationId``, ``ZeroXKeyError/missingPasskeyProvider``, ``ZeroXKeyError/noActiveSession``, ``ZeroXKeyError/sessionExpired`` and others.
- ``ZeroXKeyOAuthError`` covers the browser OAuth flows.
- API and gateway failures surface unchanged from `ZeroXKeyHttp`:
  - `ZeroXKeyRequestError`: a non-2xx response, as gRPC status JSON or plain text. Its `reason` is `.webAuthnRpIdNotAllowed` when the gateway does not accept your RP ID, `.webAuthnOriginNotAllowed` for an origin it does not accept, or `.other(_:)` for any other `ErrorInfo` reason. `isUnauthenticated`, `httpStatus` and `message` help with the rest.
  - `ZeroXKeyActivityError`: an activity that did not complete (`failed`, `rejected`, `consensusNeeded`, `authenticatorsNeeded(activityId:mfaStatuses:)`, `pollingTimedOut`).

```swift
do {
    try await ZeroXKeyContext.shared.loginWithPasskey(anchor: window)
} catch let error as ZeroXKeyRequestError where error.reason == .webAuthnRpIdNotAllowed {
    // The gateway does not accept config.rpId for this organization.
} catch ZeroXKeyOAuthError.canceled {
    // The user dismissed the sheet.
}
```
