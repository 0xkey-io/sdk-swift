# ``ZeroXKey``

High-level, observable entry point to 0xkey for iOS and macOS apps: authentication, sessions, wallets, signing and transactions.

## Overview

`ZeroXKey` is the umbrella module of the 0xkey Swift SDK. ``ZeroXKeyContext`` is a `@MainActor`, `ObservableObject` that owns the session state your UI observes (`authState`, `session`, `user`, `wallets`) and exposes the flows an app needs:

- passkey, email / SMS OTP, Sign in with Apple and browser OAuth (Google, Discord, X) login and sign-up,
- multiple sessions with automatic refresh,
- wallet creation, message / raw payload / transaction signing, and transaction sending,
- wallet export and import.

`import ZeroXKey` also re-exports the lower-level modules, so the generated API types (`v1*`, `T*Body`), `ZeroXKeyClient`, stampers and crypto helpers are available without extra imports:

| Module | Purpose |
|---|---|
| `ZeroXKeyEncoding` | Hex, base64url, base58 and a `JSON.stringify`-compatible writer. |
| `ZeroXKeyCrypto` | P-256 helpers, HPKE (`0xkey_hpke`), credential / export / import / OTP bundles, trust anchors. |
| `ZeroXKeyStamper` | `X-Stamp`, `X-Stamp-Webauthn` and `X-Stamp-Attested` stampers. |
| `ZeroXKeyHttp` | `ZeroXKeyClient`, the generated public API and Auth Proxy methods, structured errors. |
| `ZeroXKeyPasskeys` | `PlatformPasskeyProvider` and `PasskeyStamper` on top of AuthenticationServices. |
| `ZeroXKey` | This module. |

The SDK supports iOS 17+ and macOS 14+ and has no third-party dependencies.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:Authentication>
- <doc:SessionsAndRefresh>
- <doc:SigningAndTransactions>

### Context and configuration

- ``ZeroXKeyContext``
- ``ZeroXKeyConfig``
- ``ZeroXKeyConfig/AuthConfig``
- ``ZeroXKeyConfig/OAuthConfig``
- ``CreateSubOrgParams``

### Authentication state and results

- ``AuthState``
- ``AuthAction``
- ``AuthResult``
- ``OtpType``
- ``InitOtpResult``
- ``VerifyOtpResult``

### Browser OAuth and Sign in with Apple

- ``OAuthClient``
- ``OAuthWebProvider``
- ``OAuthSuccess``
- ``WebAuthenticator``
- ``ASWebAuthenticator``
- ``OIDCTokenProvider``
- ``AppleIDTokenProvider``
- ``ZeroXKeyOAuthError``

### Sessions

- ``ZeroXKeySession``
- ``ZeroXKeySessionEvent``
- ``ZeroXKeySessionKey``
- ``VerificationTokenClaims``

### Key and session storage

- ``ZeroXKeyKeyManager``
- ``SecureEnclaveKeyManager``
- ``SecureEnclaveAccessPolicy``
- ``KeychainKeyManager``
- ``InMemoryKeyManager``
- ``ZeroXKeySessionStore``
- ``KeychainSessionStore``
- ``InMemorySessionStore``

### Wallets and signing

- ``ZeroXKeyWallet``
- ``SignRawPayloadResult``
- ``AddressFormatDefaults``

### Errors

- ``ZeroXKeyError``
