# Sessions and Refresh

How the SDK stores sessions, switches between them, keeps them fresh and where it keeps the keys.

## Overview

A session is a short-lived JWT issued by 0xkey for one user and organization, bound to a P-256 session key pair held on the device. Every API request the SDK makes for the signed-in user is stamped (`X-Stamp`) with that key. ``ZeroXKeySession`` is the decoded JWT:

- `userId`, `organizationId`, `sessionType`, `publicKey`, `token` (the JWT) and `sessionProfileId` (scoped sessions),
- `expiry` (the `exp` claim, seconds since epoch), ``ZeroXKeySession/isExpired(at:)`` and ``ZeroXKeySession/expirationSeconds(at:)``,
- ``ZeroXKeySession/verified(jwt:dangerouslyOverrideNotarizerPublicKey:at:)``, which decodes the JWT and checks the notarizer signature and the expiry, ``ZeroXKeySession/parse(jwt:)``, which only decodes the payload, and ``ZeroXKeySession/verifySignature(dangerouslyOverrideNotarizerPublicKey:)``, which only checks the signature.

``ZeroXKeyContext`` verifies every session JWT before it stores or activates it: after login, sign-up and refresh, in ``ZeroXKeyContext/storeSession(jwt:sessionKey:)`` and ``ZeroXKeyContext/setActiveSession(sessionKey:)``, and when ``ZeroXKeyContext/configure(_:)`` restores the stored session. The JWT must be signed by the notarizer key of ``ZeroXKeyConfig/trustAnchors`` (``ZeroXKeyTrustAnchors/productionNotarizerSignPublicKey`` by default) and must not be expired. Otherwise the call throws ``ZeroXKeyError/sessionJwtSignatureInvalid`` or ``ZeroXKeyError/sessionExpired`` and nothing is stored; a stored session that fails is not restored (``AuthState/unauthenticated``). Set ``ZeroXKeyConfig/TrustAnchors/dangerouslyOverrideNotarizerPublicKey`` only for a non-production 0xkey environment.

The lifetime that passkey login, OTP login and refresh request is resolved in the order the sdk-js wallet kits use:

1. the `expirationSeconds` argument of the call;
2. the session duration of your Auth Proxy configuration (Dashboard), read once per context with one `wallet_kit_config` request that ``ZeroXKeyContext/configure(_:)`` starts in the background (only when ``ZeroXKeyConfig/authProxyConfigId`` is set; a login that needs it waits for that same request; a failing request never blocks or fails a login or the restore of a stored session, falls back and is retried after a minute);
3. ``ZeroXKeyConfig/sessionExpirationSeconds``, which is `nil` by default;
4. `"900"`.

A value that is empty, blank, not an integer or not greater than zero (`"0"`, `"-5"`, `"abc"`) counts as unset at every level and the next one applies, so an `expirationSeconds` argument of `"0"` falls through to the Dashboard. Surrounding whitespace and a leading `+` are removed before the value is sent.

With an Auth Proxy configuration the Dashboard therefore decides, and passkey, OTP and refreshed sessions have the same lifetime. Set ``ZeroXKeyConfig/sessionExpirationSeconds`` for apps that run without an Auth Proxy configuration.

If your own backend issues sessions, create a key with ``ZeroXKeyContext/createKeyPair()``, have the backend issue a session for the returned public key, then call ``ZeroXKeyContext/storeSession(jwt:sessionKey:)``. The key pair must exist locally and the JWT must not be expired.

## Multiple sessions

Sessions are stored under a session key (a name, not a cryptographic key), by default ``ZeroXKeySessionKey/default``. Pass `sessionKey:` to a login method to keep several users signed in, then switch:

```swift
let ctx = ZeroXKeyContext.shared
let keys = try ctx.sessionKeys()                      // all stored sessions
let other = try ctx.storedSession(sessionKey: keys[1]) // inspect without activating
try ctx.setActiveSession(sessionKey: keys[1])          // switch
try ctx.clearSession(sessionKey: keys[0])              // delete one and its key pair
try ctx.clearAllSessions()                             // sign out everywhere
```

- ``ZeroXKeyContext/sessionKeys()``, ``ZeroXKeyContext/storedSession(sessionKey:)`` and ``ZeroXKeyContext/activeSessionKey()`` read the store.
- ``ZeroXKeyContext/setActiveSession(sessionKey:)`` throws ``ZeroXKeyError/noActiveSession`` for an unknown key and ``ZeroXKeyError/sessionExpired`` for an expired one. When the user changes, the published `user` and `wallets` are reset; call ``ZeroXKeyContext/refreshUser()`` and ``ZeroXKeyContext/refreshWallets()`` afterwards.
- ``ZeroXKeyContext/clearSession(sessionKey:)`` removes a session and deletes its key pair. ``ZeroXKeyContext/logout()`` clears the active session. ``ZeroXKeyContext/clearAllSessions()`` clears all of them.

## Refreshing a session

``ZeroXKeyContext/refreshSession(expirationSeconds:invalidateExisting:sessionKey:)`` re-issues the active session (or the stored one named by `sessionKey`) with a fresh key pair. It runs `stamp_login` stamped by that session's own key in its organization, stores the new JWT under the same session key, keeps the session profile, then deletes the old key pair. It returns the new JWT. Refreshing a non-active session key does not change the active session.

Calls that overlap (your own call, the refresh timer, the foreground check) share one request per session key: while a refresh of that session key is running, further calls wait for it and return its JWT or its error. The parameters of the running call apply, and the shared request is not cancelled with a caller.

If the session is logged out, replaced or switched while the request is in flight, the result is discarded (its new key pair is deleted) and the call throws ``ZeroXKeyError/sessionChanged``; the state after your change is kept.

## Automatic refresh

Configure it through ``ZeroXKeyConfig/AuthConfig``:

```swift
let config = ZeroXKeyConfig(
    authProxyConfigId: "<auth proxy config id>",
    rpId: "wallet.example.com",
    organizationId: "<parent organization id>",
    auth: ZeroXKeyConfig.AuthConfig(
        autoRefreshSession: true,        // default
        sessionRefreshLeadSeconds: 60))  // default
```

- With ``ZeroXKeyConfig/AuthConfig/autoRefreshSession`` on (the default), the SDK refreshes the active session ``ZeroXKeyConfig/AuthConfig/sessionRefreshLeadSeconds`` (default 60) before it expires.
- If refresh is off or fails, the session is cleared at expiry and ``ZeroXKeyContext/authState`` becomes ``AuthState/unauthenticated``.

### App foreground

Timers do not run while the process is suspended. When the app returns to the foreground (`UIApplication.willEnterForegroundNotification` on iOS, `NSApplication.didBecomeActiveNotification` on macOS) the SDK calls ``ZeroXKeyContext/checkSessionOnForeground()`` for you. It re-checks the active session:

- expired: the session is cleared (``ZeroXKeySessionEvent/expired(sessionKey:)``);
- less than the lead time left and auto refresh on: refreshed now;
- otherwise the timer is re-armed from the current clock.

Call it yourself if you manage the app lifecycle differently. ``ZeroXKeyContext/appForegroundNotification`` is the notification the SDK observes.

### Observing events

SwiftUI views observe `authState` and `session` as usual. To log or prompt "please sign in again", set ``ZeroXKeyContext/onSessionEvent``. It is called on the main actor, only for automatic lifecycle changes:

```swift
ZeroXKeyContext.shared.onSessionEvent = { event in
    switch event {
    case .refreshed(let session):
        print("refreshed, expires at \(session.expiry)")
    case .refreshFailed(let sessionKey, let error):
        // The current session stays valid until it expires.
        print("refresh of \(sessionKey) failed: \(error)")
    case .expired(let sessionKey):
        print("\(sessionKey) expired and was cleared")
    }
}
```

``ZeroXKeySessionEvent`` has three cases: ``ZeroXKeySessionEvent/refreshed(_:)``, ``ZeroXKeySessionEvent/refreshFailed(sessionKey:error:)`` and ``ZeroXKeySessionEvent/expired(sessionKey:)``. Manual calls to `refreshSession` throw instead of emitting events. A refresh that your own logout, `storeSession` or session switch made obsolete while it ran is discarded silently: it is not reported as `refreshFailed`. Automatic refreshes run per session slot, so a switch to another session never waits on, or is skipped because of, the refresh of the previous one.

## Where keys and sessions live

``ZeroXKeyConfig`` has two storage injection points.

**Session keys: ``ZeroXKeyConfig/keyManager``** (``ZeroXKeyKeyManager``). The default is ``SecureEnclaveKeyManager``:

- New P-256 session keys are created inside the Secure Enclave and are not exportable. Only an encrypted blob that is useless on another device is persisted.
- Where the Secure Enclave is unavailable (for example the Simulator) it falls back to a software key in the Keychain. Failures of an available Secure Enclave are propagated, not silently downgraded.
- Both backends are searched on lookup. ``SecureEnclaveKeyManager/isHardwareBacked(publicKey:)`` tells which one holds a key.
- ``SecureEnclaveAccessPolicy`` (`.none` by default, `.userPresence`, `.biometryAny`, `.biometryCurrentSet`) can require user verification for every signature. Since every request is a signature, choose that deliberately for session keys.
- Keys created by the previous default, ``KeychainKeyManager`` (service `io.0xkey.sdk.keys`), are still found for signing, listing and deletion, so stored sessions keep working without a new login. Nothing new is written there. Opt out with `SecureEnclaveKeyManager(legacyKeychainService: nil)`.

``KeychainKeyManager`` and ``InMemoryKeyManager`` remain available.

**Session JWTs: ``ZeroXKeyConfig/sessionStore``** (``ZeroXKeySessionStore``). The default is ``KeychainSessionStore``, so JWTs are kept in the Keychain and not in `UserDefaults`. ``InMemorySessionStore`` keeps them for the process lifetime only.

The Keychain implementations need an app host with the usual Keychain entitlements. A command-line `swift test` binary does not have them, so inject the in-memory implementations in unit tests.

## Risk: reading session private keys through the key manager

`ZeroXKeyContext.shared.config.keyManager` is public, and ``ZeroXKeyKeyManager/privateKey(forPublicKey:)`` returns the private key hex of software-backed keys (the Simulator fallback of ``SecureEnclaveKeyManager``, keys from the legacy ``KeychainKeyManager`` service, ``KeychainKeyManager`` and ``InMemoryKeyManager``). It returns `nil` for Secure Enclave keys, which cannot leave the hardware.

Whoever holds a session private key can stamp any API request as the user until the session expires: sign transactions, export wallets, add authenticators. Treat it like the session itself, only more permanent, because a refresh with the old key yields a new session:

- Do not read, log, copy, send or back up session private keys. The SDK never needs your app to touch them.
- Prefer ``SecureEnclaveKeyManager`` (the default) so that, on devices, there is nothing to export.
- Custom ``ZeroXKeyKeyManager`` implementations should return `nil` from `privateKey(forPublicKey:)` where possible and override ``ZeroXKeyKeyManager/stamper(forPublicKey:)`` instead.
- If a key may have leaked, clear the session with ``ZeroXKeyContext/clearSession(sessionKey:)`` and log in again with `invalidateExisting: true`.

Signing arbitrary bytes with the session key is the same risk in another form. It is therefore only available as `@_spi(Unsafe) unsafeSignWithSessionKey(_:)`; use ``ZeroXKeyContext/signMessage(signWith:addressFormat:message:encoding:hashFunction:addEthereumPrefix:)`` for wallet signatures.
