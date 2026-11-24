# 0xkey Swift SDK

Swift Package for building embedded wallets on 0xkey: passkey and email OTP sign-in, sessions,
wallets, per-transaction passkey signing, and wallet import that keeps existing addresses.

- iOS 17+ / macOS 14+, Xcode 16+ (Swift 6 language mode, strict concurrency)
- No third-party dependencies
- Current version: **0.1.0** ([CHANGELOG](CHANGELOG.md))

| Product | Purpose |
|---|---|
| `ZeroXKey` | `ZeroXKeyContext` (`@MainActor`, `ObservableObject`): sign-in, sessions, wallets, signing, import / export. `import ZeroXKey` also brings in the modules below. |
| `ZeroXKeyHttp` | `ZeroXKeyClient`: every public API endpoint and Auth Proxy route, activity polling, structured errors |
| `ZeroXKeyPasskeys` | `PlatformPasskeyProvider`, `PasskeyStamper` (AuthenticationServices) |
| `ZeroXKeyStamper` | API key, WebAuthn and attested request stamps; `Stamper` protocol |
| `ZeroXKeyCrypto` | P-256, HPKE, export / import / OTP bundles, 0xkey trust anchors |
| `ZeroXKeyEncoding` | hex, base64url, base58 / base58check |

Most apps only need the `ZeroXKey` product.

## Installation

**Xcode.** *File → Add Package Dependencies…*, enter `https://github.com/0xkey-io/sdk-swift.git`
and choose *Up to Next Minor Version* from `0.1.0`.

**Package.swift.**

```swift
dependencies: [
    .package(url: "https://github.com/0xkey-io/sdk-swift.git", .upToNextMinor(from: "0.1.0")),
],
targets: [
    .target(name: "App", dependencies: [.product(name: "ZeroXKey", package: "sdk-swift")]),
]
```

`git@github.com:0xkey-io/sdk-swift.git` works as well if your machine uses SSH keys for GitHub.

The repository is public, so SwiftPM resolves it on any machine (including CI) without GitHub
credentials.

## App setup

- **Passkeys.** Add the Associated Domains entitlement `webcredentials:<rpId>` for the relying party
  ID you configure, and serve `https://<rpId>/.well-known/apple-app-site-association` listing
  `<TeamID>.<bundle ID>` under `webcredentials.apps`. Your RP ID must also be enabled for your
  organization on the 0xkey side; ask your 0xkey contact if passkey calls fail with
  `ZeroXKeyRequestError.reason == .webAuthnRpIdNotAllowed`.
- **Email / SMS OTP, OAuth and passkey sign-up** go through the Auth Proxy: create an Auth Proxy
  configuration in the 0xkey Dashboard and pass its ID as `authProxyConfigId`.
- **Sign in with Apple** (optional): the "Sign in with Apple" capability.
- **Google** (optional): a URL scheme for your app (`config.auth.oauth.appScheme`), a Google *web*
  client ID (in the Dashboard or `config.auth.oauth.googleWebClientId`), and
  `https://oauth-redirect.0xkey.io/?scheme=<appScheme>` as an authorized redirect URI of that client.

## Configure

Configure once at app start, before using `ZeroXKeyContext.shared`:

```swift
import ZeroXKey

ZeroXKeyContext.configure(ZeroXKeyConfig(
    authProxyConfigId: "<auth proxy config id>",   // 0xkey Dashboard
    rpId: "wallet.example.com",                    // your passkey relying party ID
    rpName: "Example Wallet",
    organizationId: "<parent organization id>"))

let ctx = ZeroXKeyContext.shared
```

`apiUrl` and `authProxyUrl` default to the 0xkey production hosts. Without `authProxyConfigId` the
OTP, OAuth and passkey sign-up methods throw `ZeroXKeyError.missingAuthProxyConfiguration` (use
this mode when your own backend issues sessions: `createKeyPair()` + `storeSession(jwt:)`).

`apiUrl` and `authProxyUrl` must be `https`; any other URL makes every call throw
`ZeroXKeyHttpError.insecureURL` before a request leaves the device. For a server on your development
machine, set `config.transportSecurity = .dangerouslyAllowInsecureLoopback`, which additionally
accepts `http` to `localhost`, `127.0.0.0/8` and `::1` (and nothing else). This check is the SDK's own
and does not depend on App Transport Security: relaxing ATS in `Info.plist` does not let `http`
through, and ATS still applies to the loopback URLs the opt-in accepts (Apple exempts IP addresses
and unqualified host names such as `localhost` from ATS).

## Sign in with a passkey

```swift
// New user: creates a passkey and a sub-organization for the user, then signs in.
try await ctx.signUpWithPasskey(anchor: window, passkeyDisplayName: "Alice")

// Returning user.
try await ctx.loginWithPasskey(anchor: window)

// Signed-in user: register another passkey (returns the authenticator ID).
let authenticatorId = try await ctx.addPasskey(anchor: window, name: "Alice's iPad")
```

`anchor` is the `ASPresentationAnchor` (usually the key window) that shows the system passkey sheet.

## Sign in with an email code (OTP)

```swift
let otp = try await ctx.initOtp(contact: "alice@example.com", otpType: .email)
// ... the user types the code from the email ...
let result = try await ctx.completeOtp(
    otpId: otp.otpId, otpCode: code,
    otpEncryptionTargetBundle: otp.otpEncryptionTargetBundle,
    contact: "alice@example.com", otpType: .email)
// result.action is .login for an existing user, .signup for a new one
```

`otpType: .sms` works the same way with a phone number. Code length and other OTP settings come
from the Dashboard (`ctx.client?.proxyGetWalletKitConfig()` returns them before sign-in).

## Wallets

```swift
let wallets = try await ctx.refreshWallets()          // also published as ctx.wallets
let walletId = try await ctx.createWallet(walletName: "Main")   // default accounts: Ethereum + Solana
```

## Signing

### With the session (no prompt)

After sign-in, requests are stamped with the session key held in the Secure Enclave:

```swift
let signed = try await ctx.signTransaction(
    signWith: address, unsignedTransaction: unsignedHex, type: .TRANSACTION_TYPE_ETHEREUM)

let sig = try await ctx.signRawPayload(
    signWith: address, payload: "0x…32-byte digest…",
    encoding: .PAYLOAD_ENCODING_HEXADECIMAL, hashFunction: .HASH_FUNCTION_NO_OP)   // sig.r, sig.s, sig.v

let message = try await ctx.signMessage(
    signWith: address, addressFormat: .ADDRESS_FORMAT_ETHEREUM, message: "hello")  // EIP-191 for Ethereum
```

### With a passkey for every transaction

To require the user's passkey (Face ID / Touch ID) for each signature, stamp the signing request
with a `PasskeyStamper` instead of the session key. The user still needs a session for reads; the
signing request itself is authorized by the passkey:

```swift
guard let session = ctx.session, let client = ctx.client else { throw ZeroXKeyError.noActiveSession }
let passkeyClient = client
    .with(stamper: PasskeyStamper(rpId: "wallet.example.com", presentationAnchor: { window }))
    .with(organizationId: session.organizationId)

// Transaction: unsigned transaction as hex in, signed transaction as hex out.
let tx = try await passkeyClient.signTransaction(TSignTransactionBody(
    signWith: address, unsignedTransaction: unsignedHex, type: .TRANSACTION_TYPE_ETHEREUM))
let signedHex = tx.signedTransaction

// Raw payload (for example an EIP-712 digest).
let raw = try await passkeyClient.signRawPayload(TSignRawPayloadBody(
    signWith: address, payload: digestHex,
    encoding: .PAYLOAD_ENCODING_HEXADECIMAL, hashFunction: .HASH_FUNCTION_NO_OP))
// raw.r, raw.s, raw.v
```

Each call shows the system passkey sheet once. `allowCredentials:` on `PasskeyStamper` limits the
prompt to specific credential IDs.

### Transaction format and broadcasting

`signTransaction` takes the **unsigned transaction as hex** and does not build or serialize
transactions. For Ethereum (`.TRANSACTION_TYPE_ETHEREUM`) pass an EIP-1559 (type 2) transaction,
`0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])`.
Broadcast the result yourself (`eth_sendRawTransaction`), with
`signAndSendTransaction(signWith:unsignedTransaction:type:rpcUrl:)` through your RPC, or let 0xkey
build, sign and broadcast:

```swift
let statusId = try await ctx.ethSendTransaction(TEthSendTransactionBody(
    from: address, caip2: "eip155:8453", to: recipient, sponsor: true, value: "1000"))
let status = try await ctx.pollTransactionStatus(sendTransactionStatusId: statusId)   // status.eth?.txHash
```

## Import an existing wallet (same addresses)

Importing the mnemonic or private key keeps the addresses the user already has. The secret is
encrypted on the device to the 0xkey enclave (HPKE) and is never sent in plain text:

```swift
// Mnemonic → HD wallet. Pass the accounts (paths / address formats) you used before to get the
// same addresses; the default is the first Ethereum and Solana account.
let walletId = try await ctx.importWallet(walletName: "Imported", mnemonic: mnemonic)

// Raw private key.
let privateKeyId = try await ctx.importPrivateKey(
    privateKey: privateKeyHex, privateKeyName: "Imported key", keyFormat: .hexadecimal,
    curve: .CURVE_SECP256K1, addressFormats: [.ADDRESS_FORMAT_ETHEREUM])
```

Both need a signed-in user. `exportWallet(walletId:)` and `exportWalletAccount(address:)` do the
reverse; the export bundle is verified against the 0xkey signer key before it is decrypted.

## Sessions

- State: observe `ctx.authState` (`.loading`, `.authenticated`, `.unauthenticated`), `ctx.session`,
  `ctx.user` and `ctx.wallets` from SwiftUI. Do not use `ctx.client != nil` to test for sign-in:
  before sign-in `client` is an unauthenticated Auth Proxy client.
- Storage: the session key lives in the Secure Enclave (`SecureEnclaveKeyManager`), the session
  JWT in the Keychain. Sessions survive app restarts.
- Lifetime: the `expirationSeconds` argument of a sign-in call, else the session duration set in
  the Dashboard, else `ZeroXKeyConfig.sessionExpirationSeconds`, else 900 seconds.
- Refresh: sessions are refreshed automatically shortly before they expire
  (`config.auth.autoRefreshSession`, `sessionRefreshLeadSeconds`); `refreshSession()` refreshes on
  demand. `ctx.onSessionEvent` reports `.refreshed`, `.refreshFailed` and `.expired`.
- Sign-out: `logout()` (active session) or `clearSession(sessionKey:)`. Several sessions can be
  kept side by side with `sessionKey:`; switch with `setActiveSession(sessionKey:)`.

## Errors

| Error | When |
|---|---|
| `ZeroXKeyError` | SDK-level: `.notConfigured`, `.missingAuthProxyConfiguration`, `.noActiveSession`, `.sessionExpired`, `.missingRpId`, `.missingOrganizationId`, `.invalidArgument`, `.transactionFailed`, … |
| `ZeroXKeyRequestError` | The server rejected the request: `httpStatus`, `code`, `message`, `details`, `reason` (for example `.webAuthnRpIdNotAllowed`, `.webAuthnOriginNotAllowed`) |
| `ZeroXKeyActivityError` | The activity did not complete: `.failed`, `.rejected`, `.consensusNeeded(activityId:fingerprint:)`, `.authenticatorsNeeded(activityId:mfaStatuses:)` (MFA required), `.pollingTimedOut` |
| `ZeroXKeyHttpError` | Transport or decoding problems |
| `ZeroXKeyOAuthError` | OAuth flow problems (cancelled, missing app scheme, …) |

An activity that is not `COMPLETED` is always thrown, never returned as success. After
`ZeroXKeyHttpError.decodingFailed` on a state-changing call, check the activity before retrying:
it may have completed on the server.

```swift
do {
    try await ctx.loginWithPasskey(anchor: window)
} catch let error as ZeroXKeyActivityError {
    if case .authenticatorsNeeded = error { /* ask for the second factor */ }
} catch let error as ZeroXKeyRequestError {
    print(error.httpStatus, error.message)
}
```

## Versions and compatibility

- Releases are Git tags with semantic versions (`0.1.0`). While the major version is 0, a minor
  release (`0.2.0`) may contain breaking changes, so depend on `.upToNextMinor(from:)`; patch
  releases are compatible. Every change is listed in [CHANGELOG.md](CHANGELOG.md).
- 0.1.0 targets the current 0xkey public API and Auth Proxy. It works side by side with the 0xkey
  JS, Kotlin and Flutter SDKs on the same organization: wire formats, stamps and HPKE parameters
  are the same.
- Requirements: iOS 17+ / macOS 14+, Xcode 16+.

## More

- DocC articles in `Sources/ZeroXKey/ZeroXKey.docc` (getting started, authentication, sessions,
  signing and transactions). Build them with
  `xcodebuild docbuild -scheme ZeroXKey -destination 'generic/platform=macOS'`.
- Example app: [Examples/wallet-demo](Examples/wallet-demo) (put your IDs in
  `Config/Local.xcconfig`, see `Local.xcconfig.example`).

## License

Apache License 2.0, see [LICENSE](LICENSE).
