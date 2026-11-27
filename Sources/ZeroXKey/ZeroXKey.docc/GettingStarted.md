# Getting Started

Add the SDK, prepare your app for passkeys, configure ``ZeroXKeyContext`` and observe its state from SwiftUI.

## Install the package

Add the package with Swift Package Manager (in Xcode: File > Add Package Dependencies…, or in `Package.swift`):

```swift
dependencies: [
    .package(url: "https://github.com/0xkey-io/sdk-swift.git", .upToNextMinor(from: "0.2.0")),
],
targets: [
    .target(name: "App", dependencies: [.product(name: "ZeroXKey", package: "sdk-swift")]),
]
```

Requirements: iOS 17+ or macOS 14+, Xcode 16+ (Swift 6 language mode). There are no third-party dependencies.

## Prepare the app

Depending on the sign-in methods you use:

- **Passkeys.** Add the Associated Domains entitlement `webcredentials:<rpId>` for the relying party ID you configure. Serve `https://<rpId>/.well-known/apple-app-site-association` and list `<TeamID>.<bundle ID>` under `webcredentials.apps`:

  ```json
  { "webcredentials": { "apps": ["ABCDE12345.com.example.app"] } }
  ```

  The 0xkey gateway must also accept that RP ID. Ask 0xkey to enable it for your organization.
- **Sign in with Apple.** Enable the "Sign in with Apple" capability.
- **Browser OAuth (Google, Discord, X).** Google: register your app's URL scheme and give the SDK a Google web client ID (config or Dashboard). Discord and X: register a redirect URI with an app-owned custom scheme with the provider. See <doc:Authentication>.

## Configure the context

Call ``ZeroXKeyContext/configure(_:)`` once at launch, before anything touches ``ZeroXKeyContext/shared``. It creates the shared context and restores a stored session if there is one.

```swift
import SwiftUI
import ZeroXKey

@main
struct ExampleApp: App {
    init() {
        ZeroXKeyContext.configure(ZeroXKeyConfig(
            authProxyConfigId: "<auth proxy config id>",
            rpId: "wallet.example.com",
            rpName: "Example Wallet",
            organizationId: "<parent organization id>"))
    }

    var body: some Scene {
        WindowGroup { RootView() }
    }
}
```

``ZeroXKeyConfig`` defaults `apiUrl` and `authProxyUrl` to the 0xkey production hosts. Leave `authProxyConfigId` out to run without the Auth Proxy (your own backend issues sessions, see <doc:SessionsAndRefresh>); Auth Proxy methods (OTP, OAuth, passkey sign-up) then throw ``ZeroXKeyError/missingAuthProxyConfiguration``.

### Transport security and App Transport Security

`apiUrl` and `authProxyUrl` must be `https`. ``ZeroXKeyConfig/transportSecurity`` (``ZeroXKeyTransportSecurity/requireHTTPS`` by default) is checked before every request, so another URL throws ``ZeroXKeyHttpError/insecureURL(_:)`` and nothing is sent. For a server on the development machine set it to ``ZeroXKeyTransportSecurity/dangerouslyAllowInsecureLoopback``: `http` is then accepted for `localhost`, `127.0.0.0/8` and `::1` only, never for other hosts and never with a user name or password in the URL.

The SDK's check and App Transport Security are separate layers. Relaxing ATS in `Info.plist` (`NSAllowsArbitraryLoads`) does not make the SDK accept `http`, and a loopback URL the opt-in accepts still has to pass ATS (Apple exempts IP addresses and unqualified host names such as `localhost`). Do not ship the opt-in in a release build.

``ZeroXKeyContext/shared`` traps if the context is not configured. ``ZeroXKeyContext/current()`` is the throwing alternative (``ZeroXKeyError/notConfigured``).

## Observe state from SwiftUI

``ZeroXKeyContext`` publishes ``ZeroXKeyContext/authState``, ``ZeroXKeyContext/session``, ``ZeroXKeyContext/user``, ``ZeroXKeyContext/wallets`` and ``ZeroXKeyContext/client``. `authState` is ``AuthState/loading`` until the stored session has been restored.

```swift
struct RootView: View {
    @ObservedObject private var ctx = ZeroXKeyContext.shared

    var body: some View {
        switch ctx.authState {
        case .loading:
            ProgressView()
        case .unauthenticated:
            SignInView()
        case .authenticated:
            List(ctx.wallets) { wallet in
                Text(wallet.walletName)
            }
            .task { _ = try? await ctx.refreshWallets() }
        }
    }
}
```

`user` and `wallets` are not loaded at login. Call ``ZeroXKeyContext/refreshUser()`` and ``ZeroXKeyContext/refreshWallets()`` when you need them.

## Sign in

Platform sign-in methods take an `ASPresentationAnchor` (a window) to present the system UI from:

```swift
let ctx = ZeroXKeyContext.shared
try await ctx.loginWithPasskey(anchor: window)
let wallets = try await ctx.refreshWallets()
```

See <doc:Authentication> for every method, <doc:SessionsAndRefresh> for session handling and <doc:SigningAndTransactions> for signing.
