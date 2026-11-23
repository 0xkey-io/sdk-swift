import Foundation
import os
import ZeroXKeyHttp

/// What the Auth Proxy configuration (`wallet_kit_config`, set in the Dashboard) and the local
/// `ZeroXKeyConfig` resolve to. Internal: apps that want the raw remote values read them with
/// `ZeroXKeyContext.shared.client?.proxyGetWalletKitConfig()`. This is headless: `enabledProviders`
/// is not used to show or hide anything; the app decides what to offer.
package struct ZeroXKeyRuntimeConfig: Sendable, Equatable {
    package struct Auth: Sendable, Equatable {
        /// Lifetime `stamp_login` asks for when the call gives none: the Dashboard's session
        /// duration if it is usable (an integer > 0, see `usableSessionSeconds(_:)`), else
        /// `ZeroXKeyConfig.sessionExpirationSeconds` if usable, else `"900"`. Always canonical decimal text.
        package var sessionExpirationSeconds: String
        /// OTP code length / alphabet the Dashboard prescribes. Kept for the app and for future
        /// client-side checks; nothing in the SDK acts on them today: the Auth Proxy enforces both
        /// (`otp_init_v2` has no length or alphabet parameter). `nil` when the Dashboard sends no usable value.
        package var otpLength: Int?
        package var otpAlphanumeric: Bool?
        package var oauth: OAuth
    }

    package struct OAuth: Sendable, Equatable {
        /// The Dashboard's OAuth redirect URL.
        package var redirectUrl: String?
        /// Custom-scheme browser OAuth client per provider (Discord, X), resolved local first, then
        /// remote. A local client (`ZeroXKeyConfig.auth.oauth`) brings its own redirect URI; a remote one
        /// is the Dashboard's client ID with the Dashboard's redirect URL, and only exists when both are
        /// present. Google has no entry here: its hosted flow takes `googleWebClientId` instead.
        package var clients: [OAuthWebProvider: OAuthClient]
        /// Google *web* client ID of the hosted flow: `ZeroXKeyConfig.auth.oauth.googleWebClientId`,
        /// else the Dashboard's `oauthClientIds.google` (see `OAuthWebProvider.usesRemoteClientId`).
        package var googleWebClientId: String? = nil
    }

    package var auth: Auth
    /// Whether the remote configuration was read (false: local values and defaults only).
    package var fetched: Bool

    /// A session duration in seconds that can be sent to `stamp_login`, or `nil` for "not set".
    ///
    /// This is the single test every layer of the lifetime chain goes through (call argument,
    /// Dashboard, `ZeroXKeyConfig.sessionExpirationSeconds`): a layer that is `nil`, empty, blank,
    /// not an integer or not greater than zero counts as unset and the chain continues with the next
    /// layer. The chain itself is the one sdk-js uses for `auth.sessionExpirationSeconds`
    /// (sdk-js `packages/react-wallet-kit/src/providers/client/Provider.tsx:1326-1329` for the
    /// Dashboard over local value, `Provider.tsx:2529-2531` for the call argument over both, and
    /// sdk-js `packages/core/src/__clients__/core.ts:1034-1035` for the 900 s default). sdk-js
    /// combines those layers with `??` / `||`, which let `"0"` or `"abc"` through; the common rule for all
    /// SDKs treats them as unset, and this function is where Swift applies it.
    ///
    /// Accepted: surrounding whitespace is trimmed, then a plain base-10 integer (an optional leading
    /// `+` and leading zeros are allowed) that fits in `Int` and is at least 1. The result is the
    /// canonical decimal text, so `" +030 "` becomes `"30"`. Not accepted: `""`, `" "`, `"0"`, `"-5"`,
    /// `"abc"`, `"12abc"`, `"1.5"`, `"1e3"` and values beyond `Int.max`.
    package static func usableSessionSeconds(_ raw: String?) -> String? {
        guard let raw, let value = Int(raw.trimmingCharacters(in: .whitespacesAndNewlines)), value > 0 else { return nil }
        return String(value)
    }

    /// Merges the remote configuration (if it could be read) into the local one. Session duration and
    /// OTP follow the Dashboard (as in the sdk-js wallet kits); OAuth clients follow the local
    /// configuration first.
    static func build(remote: ProxyTGetWalletKitConfigResponse?, config: ZeroXKeyConfig) -> ZeroXKeyRuntimeConfig {
        let seconds = usableSessionSeconds(remote?.sessionExpirationSeconds)
            ?? usableSessionSeconds(config.sessionExpirationSeconds)
            ?? ZeroXKeyConfig.defaultSessionExpirationSeconds
        let otpLength = remote?.otpLength.flatMap { Int($0) }.flatMap { $0 > 0 ? $0 : nil }
        let redirect = remote?.oauthRedirectUrl.flatMap { $0.isEmpty ? nil : $0 }

        var clients: [OAuthWebProvider: OAuthClient] = [:]
        for provider in OAuthWebProvider.allCases where provider != .google {
            if let local = config.auth.oauth?.client(for: provider) {
                clients[provider] = local
            } else if provider.usesRemoteClientId, let redirect,
                      let id = remote?.oauthClientIds?[provider.rawValue], !id.isEmpty {
                clients[provider] = OAuthClient(clientId: id, redirectUri: redirect)
            }
        }
        // Google's hosted flow: the app's web client ID first, the Dashboard's second.
        let googleWebClientId = config.auth.oauth?.googleWebClientId.trimmedNonEmpty
            ?? remote?.oauthClientIds?[OAuthWebProvider.google.rawValue].trimmedNonEmpty
        return ZeroXKeyRuntimeConfig(
            auth: Auth(sessionExpirationSeconds: seconds, otpLength: otpLength,
                       otpAlphanumeric: remote?.otpAlphanumeric,
                       oauth: OAuth(redirectUrl: redirect, clients: clients, googleWebClientId: googleWebClientId)),
            fetched: remote != nil)
    }
}

/// Fetch state of the runtime configuration (one per context).
enum RuntimeConfigState {
    case notLoaded
    /// The one request in flight; everybody who needs the configuration awaits this task.
    case loading(Task<ZeroXKeyRuntimeConfig, Never>)
    /// Resolved (remote read, or no Auth Proxy configuration so nothing to read). Final.
    case loaded(ZeroXKeyRuntimeConfig)
    /// The request failed at `at`; local values stand in and it is asked again after `runtimeConfigRetryInterval`.
    case failed(ZeroXKeyRuntimeConfig, at: Date)
}

extension ZeroXKeyContext {
    /// A failed `wallet_kit_config` request is not repeated for this long.
    static var runtimeConfigRetryInterval: TimeInterval { 60 }

    private static let log = Logger(subsystem: "io.0xkey.sdk", category: "runtime-config")

    /// The resolved configuration, or `nil` while it has not been fetched yet.
    package var runtimeConfig: ZeroXKeyRuntimeConfig? {
        switch runtimeConfigState {
        case .loaded(let c), .failed(let c, _): c
        case .notLoaded, .loading: nil
        }
    }

    /// Asks `wallet_kit_config` once in the background (called by `configure`). Never blocks or fails anything.
    func startRuntimeConfigFetch() {
        guard let id = config.authProxyConfigId, !id.isEmpty else { return }
        Task { [weak self] in _ = await self?.loadRuntimeConfig() }
    }

    /// The runtime configuration. Reads the Auth Proxy configuration if that has not happened (or
    /// failed more than a minute ago); overlapping callers, including the request `configure`
    /// started, share one request. A failing request is not an error: the result then holds the
    /// local values and defaults.
    package func loadRuntimeConfig() async -> ZeroXKeyRuntimeConfig {
        switch runtimeConfigState {
        case .loaded(let c):
            return c
        case .failed(let c, let at) where now().timeIntervalSince(at) < Self.runtimeConfigRetryInterval:
            return c
        case .loading(let task):
            return await task.value
        case .notLoaded, .failed:
            break
        }
        let task = Task { await self.fetchRuntimeConfig() }
        runtimeConfigState = .loading(task)
        return await task.value
    }

    private func fetchRuntimeConfig() async -> ZeroXKeyRuntimeConfig {
        guard let id = config.authProxyConfigId, !id.isEmpty, let client = try? proxyClient() else {
            let local = ZeroXKeyRuntimeConfig.build(remote: nil, config: config)
            runtimeConfigState = .loaded(local)
            return local
        }
        do {
            let resolved = ZeroXKeyRuntimeConfig.build(remote: try await client.proxyGetWalletKitConfig(), config: config)
            runtimeConfigState = .loaded(resolved)
            return resolved
        } catch {
            Self.log.error("wallet_kit_config could not be read, using the local configuration: \(String(describing: error), privacy: .private)")
            let fallback = ZeroXKeyRuntimeConfig.build(remote: nil, config: config)
            runtimeConfigState = .failed(fallback, at: now())
            return fallback
        }
    }

    /// The lifetime `stamp_login` asks for, in the same order the sdk-js wallet kits use for
    /// `auth.sessionExpirationSeconds` (see ``ZeroXKeyRuntimeConfig/usableSessionSeconds(_:)``):
    ///
    /// 1. `explicit`, the `expirationSeconds` argument of the call (the configuration is not even read);
    /// 2. the session duration of the Auth Proxy configuration (Dashboard), when `authProxyConfigId`
    ///    is set and the configuration can be read (one `wallet_kit_config` request per context);
    /// 3. `config.sessionExpirationSeconds`;
    /// 4. `"900"`.
    ///
    /// A layer whose value is `nil`, empty, blank, not an integer or ≤ 0 (`"0"`, `"-5"`, `"abc"`) is
    /// treated as unset and the next layer applies; so an `expirationSeconds: "0"` argument falls back to
    /// the Dashboard. Every path that asks `stamp_login` for a lifetime (passkey login and sign-up, OTP
    /// login, scoped OTP login, `refreshSession` and auto-refresh)
    /// resolves through this function.
    ///
    /// OTP sessions created by the Auth Proxy (`otp_login_v2`) always have the Dashboard's duration;
    /// this keeps passkey and refreshed sessions consistent with them. A failing configuration
    /// request never fails the login: it falls back to 3 / 4 and is retried after a minute.
    package func resolvedExpirationSeconds(_ explicit: String?) async -> String {
        if let explicit = ZeroXKeyRuntimeConfig.usableSessionSeconds(explicit) { return explicit }
        return await loadRuntimeConfig().auth.sessionExpirationSeconds
    }
}
