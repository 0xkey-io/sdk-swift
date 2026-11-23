import SwiftUI
import ZeroXKey

/// Minimal wallet built on the 0xkey Swift SDK.
/// Bundle ID, team, RP ID (also the Associated Domains `webcredentials:` entry), organization
/// and Auth Proxy config come from `Config/Demo.xcconfig` / `Config/Local.xcconfig`.
@main
struct WalletDemoApp: App {
    init() {
        ZeroXKeyContext.configure(DemoSettings.load().config)
        ZeroXKeyContext.shared.onSessionEvent = { SessionEventLog.shared.record($0) }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(ZeroXKeyContext.shared)
        }
    }
}

/// Tenant settings read from Info.plist (filled from build settings in project.yml).
struct DemoSettings {
    let organizationId: String?
    let authProxyConfigId: String?
    let rpId: String

    static func load(bundle: Bundle = .main) -> DemoSettings {
        func value(_ key: String) -> String? {
            guard let v = bundle.object(forInfoDictionaryKey: key) as? String,
                  !v.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
            return v
        }
        return DemoSettings(
            organizationId: value("ZeroXKeyOrganizationId"),
            authProxyConfigId: value("ZeroXKeyAuthProxyConfigId"),
            rpId: value("ZeroXKeyRpId") ?? "wallet.example.com")
    }

    var config: ZeroXKeyConfig {
        ZeroXKeyConfig(
            authProxyConfigId: authProxyConfigId,
            rpId: rpId,
            rpName: "Wallet Demo",
            organizationId: organizationId,
            keyManager: SecureEnclaveKeyManager(),   // Secure Enclave, software fallback on simulator
            sessionStore: KeychainSessionStore(service: (Bundle.main.bundleIdentifier ?? "wallet-demo") + ".sessions"))
    }

    var missing: [String] {
        var m: [String] = []
        if organizationId == nil { m.append("ZEROXKEY_ORGANIZATION_ID") }
        if authProxyConfigId == nil { m.append("ZEROXKEY_AUTH_PROXY_CONFIG_ID") }
        return m
    }
}

struct RootView: View {
    @EnvironmentObject var zeroXKey: ZeroXKeyContext

    var body: some View {
        NavigationStack {
            switch zeroXKey.authState {
            case .loading:
                ProgressView()
            case .authenticated:
                WalletsView()
            case .unauthenticated:
                LoginView()
            }
        }
    }
}

/// Session lifecycle events, shown on the wallets screen and logged to the Xcode console.
@MainActor
final class SessionEventLog: ObservableObject {
    static let shared = SessionEventLog()
    @Published private(set) var lines: [String] = []

    func record(_ event: ZeroXKeySessionEvent) {
        let time = Date().formatted(date: .omitted, time: .standard)
        let line: String
        switch event {
        case .refreshed(let s): line = "\(time) refreshed, expires \(Date(timeIntervalSince1970: s.expiry).formatted(date: .omitted, time: .standard))"
        case .refreshFailed(let key, let error): line = "\(time) refreshFailed [\(key)]: \(describe(error))"
        case .expired(let key): line = "\(time) expired [\(key)]"
        }
        NSLog("[WalletDemo] session event: %@", line)
        lines.append(line)
    }
}

/// Window for passkey and Sign in with Apple sheets.
@MainActor
func currentAnchor() -> UIWindow {
    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    if let key = scenes.flatMap(\.windows).first(where: \.isKeyWindow) { return key }
    if let any = scenes.first?.windows.first { return any }
    return UIWindow()
}

/// Human-readable error text, including the 0xkey-specific RP ID rejection.
func describe(_ error: any Error) -> String {
    if let e = error as? ZeroXKeyRequestError {
        switch e.reason {
        case .webAuthnRpIdNotAllowed?:
            return "The 0xkey gateway rejected RP ID \(DemoSettings.load().rpId) (not enabled for this organization). \(e.message)"
        case .webAuthnOriginNotAllowed?:
            return "The 0xkey gateway rejected this origin. \(e.message)"
        default:
            return e.description
        }
    }
    if let e = error as? ZeroXKeyPasskeyError {
        switch e {
        case .canceled: return "Cancelled."
        case .notAssociated(let m): return "App is not associated with \(DemoSettings.load().rpId): \(m)"
        default: return "\(e)"
        }
    }
    return "\(error)"
}
