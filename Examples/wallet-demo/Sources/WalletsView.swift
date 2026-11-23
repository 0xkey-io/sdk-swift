import SwiftUI
import ZeroXKey

struct WalletsView: View {
    @EnvironmentObject var zeroXKey: ZeroXKeyContext
    @ObservedObject private var events = SessionEventLog.shared
    @State private var busy = false
    @State private var message: String?
    @State private var signature: String?
    @State private var exported: String?

    var body: some View {
        List {
            if let session = zeroXKey.session {
                Section("Session") {
                    LabeledContent("Organization", value: session.organizationId)
                    LabeledContent("Expires", value: Date(timeIntervalSince1970: session.expiry).formatted(date: .omitted, time: .standard))
                    LabeledContent("Session key", value: String(session.publicKey.prefix(12)) + "…")
                    LabeledContent("Key backend",
                                   value: SecureEnclaveKeyManager().isHardwareBacked(publicKey: session.publicKey) ? "Secure Enclave" : "software")
                    LabeledContent("Stored sessions", value: "\((try? zeroXKey.sessionKeys())?.count ?? 0)")
                    LabeledContent("Active slot", value: (try? zeroXKey.activeSessionKey()) ?? "-")
                    Button("Add second session (passkey)") {
                        run { try await zeroXKey.loginWithPasskey(anchor: currentAnchor(), sessionKey: "demo-second") }
                    }
                    Button("Switch session") {
                        run {
                            let keys = try zeroXKey.sessionKeys().sorted()
                            guard keys.count > 1, let active = try zeroXKey.activeSessionKey(),
                                  let i = keys.firstIndex(of: active) else { return }
                            try zeroXKey.setActiveSession(sessionKey: keys[(i + 1) % keys.count])
                            _ = try await zeroXKey.refreshWallets()
                        }
                    }
                    Button("Clear all sessions", role: .destructive) { run { try zeroXKey.clearAllSessions() } }
                }
            }
            if !events.lines.isEmpty {
                Section("Session events") {
                    ForEach(events.lines.indices.reversed(), id: \.self) { Text(events.lines[$0]).font(.caption2) }
                }
            }

            ForEach(zeroXKey.wallets) { wallet in
                Section(wallet.walletName) {
                    ForEach(wallet.accounts, id: \.address) { account in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(account.address).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                            Text(account.addressFormat.rawValue).font(.caption2).foregroundStyle(.secondary)
                        }
                        .swipeActions {
                            Button("Sign") {
                                run {
                                    let sig = try await zeroXKey.signMessage(
                                        signWith: account.address, addressFormat: account.addressFormat, message: "Hello from 0xkey")
                                    signature = "r=\(sig.r)\ns=\(sig.s)\nv=\(sig.v)"
                                }
                            }
                            if account.addressFormat == .ADDRESS_FORMAT_ETHEREUM {
                                Button("Sign tx") {
                                    run {
                                        // EIP-1559 Sepolia, nonce 0, value 0, to = self. Signed only, never broadcast.
                                        let unsigned = "02ea83aa36a780843b9aca00847735940082520894"
                                            + account.address.lowercased().replacingOccurrences(of: "0x", with: "") + "8080c0"
                                        let signed = try await zeroXKey.signTransaction(
                                            signWith: account, unsignedTransaction: unsigned, type: .TRANSACTION_TYPE_ETHEREUM)
                                        signature = "signedTransaction=\(signed)"
                                    }
                                }
                            }
                        }
                    }
                    Button("Export recovery phrase", role: .destructive) {
                        run { exported = try await zeroXKey.exportWallet(walletId: wallet.walletId) }
                    }
                }
            }

            Section {
                Button("Create wallet") { run { _ = try await zeroXKey.createWallet(walletName: "Wallet \(zeroXKey.wallets.count + 1)") } }
                Button("Add passkey") {
                    run {
                        let id = try await zeroXKey.addPasskey(anchor: currentAnchor())
                        message = "Passkey added (authenticator \(id))"
                    }
                }
                Button("Refresh") { run { _ = try await zeroXKey.refreshWallets() } }
                Button("Log out", role: .destructive) { run { try zeroXKey.logout() } }
            }

            if let signature { Section("Signature") { Text(signature).font(.system(.caption, design: .monospaced)).textSelection(.enabled) } }
            if let exported {
                Section("Recovery phrase — keep it secret") {
                    Text(exported).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                    Button("Hide") { self.exported = nil }
                }
            }
            if let message { Section { Text(message).font(.footnote).foregroundStyle(.red) } }
        }
        .disabled(busy)
        .overlay { if busy { ProgressView() } }
        .navigationTitle("Wallets")
        .task { run { _ = try await zeroXKey.refreshWallets() } }
    }

    private func run(_ work: @escaping @MainActor () async throws -> Void) {
        busy = true
        message = nil
        Task {
            defer { busy = false }
            do { try await work() } catch { message = describe(error) }
        }
    }
}
