import AuthenticationServices
import SwiftUI
import ZeroXKey

struct LoginView: View {
    @EnvironmentObject var zeroXKey: ZeroXKeyContext
    @State private var email = ""
    @State private var code = ""
    @State private var otp: InitOtpResult?
    @State private var busy = false
    @State private var message: String?

    private let settings = DemoSettings.load()

    var body: some View {
        Form {
            if !settings.missing.isEmpty {
                Section {
                    Text("Set \(settings.missing.joined(separator: ", ")) in project.yml before running against 0xkey.")
                        .font(.footnote).foregroundStyle(.orange)
                }
            }

            Section("Passkey (\(settings.rpId))") {
                Button("Log in with passkey") { run { try await zeroXKey.loginWithPasskey(anchor: currentAnchor()) } }
                Button("Create account with passkey") {
                    run { try await zeroXKey.signUpWithPasskey(anchor: currentAnchor(), passkeyDisplayName: "Wallet Demo") }
                }
            }

            Section("Sign in with Apple") {
                SignInWithAppleButton(.continue, onRequest: { _ in }, onCompletion: { _ in })
                    .frame(height: 44)
                    .allowsHitTesting(false)
                    .overlay {
                        // The SDK runs its own ASAuthorization request so it can set the nonce
                        // bound to the session key; the system button is only the visual.
                        Button { run { _ = try await zeroXKey.handleAppleOAuth(anchor: currentAnchor()) } } label: {
                            Color.clear
                        }
                    }
            }

            Section("Email code") {
                TextField("you@example.com", text: $email)
                    .textContentType(.emailAddress).keyboardType(.emailAddress).textInputAutocapitalization(.never)
                if let otp {
                    TextField("6-digit code", text: $code).keyboardType(.numberPad).textContentType(.oneTimeCode)
                    Button("Verify") {
                        run {
                            _ = try await zeroXKey.completeOtp(
                                otpId: otp.otpId, otpCode: code, otpEncryptionTargetBundle: otp.otpEncryptionTargetBundle,
                                contact: email, otpType: .email)
                        }
                    }
                } else {
                    Button("Send code") { run { otp = try await zeroXKey.initOtp(contact: email, otpType: .email) } }
                        .disabled(email.isEmpty)
                }
            }

            if let message {
                Section { Text(message).font(.footnote).foregroundStyle(.red) }
            }
        }
        .disabled(busy)
        .overlay { if busy { ProgressView() } }
        .navigationTitle("Wallet Demo")
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
