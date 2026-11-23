import AuthenticationServices
import Foundation
import Testing
import ZeroXKeyPasskeys
import ZeroXKeyStamper

// The AuthenticationServices sheet cannot run in `swift test`; the UI path is exercised by
// Examples/wallet-demo. These tests cover the pure parts.
@Suite("Platform passkeys")
struct PasskeysTests {
    @Test func cancellationMapsToCanceled() {
        let e = NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.Code.canceled.rawValue)
        #expect(PasskeyErrorMapping.map(e) as? ZeroXKeyPasskeyError == .canceled)
    }

    @Test func associatedDomainFailureIsNamed() {
        let e = NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.Code.failed.rawValue,
                        userInfo: [NSLocalizedDescriptionKey: "Application with identifier X is not associated with domain login.example.org"])
        #expect(PasskeyErrorMapping.map(e) as? ZeroXKeyPasskeyError
                == .notAssociated("Application with identifier X is not associated with domain login.example.org"))
    }

    @Test func otherErrorsKeepCodeAndMessage() {
        let generic = NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.Code.failed.rawValue,
                              userInfo: [NSLocalizedDescriptionKey: "boom"])
        #expect(PasskeyErrorMapping.map(generic) as? ZeroXKeyPasskeyError
                == .failed(code: ASAuthorizationError.Code.failed.rawValue, message: "boom"))
        let foreign = NSError(domain: NSURLErrorDomain, code: -1009, userInfo: [NSLocalizedDescriptionKey: "offline"])
        #expect(PasskeyErrorMapping.map(foreign) as? ZeroXKeyPasskeyError == .failed(code: -1009, message: "offline"))
    }

    @Test func transportsMatchSdkJsReactNative() {
        // sdk-js/packages/react-native-passkey-stamper/src/index.ts:197
        #expect(PlatformPasskeyProvider.reportedTransports == ["AUTHENTICATOR_TRANSPORT_HYBRID"])
    }

    @Test @MainActor func passkeyStamperKeepsCallerRpId() {
        #if os(macOS)
        let s = PasskeyStamper(rpId: "login.example.org", presentationAnchor: { NSWindow() })
        #else
        let s = PasskeyStamper(rpId: "login.example.org", presentationAnchor: { UIWindow() })
        #endif
        #expect(s.rpId == "login.example.org")
    }
}
