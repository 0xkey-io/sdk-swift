import Foundation
import Testing
import ZeroXKey
import ZeroXKeyHttp
import ZeroXKeyTestSupport

@Suite("Transport security (context)") @MainActor
struct ConfigTransportSecurityTests {
    func context(apiUrl: String, authProxyUrl: String = "https://authproxy.0xkey.io", configId: String? = "cfg",
                 transport: ZeroXKeyTransportSecurity? = nil, server: MockServer) -> ZeroXKeyContext {
        var config = ZeroXKeyConfig(apiUrl: apiUrl, authProxyUrl: authProxyUrl, authProxyConfigId: configId,
                                    keyManager: InMemoryKeyManager(), sessionStore: InMemorySessionStore(),
                                    urlSession: server.session).trustingFixtures()
        if let transport { config.transportSecurity = transport }
        return ZeroXKeyContext(config: config)
    }

    @Test func httpsOnlyIsTheDefault() {
        #expect(ZeroXKeyConfig().transportSecurity == .requireHTTPS)
    }

    @Test func httpEndpointsAreRefusedBeforeAnyRequest() async throws {
        let server = MockServer()
        for (api, proxy) in [("http://\(server.apiHost)", "https://\(server.authProxyHost)"),
                             ("https://\(server.apiHost)", "http://\(server.authProxyHost)"),
                             ("http://localhost:8080", "http://127.0.0.1:8081")] {
            let ctx = context(apiUrl: api, authProxyUrl: proxy, server: server)
            #expect(ctx.client == nil)
            await #expect(throws: ZeroXKeyHttpError.self, "\(api) \(proxy)") {
                _ = try await ctx.initOtp(contact: "a@b.c", otpType: .email)
            }
            let key = try ctx.createKeyPair()
            let jwt = APIFixtures.sessionJWT(publicKey: key, organizationId: "o", userId: "u", exp: 4_102_444_800)
            try await ctx.storeSession(jwt: jwt)
            #expect(ctx.authState == .unauthenticated)
            await #expect(throws: (any Error).self) { _ = try await ctx.refreshWallets() }
        }
        #expect(server.requests.isEmpty)
    }

    @Test func loopbackOptInAllowsLocalDevelopmentOnly() async throws {
        let server = MockServer()
        let local = context(apiUrl: "http://localhost:8080", authProxyUrl: "http://127.0.0.1:8081",
                            transport: .dangerouslyAllowInsecureLoopback, server: server)
        #expect(local.client?.transportSecurity == .dangerouslyAllowInsecureLoopback)
        for (api, proxy) in [("http://\(server.apiHost)", "http://localhost"),
                             ("http://localhost@\(server.apiHost)", "http://localhost"),
                             ("http://localhost", "http://localhost.\(server.authProxyHost)")] {
            let ctx = context(apiUrl: api, authProxyUrl: proxy, transport: .dangerouslyAllowInsecureLoopback, server: server)
            #expect(ctx.client == nil, "\(api) \(proxy)")
            await #expect(throws: ZeroXKeyHttpError.self, "\(api) \(proxy)") {
                _ = try await ctx.initOtp(contact: "a@b.c", otpType: .email)
            }
        }
        #expect(server.requests.isEmpty)
    }
}
