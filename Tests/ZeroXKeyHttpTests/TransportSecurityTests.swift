import Foundation
import Testing
import ZeroXKeyHttp
import ZeroXKeyTestSupport

private func allowed(_ s: String, _ policy: ZeroXKeyTransportSecurity) -> Bool {
    URL(string: s).map(policy.allows) ?? false
}

@Suite("Transport security policy")
struct TransportSecurityPolicyTests {
    static let https = ["https://api.0xkey.io", "HTTPS://api.0xkey.io/v1", "https://api.0xkey.io:8443/x?y=1",
                        "https://127.0.0.1", "https://[::1]:443"]
    static let loopbackHTTP = ["http://localhost", "http://LOCALHOST:8080/", "HTTP://localhost", "Http://LocalHost:1",
                               "http://127.0.0.1", "http://127.0.0.1:8545", "http://127.255.255.254:1", "http://127.1.2.3",
                               "http://[::1]", "http://[::1]:8080", "http://[0:0:0:0:0:0:0:1]:80"]
    /// Plain `http` that must stay refused even with the loopback opt-in.
    static let nonLoopbackHTTP = [
        "http://api.0xkey.io", "http://10.0.0.5:8545", "http://192.168.1.10", "http://128.0.0.1", "http://0.0.0.0",
        "http://localhost.example.org", "http://localhost.", "http://mylocalhost", "http://127.0.0.1.example.org",
        "http://example.org/localhost", "http://example.org?h=localhost", "http://example.org#@localhost",
        // userinfo: the host after `@` is the one connected to
        "http://localhost@example.org", "http://localhost:80@example.org", "http://127.0.0.1@example.org",
        "http://[::1]@example.org", "http://user:pw@localhost", "http://user@127.0.0.1:8545",
        // numeric forms other resolvers might map to loopback
        "http://127.1", "http://127.0.1", "http://2130706433", "http://0x7f.0.0.1", "http://0177.0.0.1",
        "http://127.0.0.256", "http://127.0.0.-1",
        "http://[::2]", "http://[::ffff:127.0.0.1]", "http://[::1%25lo0]", "http://example.org\\@localhost.example.org",
    ]
    static let otherSchemes = ["ws://localhost", "wss://api.0xkey.io", "ftp://localhost", "file:///etc/hosts",
                               "api.0xkey.io", "//api.0xkey.io", "https://", "http://", "localhost:8080"]

    @Test func requireHTTPSIsStrict() {
        let p = ZeroXKeyTransportSecurity.requireHTTPS
        for s in Self.https { #expect(allowed(s, p), "\(s)") }
        for s in Self.loopbackHTTP + Self.nonLoopbackHTTP + Self.otherSchemes { #expect(!allowed(s, p), "\(s)") }
    }

    @Test func loopbackOptInOnlyAddsLoopbackHTTP() {
        let p = ZeroXKeyTransportSecurity.dangerouslyAllowInsecureLoopback
        for s in Self.https + Self.loopbackHTTP { #expect(allowed(s, p), "\(s)") }
        for s in Self.nonLoopbackHTTP + Self.otherSchemes { #expect(!allowed(s, p), "\(s)") }
    }

    @Test func loopbackHosts() {
        for h in ["localhost", "LocalHost", "127.0.0.1", "127.9.8.7", "::1", "[::1]", "0:0:0:0:0:0:0:1", "0000::0001"] {
            #expect(ZeroXKeyTransportSecurity.isLoopbackHost(h), "\(h)")
        }
        for h in ["", "localhost.", "localhost.localdomain", "127.0.0", "127.0.0.1.", "127.00000.0.1", "1.2.3.4",
                  "::", "::2", "::ffff:127.0.0.1", "[::1", "fe80::1", "127.0.0.1a", "１２７.0.0.1"] {
            #expect(!ZeroXKeyTransportSecurity.isLoopbackHost(h), "\(h)")
        }
    }

    @Test func validateThrowsWithoutCredentials() {
        #expect(throws: ZeroXKeyHttpError.insecureURL("http://example.org/x")) {
            try ZeroXKeyTransportSecurity.dangerouslyAllowInsecureLoopback.validate(URL(string: "http://user:secret@example.org/x")!)
        }
        #expect(throws: ZeroXKeyHttpError.insecureURL("http://localhost:8080")) {
            try ZeroXKeyTransportSecurity.requireHTTPS.validate(URL(string: "http://localhost:8080")!)
        }
    }
}

@Suite("Transport security in ZeroXKeyClient")
struct ClientTransportSecurityTests {
    @Test func clientRefusesHTTPByDefaultBeforeSending() async throws {
        let server = MockServer()
        let insecure = URL(string: "http://\(server.apiHost)")!
        for client in [ZeroXKeyClient(apiBaseURL: insecure, urlSession: server.session),
                       ZeroXKeyClient(apiBaseURL: insecure, urlSession: server.session, transportSecurity: .dangerouslyAllowInsecureLoopback)] {
            await #expect(throws: ZeroXKeyHttpError.insecureURL("http://\(server.apiHost)/public/v1/query/whoami")) {
                _ = try await client.getWhoami()
            }
        }
        #expect(ZeroXKeyClient(apiBaseURL: insecure).transportSecurity == .requireHTTPS)
        #expect(server.requests.isEmpty)
    }

    @Test func authProxyRequestsAreCheckedToo() async throws {
        let server = MockServer()
        let client = ZeroXKeyClient(apiBaseURL: server.apiURL, authProxyBaseURL: URL(string: "http://\(server.authProxyHost)")!,
                                    authProxyConfigId: "cfg", urlSession: server.session)
        await #expect(throws: ZeroXKeyHttpError.self) { _ = try await client.proxyGetWalletKitConfig() }
        #expect(server.requests.isEmpty)
    }

    @Test func loopbackOptInSendsToLocalhostAndKeepsThePolicyOnCopies() async throws {
        let server = MockServer(apiHost: "localhost")
        server.on("/public/v1/query/whoami", respond: .json([
            "organizationId": "o", "organizationName": "n", "userId": "u", "username": "a",
        ]))
        let client = ZeroXKeyClient(apiBaseURL: URL(string: "http://localhost:8080")!, urlSession: server.session,
                                    transportSecurity: .dangerouslyAllowInsecureLoopback)
        #expect(try await client.getWhoami().userId == "u")
        #expect(try await client.with(organizationId: "o2").with(stamper: nil).getWhoami().userId == "u")
        #expect(client.with(organizationId: "o2").transportSecurity == .dangerouslyAllowInsecureLoopback)
        #expect(server.requests.count == 2)
        let strict = ZeroXKeyClient(apiBaseURL: URL(string: "http://localhost:8080")!, urlSession: server.session)
        await #expect(throws: ZeroXKeyHttpError.self) { _ = try await strict.getWhoami() }
        #expect(server.requests.count == 2)
    }
}
