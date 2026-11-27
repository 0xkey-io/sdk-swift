import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

/// Decodes an `X-Stamp` header and verifies it over `body` with an independent check.
func verifyApiKeyStamp(_ header: String?, body: Data, expectedPublicKey: String) throws -> Bool {
    let value = try #require(header)
    let json = try JSONSerialization.jsonObject(with: Base64URL.decode(value)) as! [String: String]
    guard json["publicKey"] == expectedPublicKey, json["scheme"] == "SIGNATURE_SCHEME_TK_API_P256" else { return false }
    return try verifyStampSignature(publicKey: expectedPublicKey, signature: json["signature"]!, signedData: String(decoding: body, as: UTF8.self))
}

func makeClient(_ server: MockServer, stamper: (any Stamper)?, organizationId: String? = "org-default",
                configId: String? = "cfg-123", poller: ActivityPollerConfig = .init(intervalMs: 0, numRetries: 3)) -> ZeroXKeyClient {
    ZeroXKeyClient(apiBaseURL: server.apiURL, stamper: stamper, organizationId: organizationId,
                   authProxyBaseURL: server.authProxyURL, authProxyConfigId: configId,
                   activityPoller: poller, urlSession: server.session, now: { Date(timeIntervalSince1970: 1_763_500_000.123) })
}

@Suite("Query requests")
struct QueryRequestTests {
    let key = generateP256KeyPair()

    @Test func whoamiSendsStampedBodyAndHeaders() async throws {
        let server = MockServer()
        server.on("/public/v1/query/whoami", respond: .json([
            "organizationId": "org-default", "organizationName": "Example Org", "userId": "u-1", "username": "alice",
        ]))
        let stamper = try ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey)
        let res = try await makeClient(server, stamper: stamper).getWhoami()
        #expect(res.userId == "u-1" && res.username == "alice" && res.organizationName == "Example Org")

        let req = try #require(server.requests.first)
        #expect(server.requests.count == 1)
        #expect(req.method == "POST")
        #expect(req.url.absoluteString == "https://\(server.apiHost)/public/v1/query/whoami")
        #expect(req.header("Content-Type") == "application/json")
        #expect(req.header("X-Client-Version") == "0xkey-swift/0.2.0")
        #expect(req.bodyString == #"{"organizationId":"org-default"}"#)
        #expect(try verifyApiKeyStamp(req.header("X-Stamp"), body: req.body, expectedPublicKey: key.publicKey))
        #expect(req.header("X-Auth-Proxy-Config-ID") == nil)
    }

    @Test func explicitOrganizationOverridesDefault() async throws {
        let server = MockServer()
        server.on("/public/v1/query/list_wallets", respond: .json(["wallets": [APIFixtures.wallet(id: "w1", name: "Main")]]))
        let stamper = try ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey)
        let res = try await makeClient(server, stamper: stamper).getWallets(TGetWalletsBody(organizationId: "org-sub"))
        #expect(res.wallets.map(\.walletId) == ["w1"])
        #expect(server.requests.first?.json["organizationId"] as? String == "org-sub")
    }

    @Test func stampedBodyBytesAreExactlyWhatIsSent() async throws {
        let server = MockServer()
        server.on("/public/v1/query/get_user", respond: .json(["user": [
            "userId": "u/1", "userName": "héllo 世界 \"q\"", "authenticators": [], "apiKeys": [], "userTags": [],
            "oauthProviders": [], "createdAt": APIFixtures.timestamp, "updatedAt": APIFixtures.timestamp, "mfaPolicies": [],
        ]]))
        let stamper = try ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey)
        let client = makeClient(server, stamper: stamper)
        let body = TGetUserBody(userId: "u/1 \u{4e16}", organizationId: "o\"1")
        let signed = try await client.stampGetUser(body)
        #expect(!signed.body.contains("\\/"))   // JSON.stringify does not escape "/"
        #expect(signed.body.contains("\u{4e16}"))
        let user = try await client.getUser(body).user
        #expect(user?.userName == "héllo 世界 \"q\"")
        let req = try #require(server.requests.last)
        #expect(req.bodyString == signed.body)
        #expect(try verifyApiKeyStamp(req.header("X-Stamp"), body: req.body, expectedPublicKey: key.publicKey))
    }

    @Test func sendSignedRequestReusesBodyAndStamp() async throws {
        let server = MockServer()
        server.on("/public/v1/query/list_wallets", respond: .json(["wallets": []]))
        let stamper = try ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey)
        let client = makeClient(server, stamper: stamper)
        let signed = try await client.stampGetWallets()
        #expect(server.requests.isEmpty)
        _ = try await client.send(signed)
        let req = try #require(server.requests.first)
        #expect(req.bodyString == signed.body)
        #expect(req.header("X-Stamp") == signed.stamp.stampHeaderValue)
    }

    @Test func webAuthnStamperHeaderMatchesBody() async throws {
        let server = MockServer()
        server.on("/public/v1/query/whoami", respond: .json([
            "organizationId": "o", "organizationName": "n", "userId": "u", "username": "x",
        ]))
        let provider = FixedAssertionProvider()
        let stamper = WebAuthnStamper(rpId: "login.example.org", provider: provider)
        _ = try await makeClient(server, stamper: stamper).getWhoami()
        let req = try #require(server.requests.first)
        #expect(req.header("X-Stamp") == nil)
        let header = try #require(req.header("X-Stamp-Webauthn"))
        #expect(header == WebAuthnStamp.headerValue(for: provider.assertion))
        let seen = try #require(provider.requests.first)
        #expect(seen.rpId == "login.example.org")
        #expect(seen.challenge == WebAuthnStamp.challenge(for: req.bodyString))
    }

    @Test func noStamperSendsNoStampHeader() async throws {
        let server = MockServer()
        server.on("/public/v1/query/get_organization_configs", respond: .json(["configs": [String: Any]()]))
        _ = try? await makeClient(server, stamper: nil).getOrganizationConfigs(TGetOrganizationConfigsBody())
        let req = try #require(server.requests.first)
        #expect(req.headers.keys.filter { $0.lowercased().hasPrefix("x-stamp") }.isEmpty)
    }
}

final class FixedAssertionProvider: PasskeyAssertionProvider, @unchecked Sendable {
    let assertion = PasskeyAssertion(credentialId: Data([1, 2, 3]), authenticatorData: Data([4, 5]),
                                     clientDataJSON: Data(#"{"type":"webauthn.get"}"#.utf8), signature: Data([6, 7, 8]))
    private let lock = NSLock()
    private var _requests: [PasskeyAssertionRequest] = []
    var requests: [PasskeyAssertionRequest] { lock.withLock { _requests } }
    func assert(_ request: PasskeyAssertionRequest) async throws -> PasskeyAssertion {
        lock.withLock { _requests.append(request) }
        return assertion
    }
}

@Suite("Network isolation")
struct NetworkIsolationTests {
    @Test func defaultsPointAt0xkeyButMockSessionNeverReachesThem() async throws {
        #expect(ZeroXKeyClient.defaultApiBaseURL.absoluteString == "https://api.0xkey.io")
        #expect(ZeroXKeyClient.defaultAuthProxyBaseURL.absoluteString == "https://authproxy.0xkey.io")
        let client = ZeroXKeyClient(organizationId: "o", urlSession: MockURLProtocol.session())
        do {
            _ = try await client.getWhoami()
            Issue.record("request to an unregistered host must fail")
        } catch let error as URLError {
            #expect(error.code == .cannotConnectToHost)
        }
    }

    @Test func otherTestsHostIsNotShared() async throws {
        let a = MockServer(), b = MockServer()
        a.on("/public/v1/query/whoami", respond: .json(["organizationId": "o", "organizationName": "n", "userId": "u", "username": "x"]))
        _ = try await makeClient(a, stamper: nil).getWhoami()
        await #expect(throws: ZeroXKeyRequestError.self) { try await makeClient(b, stamper: nil).getWhoami() }
        #expect(a.requests.count == 1 && b.requests.count == 1)
    }
}
