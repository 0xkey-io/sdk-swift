import Foundation
import Testing
import ZeroXKey
import ZeroXKeyEncoding
import ZeroXKeyTestSupport

final class CancelingRegistrar: PasskeyRegistrationProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var _calls = 0
    var calls: Int { lock.withLock { _calls } }
    func register(_ request: PasskeyRegistrationRequest) async throws -> PasskeyRegistration {
        lock.withLock { _calls += 1 }
        throw ZeroXKeyPasskeyError.canceled
    }
}

@Suite("Add passkey to a signed-in user") @MainActor
struct AddPasskeyTests {
    let t0: TimeInterval = 1_763_500_000

    func signedIn(_ server: MockServer, registration: (any PasskeyRegistrationProvider)?, rpId: String? = "login.example.org")
        async throws -> (ZeroXKeyContext, String) {
        let ctx = makeContext(server, rpId: rpId, registration: registration)
        let pk = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: pk, organizationId: "org-sub", userId: "u-1", exp: t0 + 900))
        return (ctx, pk)
    }

    static let created = MockResponse.json(APIFixtures.activityResponse(APIFixtures.activity(
        organizationId: "org-sub", status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2",
        result: ["createAuthenticatorsResult": ["authenticatorIds": ["auth-1"]]])))

    @Test func registersWithConfiguredRpIdAndSubmitsCreateAuthenticators() async throws {
        let server = MockServer()
        let registrar = FakeRegistrar()
        let (ctx, sessionKey) = try await signedIn(server, registration: registrar)
        server.on("/public/v1/submit/create_authenticators", respond: Self.created)

        let id = try await ctx.addPasskey(name: "iPhone 17")
        #expect(id == "auth-1")

        let reg = try #require(registrar.seen.first)
        #expect(reg.rpId == "login.example.org")
        #expect(reg.userName == "iPhone 17" && reg.displayName == "iPhone 17")
        #expect(reg.challenge.count == 32 && reg.userId.count == 32)

        let req = try #require(server.requests(to: "/public/v1/submit/create_authenticators").first)
        _ = try verifyStamp(req, publicKey: sessionKey)
        #expect(req.json["type"] as? String == "ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2")
        #expect(req.json["organizationId"] as? String == "org-sub")
        let params = try #require(req.json["parameters"] as? [String: Any])
        #expect(params["userId"] as? String == "u-1")
        let auths = try #require(params["authenticators"] as? [[String: Any]])
        #expect(auths.count == 1)
        #expect(auths[0]["authenticatorName"] as? String == "iPhone 17")
        #expect(auths[0]["challenge"] as? String == Base64URL.encode(reg.challenge))
        // FakeRegistrar returns credentialId C0FFEE, clientData "{}", attestationObject A101.
        #expect((auths[0]["attestation"] as? [String: AnyHashable]) == [
            "credentialId": "wP_u", "clientDataJson": "e30", "attestationObject": "oQE",
            "transports": ["AUTHENTICATOR_TRANSPORT_INTERNAL"] as [String],
        ])
    }

    @Test func explicitUserAndOrganizationAndDefaultName() async throws {
        let server = MockServer()
        let registrar = FakeRegistrar()
        let (ctx, _) = try await signedIn(server, registration: registrar)
        server.on("/public/v1/submit/create_authenticators", respond: Self.created)
        _ = try await ctx.addPasskey(userId: "u-2", organizationId: "org-other")
        let req = try #require(server.requests(to: "/public/v1/submit/create_authenticators").first)
        #expect(req.json["organizationId"] as? String == "org-other")
        #expect((req.json["parameters"] as? [String: Any])?["userId"] as? String == "u-2")
        let name = try #require(registrar.seen.first?.userName)
        #expect(name == "0xkey Passkey-1763500000000")   // makeContext clock: 1_763_500_000 s
        let sent = (req.json["parameters"] as? [String: Any])?["authenticators"] as? [[String: Any]]
        #expect(sent?.first?["authenticatorName"] as? String == "0xkey Passkey-1763500000000")
    }

    @Test func providerCancelSendsNothing() async throws {
        let server = MockServer()
        let registrar = CancelingRegistrar()
        let (ctx, _) = try await signedIn(server, registration: registrar)
        await #expect(throws: ZeroXKeyPasskeyError.canceled) { try await ctx.addPasskey() }
        #expect(registrar.calls == 1)
        #expect(server.requests.isEmpty)
        #expect(ctx.authState == .authenticated)
    }

    @Test func unauthorizedJsonReasonSurfaces() async throws {
        let server = MockServer()
        let (ctx, _) = try await signedIn(server, registration: FakeRegistrar())
        server.on("/public/v1/submit/create_authenticators", respond: .json([
            "code": 16, "message": "unauthenticated",
            "details": [["@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "WEBAUTHN_RP_ID_NOT_ALLOWED"]],
        ], status: 401))
        await #expect {
            try await ctx.addPasskey()
        } throws: { ($0 as? ZeroXKeyRequestError)?.reason == .webAuthnRpIdNotAllowed }
    }

    @Test func preconditions() async throws {
        let server = MockServer()
        await #expect(throws: ZeroXKeyError.noActiveSession) {
            try await makeContext(server, rpId: "x", registration: FakeRegistrar()).addPasskey()
        }
        let (noProvider, _) = try await signedIn(server, registration: nil)
        await #expect(throws: ZeroXKeyError.missingPasskeyProvider) { try await noProvider.addPasskey() }
        let (noRp, _) = try await signedIn(server, registration: FakeRegistrar(), rpId: nil)
        await #expect(throws: ZeroXKeyError.missingRpId) { try await noRp.addPasskey() }
        let (ctx, _) = try await signedIn(server, registration: FakeRegistrar())
        for bad in ["", "emoji 🔑", String(repeating: "a", count: 65)] {
            await #expect(throws: ZeroXKeyError.self, "\(bad)") { try await ctx.addPasskey(name: bad) }
        }
        #expect(server.requests.isEmpty)
    }

    @Test func emptyAuthenticatorIdsIsBadResponse() async throws {
        let server = MockServer()
        let (ctx, _) = try await signedIn(server, registration: FakeRegistrar())
        server.on("/public/v1/submit/create_authenticators", respond: .json(APIFixtures.activityResponse(APIFixtures.activity(
            status: "ACTIVITY_STATUS_COMPLETED", result: ["createAuthenticatorsResult": ["authenticatorIds": [String]()]]))))
        await #expect(throws: ZeroXKeyError.badResponse("create_authenticators returned no authenticator ID")) {
            try await ctx.addPasskey()
        }
    }
}
