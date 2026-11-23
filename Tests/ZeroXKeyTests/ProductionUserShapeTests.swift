import Foundation
import Testing
import ZeroXKey
import ZeroXKeyTestSupport

/// `get_user` as production returns it: no `mfaPolicies` key (the swagger snapshot is newer than
/// the deployed server). Shape and key set taken from a production response; values neutral.
@Suite("Production get_user shape") @MainActor
struct ProductionUserShapeTests {
    static let prodGetUser = #"""
    {"user":{
      "apiKeys":[{"apiKeyId":"00000000-0000-4000-8000-0000000000a2","apiKeyName":"passkey-auth",
        "createdAt":{"nanos":"0","seconds":"1795125557"},
        "credential":{"publicKey":"02aa","type":"CREDENTIAL_TYPE_API_KEY_P256"},
        "updatedAt":{"nanos":"0","seconds":"1795125557"}}],
      "authenticators":[{"aaguid":"AAAAAAAAAAAAAAAAAAAAAA==","attestationType":"public-key",
        "authenticatorId":"00000000-0000-4000-8000-0000000000a3","authenticatorName":"Example passkey",
        "createdAt":{"nanos":"0","seconds":"1795125557"},
        "credential":{"publicKey":"04bb","type":"CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR"},
        "credentialId":"Y3JlZA","model":"Security key","transports":["AUTHENTICATOR_TRANSPORT_INTERNAL"],
        "updatedAt":{"nanos":"0","seconds":"1795125557"}}],
      "createdAt":{"nanos":"0","seconds":"1795125557"},
      "oauthProviders":[],
      "updatedAt":{"nanos":"0","seconds":"1795125557"},
      "userId":"00000000-0000-4000-8000-0000000000a1",
      "userName":"Example user",
      "userTags":[]
    }}
    """#

    @Test func refreshUserDecodesUserWithoutMfaPolicies() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(
            publicKey: key, organizationId: "org-1", userId: "00000000-0000-4000-8000-0000000000a1", exp: 1_763_500_900))
        server.on("/public/v1/query/get_user", respond: .text(Self.prodGetUser, status: 200))
        let user = try await ctx.refreshUser()
        #expect(user.userId == "00000000-0000-4000-8000-0000000000a1")
        #expect(user.mfaPolicies.isEmpty)
        #expect(user.authenticators.first?.credentialId == "Y3JlZA")
        #expect(user.apiKeys.count == 1)
        #expect(ctx.user?.userName == "Example user")
    }

    @Test func userWithoutIdStillFails() async throws {
        let server = MockServer()
        let ctx = makeContext(server)
        let key = try ctx.createKeyPair()
        try await ctx.storeSession(jwt: APIFixtures.sessionJWT(publicKey: key, organizationId: "org-1", userId: "u", exp: 1_763_500_900))
        let withoutId = Self.prodGetUser.replacingOccurrences(of: #""userId":"00000000-0000-4000-8000-0000000000a1","#, with: "")
        #expect(withoutId != Self.prodGetUser)
        server.on("/public/v1/query/get_user", respond: .text(withoutId, status: 200))
        await #expect(throws: (any Error).self) { try await ctx.refreshUser() }
    }
}
