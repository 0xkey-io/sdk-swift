import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

/// The gateway emits unset sub-messages as JSON `null` (protojson `EmitUnpopulated`). Generated
/// response types and models must decode such payloads (see the generator's message-field rule).
@Suite("Null-tolerant decoding")
struct NullTolerantDecodingTests {
    @Test func everyGeneratedTypeDecodesNullAndMissingMessageFields() throws {
        let cases = NullDecodeCases.all
        #expect(cases.count == NullDecodeCases.totalCount)
        #expect(Set(cases.map(\.name)).count == cases.count)
        // Every endpoint (public + Auth Proxy) has exactly one response type, all of them covered.
        #expect(cases.filter { $0.name.hasSuffix("Response") && ($0.name.hasPrefix("T") || $0.name.hasPrefix("ProxyT")) }.count
                == ZeroXKeyAPIManifest.endpoints.count)
        #expect(NullDecodeCases.responseTypeCount == ZeroXKeyAPIManifest.endpoints.count)
        var withMessageFields = 0
        for c in cases {
            for json in [c.nullJSON, c.missingJSON] {
                let encoded: Data
                do {
                    encoded = try c.roundTrip(Data(json.utf8))
                } catch {
                    Issue.record("\(c.name) failed to decode \(json): \(error)")
                    continue
                }
                // Null / absent message fields decode to nil, so they are not re-encoded.
                let obj = try #require(try JSONSerialization.jsonObject(with: encoded) as? [String: Any], "\(c.name)")
                for key in c.nilKeys { #expect(obj[key] == nil, "\(c.name).\(key)") }
            }
            if !c.nilKeys.isEmpty { withMessageFields += 1 }
        }
        #expect(withMessageFields == NullDecodeCases.withMessageFieldsCount)
        #expect(withMessageFields > 0)
    }

    /// Field-deletion property: every required non-message field of every decoded type, except
    /// the generator's DECODE_STRICT_FIELDS, may be absent or null and decodes as its zero value;
    /// the strict ones are still required.
    @Test func everyRequiredFieldMayBeMissingExceptStrictOnes() throws {
        func object(_ json: String) throws -> [String: Any] {
            try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        }
        func data(_ obj: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: obj) }
        var zeroChecked = 0, strictChecked = 0
        for c in NullDecodeCases.all {
            let base = try object(c.missingJSON)
            for key in c.zeroKeys {
                #expect(base[key] != nil, "\(c.name).\(key) not in base JSON")
                var without = base
                without[key] = nil
                var asNull = base
                asNull[key] = NSNull()
                for variant in [without, asNull] {
                    do {
                        let encoded = try object(String(decoding: c.roundTrip(data(variant)), as: UTF8.self))
                        // Non-optional: the zero value is filled in and encoded again.
                        #expect(encoded[key] != nil && !(encoded[key] is NSNull), "\(c.name).\(key)")
                    } catch {
                        Issue.record("\(c.name) without \(key): \(error)")
                    }
                }
                zeroChecked += 1
            }
            if !c.zeroKeys.isEmpty {
                var none = base
                for key in c.zeroKeys { none[key] = nil }
                do { _ = try c.roundTrip(data(none)) } catch { Issue.record("\(c.name) without all zero-value keys: \(error)") }
            }
            for key in c.strictKeys {
                var without = base
                without[key] = nil
                #expect(throws: DecodingError.self, "\(c.name).\(key) must stay required") { _ = try c.roundTrip(data(without)) }
                strictChecked += 1
            }
        }
        #expect(zeroChecked == NullDecodeCases.zeroKeyCount && zeroChecked > 0)
        #expect(strictChecked == NullDecodeCases.strictKeyCount && strictChecked > 0)
    }

    @Test func nonMessageRequiredFieldsStillRequired() {
        // A required scalar that is missing must still fail: the rule only relaxes message fields.
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(TGetWhoamiResponse.self, from: Data("{}".utf8)) }
    }
}

/// Hand-written responses in the shape production returns.
@Suite("Production-shaped responses")
struct ProductionShapedResponseTests {
    func client(_ server: MockServer) throws -> ZeroXKeyClient {
        let key = generateP256KeyPair()
        return makeClient(server, stamper: try ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey))
    }

    static func json(_ text: String) -> MockResponse {
        MockResponse(status: 200, body: Data(text.utf8), headers: ["Content-Type": "application/json"])
    }

    @Test func createSubOrganizationWithNullVoteUserAndNullTimestamps() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/create_sub_organization", respond: Self.json(#"""
        {"activity":{"id":"act-1","organizationId":"org-1","status":"ACTIVITY_STATUS_COMPLETED",
         "type":"ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8","intent":{"createSubOrganizationIntentV8":null},
         "result":{"createSubOrganizationResultV8":{"subOrganizationId":"sub-1","wallet":null,"rootUserIds":["u-1"]},
                   "createWalletResult":null,"signRawPayloadResult":null},
         "votes":[{"id":"v-1","userId":"u-0","user":null,"activityId":"act-1","selection":"VOTE_SELECTION_APPROVED",
                   "message":"","publicKey":"02aa","signature":"","scheme":"","createdAt":null}],
         "fingerprint":"fp","timestampMs":"1763500000000","canApprove":false,"canReject":false,"createdAt":null,"updatedAt":null,
         "failure":null,"appProofs":[]}}
        """#))
        let res = try await client(server).createSubOrganization(TCreateSubOrganizationBody(
            subOrganizationName: "s", rootUsers: [], rootQuorumThreshold: 1))
        #expect(res.subOrganizationId == "sub-1")
        #expect(res.wallet == nil)
        #expect(res.activity.votes.first?.user == nil)
        #expect(res.activity.createdAt == nil)
    }

    @Test func getWalletsWithMissingTimestamps() async throws {
        let server = MockServer()
        server.on("/public/v1/query/list_wallets", respond: Self.json(#"""
        {"wallets":[{"walletId":"w-1","walletName":"Main","exported":false,"imported":false}]}
        """#))
        let res = try await client(server).getWallets()
        #expect(res.wallets.map(\.walletId) == ["w-1"])
        #expect(res.wallets.first?.createdAt == nil)
    }

    @Test func getUserWithNullUser() async throws {
        let server = MockServer()
        server.on("/public/v1/query/get_user", respond: Self.json(#"{"user":null}"#))
        let res = try await client(server).getUser(TGetUserBody(userId: "u-1"))
        #expect(res.user == nil)
    }

    @Test func sendTransactionStatusWithNullChainSections() async throws {
        let server = MockServer()
        server.on("/public/v1/query/get_send_transaction_status", respond: Self.json(#"""
        {"txStatus":"INCLUDED","eth":{"txHash":"0xabc"},"sol":null,"tron":null,"error":null,"txError":""}
        """#))
        let res = try await client(server).getSendTransactionStatus(TGetSendTransactionStatusBody(sendTransactionStatusId: "s"))
        #expect(res.eth?.txHash == "0xabc")
        #expect(res.sol == nil && res.error == nil)
    }
}
