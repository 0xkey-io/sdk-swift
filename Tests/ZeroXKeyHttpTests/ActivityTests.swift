import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

@Suite("Activities and polling")
struct ActivityTests {
    let key = generateP256KeyPair()
    var stamper: ApiKeyStamper { try! ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey) }
    let signBody = TSignRawPayloadBody(signWith: "0xabc", payload: "0x68656c6c6f",
                                       encoding: .PAYLOAD_ENCODING_HEXADECIMAL, hashFunction: .HASH_FUNCTION_KECCAK256)
    static var sigResult: [String: Any] { ["signRawPayloadResult": ["r": "aa", "s": "bb", "v": "01"]] }

    @Test func envelopeMatchesSdkJsActivityShape() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(status: "ACTIVITY_STATUS_COMPLETED", result: Self.sigResult))))
        let res = try await makeClient(server, stamper: stamper).signRawPayload(signBody)
        #expect(res.r == "aa" && res.s == "bb" && res.v == "01")
        #expect(res.activity.status == .ACTIVITY_STATUS_COMPLETED)

        let req = try #require(server.requests.first)
        let json = req.json
        #expect(Set(json.keys) == ["organizationId", "parameters", "timestampMs", "type"])
        #expect(json["type"] as? String == "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2")
        #expect(json["organizationId"] as? String == "org-default")
        #expect(json["timestampMs"] as? String == "1763500000123")
        let params = try #require(json["parameters"] as? [String: String])
        #expect(params == ["signWith": "0xabc", "payload": "0x68656c6c6f",
                           "encoding": "PAYLOAD_ENCODING_HEXADECIMAL", "hashFunction": "HASH_FUNCTION_KECCAK256"])
        #expect(try verifyApiKeyStamp(req.header("X-Stamp"), body: req.body, expectedPublicKey: key.publicKey))
    }

    @Test func explicitTimestampAndOrgArePassedThrough() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(status: "ACTIVITY_STATUS_COMPLETED", result: Self.sigResult))))
        var body = signBody
        body.organizationId = "org-x"
        body.timestampMs = "42"
        _ = try await makeClient(server, stamper: stamper).signRawPayload(body)
        let json = try #require(server.requests.first).json
        #expect(json["organizationId"] as? String == "org-x" && json["timestampMs"] as? String == "42")
        #expect((json["parameters"] as? [String: Any])?.keys.contains("organizationId") == false)
    }

    @Test func pollsGetActivityUntilCompleted() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(id: "act-9", organizationId: "org-sub", status: "ACTIVITY_STATUS_PENDING"))))
        server.on("/public/v1/query/get_activity") { _, n in
            .json(APIFixtures.activityResponse(APIFixtures.activity(
                id: "act-9", organizationId: "org-sub",
                status: n < 1 ? "ACTIVITY_STATUS_PENDING" : "ACTIVITY_STATUS_COMPLETED",
                result: n < 1 ? [:] : Self.sigResult)))
        }
        let res = try await makeClient(server, stamper: stamper).signRawPayload(signBody)
        #expect(res.r == "aa")
        let polls = server.requests(to: "/public/v1/query/get_activity")
        #expect(polls.count == 2)
        for p in polls {
            #expect(p.json["activityId"] as? String == "act-9")
            #expect(p.json["organizationId"] as? String == "org-sub")
            #expect(try verifyApiKeyStamp(p.header("X-Stamp"), body: p.body, expectedPublicKey: key.publicKey))
        }
    }

    @Test func pollingStopsAfterNumRetries() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(status: "ACTIVITY_STATUS_CREATED"))))
        server.on("/public/v1/query/get_activity", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(status: "ACTIVITY_STATUS_PENDING"))))
        let client = makeClient(server, stamper: stamper, poller: .init(intervalMs: 1, numRetries: 2))
        await #expect(throws: ZeroXKeyActivityError.pollingTimedOut(activityId: "act-1", status: "ACTIVITY_STATUS_PENDING", attempts: 2)) {
            try await client.signRawPayload(signBody)
        }
        #expect(server.requests(to: "/public/v1/query/get_activity").count == 2)
    }

    @Test func failedRejectedConsensusAuthenticatorsAreNamedErrors() async throws {
        let failure: [String: Any] = ["code": 3, "message": "signWith not found", "details": []]
        let cases: [(String, ZeroXKeyActivityError)] = [
            ("ACTIVITY_STATUS_FAILED", .failed(activityId: "act-1", status: "ACTIVITY_STATUS_FAILED",
                                               failure: .object(["code": .number(3), "message": .string("signWith not found"), "details": .array([])]))),
            ("ACTIVITY_STATUS_REJECTED", .rejected(activityId: "act-1")),
            ("ACTIVITY_STATUS_CONSENSUS_NEEDED", .consensusNeeded(activityId: "act-1", fingerprint: "fp-1")),
            // get_mfa_status is unrouted (404) here, so the statuses are empty.
            ("ACTIVITY_STATUS_AUTHENTICATORS_NEEDED", .authenticatorsNeeded(activityId: "act-1", mfaStatuses: [])),
        ]
        for (status, expected) in cases {
            let server = MockServer()
            let act = APIFixtures.activity(status: status, failure: status.hasSuffix("FAILED") ? failure : nil)
            server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(act)))
            server.on("/public/v1/query/get_activity", respond: .json(APIFixtures.activityResponse(act)))
            let client = makeClient(server, stamper: stamper)
            await #expect(throws: expected) { try await client.signRawPayload(signBody) }
            // CONSENSUS_NEEDED is not terminal in sdk-js, so it is polled first.
            let expectedPolls = status == "ACTIVITY_STATUS_CONSENSUS_NEEDED" ? 3 : 0
            #expect(server.requests(to: "/public/v1/query/get_activity").count == expectedPolls, "\(status)")
        }
    }

    @Test func authenticatorsNeededCarriesMfaStatus() async throws {
        let server = MockServer()
        let act = APIFixtures.activity(organizationId: "org-sub", status: "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED")
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(act)))
        server.on("/public/v1/query/get_mfa_status", respond: .json(["mfaStatuses": [[
            "mfaPolicyId": "pol-1", "userId": "u-1", "satisfied": false,
            "satisfiedMethods": [], "requiredMethods": [],
        ]]]))
        let client = makeClient(server, stamper: stamper)
        await #expect(throws: ZeroXKeyActivityError.authenticatorsNeeded(activityId: "act-1", mfaStatuses: [
            v1MfaStatus(mfaPolicyId: "pol-1", userId: "u-1", satisfied: false, satisfiedMethods: [], requiredMethods: []),
        ])) { try await client.signRawPayload(signBody) }
        let mfa = try #require(server.requests(to: "/public/v1/query/get_mfa_status").first)
        #expect(mfa.json["activityId"] as? String == "act-1")
        #expect(mfa.json["organizationId"] as? String == "org-sub")
        #expect(try verifyApiKeyStamp(mfa.header("X-Stamp"), body: mfa.body, expectedPublicKey: stamper.apiPublicKey))
    }

    @Test func undecodableMfaStatusIsThrownNotEmptied() async throws {
        let server = MockServer()
        let act = APIFixtures.activity(status: "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED")
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(act)))
        server.on("/public/v1/query/get_mfa_status", respond: .json(["mfaStatuses": [["mfaPolicyId": 7, "userId": "u-1"]]]))
        let client = makeClient(server, stamper: stamper)
        do {
            _ = try await client.signRawPayload(signBody)
            Issue.record("expected a decoding error")
        } catch let error as ZeroXKeyHttpError {
            guard case .decodingFailed(let type, _) = error else { Issue.record("\(error)"); return }
            #expect(type.contains("GetMfaStatus"))
        }
    }

    /// C1 applies to the MFA status too: production may omit empty arrays and `false`.
    @Test func mfaStatusWithoutArraysAndFalseDecodes() async throws {
        let server = MockServer()
        let act = APIFixtures.activity(status: "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED")
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(act)))
        server.on("/public/v1/query/get_mfa_status", respond: .text(
            #"{"mfaStatuses":[{"mfaPolicyId":"pol-1","userId":"u-1","requiredMethods":[{}]},{"mfaPolicyId":"pol-2","userId":"u-1","satisfied":null,"satisfiedMethods":null}]}"#,
            status: 200))
        let client = makeClient(server, stamper: stamper)
        await #expect(throws: ZeroXKeyActivityError.authenticatorsNeeded(activityId: "act-1", mfaStatuses: [
            v1MfaStatus(mfaPolicyId: "pol-1", userId: "u-1", satisfied: false, satisfiedMethods: [],
                        requiredMethods: [v1RequiredAuthenticationMethod(any: [])]),
            v1MfaStatus(mfaPolicyId: "pol-2", userId: "u-1", satisfied: false, satisfiedMethods: [], requiredMethods: []),
        ])) { try await client.signRawPayload(signBody) }
    }

    /// A held activity as an EmitUnpopulated-free server could send it: no votes, no result,
    /// no canApprove / canReject.
    @Test func heldActivityWithoutVotesDecodes() throws {
        let json = #"{"activity":{"id":"act-1","organizationId":"org-1","status":"ACTIVITY_STATUS_AUTHENTICATORS_NEEDED","type":"ACTIVITY_TYPE_STAMP_LOGIN","fingerprint":"fp-1"}}"#
        let res = try JSONDecoder().decode(TGetActivityResponse.self, from: Data(json.utf8))
        let a = try #require(res.activity)
        #expect(a.votes.isEmpty && a.canApprove == false && a.canReject == false && a.result == nil)
        #expect(a.fingerprint == "fp-1")
    }

    @Test func versionedResultKeyFallback() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/create_sub_organization", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8",
                                 result: ["createSubOrganizationResultV9": ["subOrganizationId": "sub-9", "rootUserIds": ["u"]]]))))
        let res = try await makeClient(server, stamper: stamper).createSubOrganization(TCreateSubOrganizationBody(
            subOrganizationName: "s", rootUsers: [], rootQuorumThreshold: 1))
        #expect(res.subOrganizationId == "sub-9")
        #expect(server.requests.first?.json["type"] as? String == "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8")
    }

    @Test func completedWithoutResultIsMissingResult() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(status: "ACTIVITY_STATUS_COMPLETED", result: [:]))))
        await #expect(throws: ZeroXKeyActivityError.missingResult(activityId: "act-1", resultKey: "signRawPayloadResult")) {
            try await makeClient(server, stamper: stamper).signRawPayload(signBody)
        }
    }

    @Test func approveActivityIsNotPolled() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/approve_activity", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(status: "ACTIVITY_STATUS_PENDING", type: "ACTIVITY_TYPE_APPROVE_ACTIVITY"))))
        let res = try await makeClient(server, stamper: stamper).approveActivity(TApproveActivityBody(fingerprint: "fp-1"))
        #expect(res.activity.status == .ACTIVITY_STATUS_PENDING)
        #expect(server.requests.count == 1)
        #expect(server.requests.first?.json["type"] as? String == "ACTIVITY_TYPE_APPROVE_ACTIVITY")
    }

    @Test func unknownEnumValuesRoundTrip() async throws {
        let server = MockServer()
        server.on("/public/v1/submit/sign_raw_payload", respond: .json(APIFixtures.activityResponse(
            APIFixtures.activity(status: "ACTIVITY_STATUS_COMPLETED", type: "ACTIVITY_TYPE_FROM_THE_FUTURE_V9", result: Self.sigResult))))
        let res = try await makeClient(server, stamper: stamper).signRawPayload(signBody)
        #expect(res.activity.type.rawValue == "ACTIVITY_TYPE_FROM_THE_FUTURE_V9")
    }

    /// Shape returned by prod for ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V8 (2026-11-19).
    @Test func voteWithNullUserDecodes() throws {
        let json = #"{"id":"v","userId":"u","user":null,"activityId":"a","selection":"VOTE_SELECTION_APPROVED","message":"m","publicKey":"02aa","signature":"30","scheme":"SIGNATURE_SCHEME_TK_API_P256","createdAt":{"seconds":"1","nanos":"0"}}"#
        let vote = try JSONDecoder().decode(v1Vote.self, from: Data(json.utf8))
        #expect(vote.user == nil && vote.userId == "u")
    }
}
