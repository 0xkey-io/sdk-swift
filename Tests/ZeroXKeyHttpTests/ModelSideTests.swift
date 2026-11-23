import Foundation
import Testing
import ZeroXKeyHttp

/// Models are generated per side: request-only models keep swagger-required message fields
/// required; response-only and shared (request + response) models make message fields Optional.
@Suite("Model sides (request / response / both)")
struct ModelSideTests {
    static let attestation = v1Attestation(credentialId: "Y3JlZA", clientDataJson: "e30", attestationObject: "oQE",
                                           transports: [.AUTHENTICATOR_TRANSPORT_INTERNAL])

    @Test func requestOnlyModelKeepsRequiredMessage() throws {
        // v1CreateAuthenticatorsRequest is only ever sent: `parameters` is a non-optional stored property.
        let req = v1CreateAuthenticatorsRequest(
            type: "ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2", timestampMs: "1", organizationId: "o",
            parameters: v1CreateAuthenticatorsIntentV2(authenticators: [], userId: "u"))
        let params: v1CreateAuthenticatorsIntentV2 = req.parameters   // compiles only if non-optional
        #expect(params.userId == "u")
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(v1CreateAuthenticatorsRequest.self, from: Data(
                #"{"type":"ACTIVITY_TYPE_CREATE_AUTHENTICATORS_V2","timestampMs":"1","organizationId":"o","parameters":null}"#.utf8))
        }
    }

    @Test func sharedModelFieldStaysOptional() throws {
        // v1AuthenticatorParamsV2 is sent in create_authenticators and echoed in activity.intent
        // of responses, where the gateway may emit null: decoding must succeed.
        let decoded = try JSONDecoder().decode(v1AuthenticatorParamsV2.self, from: Data(
            #"{"authenticatorName":"a","challenge":"c","attestation":null}"#.utf8))
        #expect(decoded.attestation == nil)
        // Request bytes when set (ZeroXKeyClient encodes bodies with .sortedKeys).
        let p = v1AuthenticatorParamsV2(authenticatorName: "iPhone", challenge: "Y2g", attestation: Self.attestation)
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        #expect(String(decoding: try enc.encode(p), as: UTF8.self)
                == #"{"attestation":{"attestationObject":"oQE","clientDataJson":"e30","credentialId":"Y3JlZA","transports":["AUTHENTICATOR_TRANSPORT_INTERNAL"]},"authenticatorName":"iPhone","challenge":"Y2g"}"#)
    }

    @Test func responseOnlyModelIsOptional() throws {
        let vote = try JSONDecoder().decode(v1Vote.self, from: Data(
            #"{"id":"v","userId":"u","user":null,"activityId":"a","selection":"VOTE_SELECTION_APPROVED","message":"","publicKey":"","signature":"","scheme":"","createdAt":null}"#.utf8))
        #expect(vote.user == nil && vote.createdAt == nil)
        // No strict encoder: re-encoding a decoded response value works.
        #expect(try !JSONEncoder().encode(vote).isEmpty)
    }
}
