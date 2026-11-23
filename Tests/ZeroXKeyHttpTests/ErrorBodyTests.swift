import Foundation
import Testing
import ZeroXKeyCrypto
import ZeroXKeyHttp
import ZeroXKeyStamper
import ZeroXKeyTestSupport

@Suite("Error bodies")
struct ErrorBodyTests {
    let key = generateP256KeyPair()
    var stamper: ApiKeyStamper { try! ApiKeyStamper(apiPublicKey: key.publicKey, apiPrivateKey: key.privateKey) }

    func fail(_ response: MockResponse) async throws -> ZeroXKeyRequestError {
        let server = MockServer()
        server.on("/public/v1/query/whoami", respond: response)
        do {
            _ = try await makeClient(server, stamper: stamper).getWhoami()
        } catch let e as ZeroXKeyRequestError {
            return e
        }
        throw CocoaError(.featureUnsupported)
    }

    @Test func unauthorizedGrpcJsonWithRpIdReason() async throws {
        // Planned gateway shape: gRPC status with google.rpc.ErrorInfo reason.
        let e = try await fail(.json([
            "code": 16, "message": "unauthenticated",
            "details": [["@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "WEBAUTHN_RP_ID_NOT_ALLOWED", "domain": "0xkey.io"]],
        ], status: 401))
        #expect(e.kind == .grpcStatus && e.httpStatus == 401 && e.code == 16 && e.message == "unauthenticated")
        #expect(e.reason == .webAuthnRpIdNotAllowed)
        #expect(e.errorInfoReasons == ["WEBAUTHN_RP_ID_NOT_ALLOWED"])
        #expect(e.isUnauthenticated)
        #expect(e.description.contains("WEBAUTHN_RP_ID_NOT_ALLOWED"))
    }

    @Test func originNotAllowedReason() async throws {
        let e = try await fail(.json([
            "code": 16, "message": "unauthenticated",
            "details": [["@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "WEBAUTHN_ORIGIN_NOT_ALLOWED"]],
        ], status: 401))
        #expect(e.reason == .webAuthnOriginNotAllowed)
    }

    @Test func unauthorizedPlainTextFromCurrentGateway() async throws {
        // Byte-identical to Go's http.Error(w, "Unauthorized: "+err.Error(), 401).
        let e = try await fail(.text("Unauthorized: RP ID hash mismatch\n", status: 401))
        #expect(e.kind == .plainText)
        #expect(e.httpStatus == 401 && e.code == 16)
        #expect(e.message == "Unauthorized: RP ID hash mismatch")
        #expect(e.rawBody == "Unauthorized: RP ID hash mismatch\n")
        #expect(e.reason == .webAuthnRpIdNotAllowed)
        #expect(e.details.isEmpty)

        let other = try await fail(.text("Unauthorized: missing authentication stamp\n", status: 401))
        #expect(other.kind == .plainText && other.reason == nil && other.isUnauthenticated)
    }

    @Test func otherReasonIsPreserved() async throws {
        let e = try await fail(.json([
            "code": 7, "message": "denied",
            "details": [["@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "POLICY_DENIED"]],
        ], status: 403))
        #expect(e.reason == .other("POLICY_DENIED") && e.code == 7 && !e.isUnauthenticated)
    }

    @Test func serverErrorsAndNonJson() async throws {
        let html = try await fail(MockResponse(status: 502, body: Data("<html>bad gateway</html>".utf8), headers: ["Content-Type": "text/html"]))
        #expect(html.kind == .plainText && html.code == 13 && html.httpStatus == 502)

        let empty = try await fail(MockResponse(status: 503, body: Data(), headers: [:]))
        #expect(empty.kind == .empty && empty.code == 14 && !empty.message.isEmpty)

        let grpc500 = try await fail(.json(["code": 13, "message": "internal error", "details": []], status: 500))
        #expect(grpc500.kind == .grpcStatus && grpc500.code == 13 && grpc500.message == "internal error")

        let jsonNotStatus = try await fail(MockResponse(status: 500, body: Data("[1,2]".utf8)))
        #expect(jsonNotStatus.kind == .plainText && jsonNotStatus.message == "[1,2]")
    }

    @Test func rateLimitKeepsRetryAfter() async throws {
        let e = try await fail(MockResponse(status: 429, body: Data(#"{"code":8,"message":"slow down"}"#.utf8),
                                            headers: ["Content-Type": "application/json", "Retry-After": "7"]))
        #expect(e.code == 8 && e.retryAfter == "7")
    }

    @Test func successWithUndecodableBodyIsDecodingError() async throws {
        let server = MockServer()
        server.on("/public/v1/query/whoami", respond: .json(["unexpected": true]))
        await #expect {
            try await makeClient(server, stamper: stamper).getWhoami()
        } throws: { error in
            if case ZeroXKeyHttpError.decodingFailed(let type, _) = error { return type == "TGetWhoamiResponse" }
            return false
        }
    }

    @Test func grpcCodeMapping() {
        #expect(ZeroXKeyRequestError.grpcCode(forHTTPStatus: 400) == 3)
        #expect(ZeroXKeyRequestError.grpcCode(forHTTPStatus: 401) == 16)
        #expect(ZeroXKeyRequestError.grpcCode(forHTTPStatus: 404) == 5)
        #expect(ZeroXKeyRequestError.grpcCode(forHTTPStatus: 418) == 2)
    }
}
