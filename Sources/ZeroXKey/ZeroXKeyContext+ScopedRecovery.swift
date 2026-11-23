import Foundation
import ZeroXKeyHttp
import ZeroXKeyStamper

// Experimental: scoped session recovery. The 0xkey servers do not support attested scoped
// `stamp_login` yet (the enclave rejects `sessionProfileId` on attested STAMP_LOGIN, the Auth Proxy
// rejects OTP logins with a profile), so everything here is `@_spi(Experimental)`:
// `@_spi(Experimental) import ZeroXKey` to use it.

/// **Experimental.** An OTP login held by an MFA policy (`ACTIVITY_STATUS_AUTHENTICATORS_NEEDED`).
///
/// Approve it with a second factor (``ZeroXKeyContext/approvePendingLogin(_:stamper:)``), then
/// finish it with ``ZeroXKeyContext/resumeOtpLogin(_:maxAttempts:intervalSeconds:)``. Holds the
/// verification token, which keeps authorizing the pending `stamp_login`: treat it like a secret
/// and do not persist it. `description`, `debugDescription` and reflection (`dump`) redact it.
@_spi(Experimental)
public struct PendingOtpLogin: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The held `STAMP_LOGIN` activity.
    public let activityId: String
    /// Organization the activity runs in (the user's sub-organization).
    public let organizationId: String
    /// Fingerprint that `approve_activity` must reference.
    public let fingerprint: String
    /// MFA policies still to satisfy (best effort `get_mfa_status`; empty if unavailable).
    public let mfaStatuses: [v1MfaStatus]
    /// Session public key (the verification-token key) the resulting session will use.
    public let publicKey: String
    /// Session profile requested for the login, if any.
    public let sessionProfileId: String?
    /// Local session key the session is stored under when the login completes.
    public let sessionKey: String
    let verificationToken: String

    public var description: String {
        "PendingOtpLogin(activityId: \(activityId), organizationId: \(organizationId), fingerprint: \(fingerprint), "
            + "mfaStatuses: \(mfaStatuses.count), publicKey: \(publicKey), sessionProfileId: \(sessionProfileId ?? "nil"), "
            + "sessionKey: \(sessionKey), verificationToken: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: [
            "activityId": activityId, "organizationId": organizationId, "fingerprint": fingerprint,
            "mfaStatuses": mfaStatuses, "publicKey": publicKey, "sessionProfileId": sessionProfileId as Any,
            "sessionKey": sessionKey, "verificationToken": "<redacted>",
        ], displayStyle: .struct)
    }
}

/// **Experimental.** Result of `beginOtpLogin`.
@_spi(Experimental)
public enum OtpLoginOutcome: Sendable, Equatable {
    /// Logged in; the session is stored and active.
    case completed(session: String)
    /// An MFA policy holds the login: approve with a second factor, then resume.
    case mfaRequired(PendingOtpLogin)
}

/// Scoped session recovery on 0xkey endpoints:
///
/// 1. OTP verification token → `beginOtpLogin`
///    with the recovery session profile; the login may be held by an MFA policy.
/// 2. A second factor approves the held activity (`approve_activity`) —
///    `approvePendingLogin(_:stamper:)`, e.g. with a passkey, an API key or another attested key.
/// 3. `resumeOtpLogin(_:maxAttempts:intervalSeconds:)` polls the activity and stores the
///    scoped session.
/// 4. With that session, enroll a replacement passkey: `addPasskey(name:userId:organizationId:)`.
///
/// Endpoints: `stamp_login` (`sessionProfileId`), `get_activity`, `get_mfa_status`,
/// `approve_activity`. Session profiles themselves are created server side
/// (`create_session_profile`).
extension ZeroXKeyContext {
    /// Starts an OTP login that may be held by MFA. Like `loginWithOtp`, but returns
    /// ``OtpLoginOutcome/mfaRequired(_:)`` instead of throwing when an MFA policy holds it.
    /// No Auth Proxy fallback (it cannot hold or resume a login).
    @_spi(Experimental)
    public func beginOtpLogin(
        verificationToken: String, organizationId: String? = nil, sessionProfileId: String? = nil,
        invalidateExisting: Bool = false, expirationSeconds: String? = nil,
        sessionKey: String = ZeroXKeySessionKey.default
    ) async throws -> OtpLoginOutcome {
        let login = try await prepareOtpLogin(verificationToken: verificationToken, organizationId: organizationId)
        let client = try baseClient(stamper: login.attested, organizationId: login.organizationId)
        let lifetime = await resolvedExpirationSeconds(expirationSeconds)
        do {
            let res = try await client.stampLogin(TStampLoginBody(
                publicKey: login.publicKey, expirationSeconds: lifetime,
                invalidateExisting: invalidateExisting ? true : nil, sessionProfileId: sessionProfileId,
                organizationId: login.organizationId))
            guard !res.session.isEmpty else { throw ZeroXKeyError.badResponse("stamp_login returned no session") }
            try await storeSession(jwt: res.session, sessionKey: sessionKey)
            return .completed(session: res.session)
        } catch ZeroXKeyActivityError.authenticatorsNeeded(let activityId, let statuses) {
            // The fingerprint and the activity's organization come from the held activity itself.
            let held = try await client.getActivity(TGetActivityBody(activityId: activityId, organizationId: login.organizationId))
            guard let activity = held.activity, !activity.fingerprint.isEmpty else {
                throw ZeroXKeyError.badResponse("get_activity returned no fingerprint for \(activityId)")
            }
            return .mfaRequired(PendingOtpLogin(
                activityId: activityId, organizationId: activity.organizationId.isEmpty ? login.organizationId : activity.organizationId,
                fingerprint: activity.fingerprint, mfaStatuses: statuses, publicKey: login.publicKey,
                sessionProfileId: sessionProfileId, sessionKey: sessionKey, verificationToken: verificationToken))
        }
    }

    /// Approves a held login with a second factor (`ACTIVITY_TYPE_APPROVE_ACTIVITY`, stamped by
    /// `stamper`, in the pending activity's organization). Returns the approval activity.
    @_spi(Experimental)
    @discardableResult
    public func approvePendingLogin(_ pending: PendingOtpLogin, stamper: any Stamper) async throws -> v1Activity {
        try await baseClient(stamper: stamper, organizationId: pending.organizationId)
            .approveActivity(TApproveActivityBody(fingerprint: pending.fingerprint, organizationId: pending.organizationId))
            .activity
    }

    /// Approves a held login with the user's passkey (`config.rpId`, the configured assertion
    /// provider).
    @_spi(Experimental)
    @discardableResult
    public func approvePendingLoginWithPasskey(_ pending: PendingOtpLogin, allowCredentials: [Data] = []) async throws -> v1Activity {
        guard let provider = passkeyAssertionProvider else { throw ZeroXKeyError.missingPasskeyProvider }
        guard let rpId = config.rpId, !rpId.isEmpty else { throw ZeroXKeyError.missingRpId }
        return try await approvePendingLogin(
            pending, stamper: WebAuthnStamper(rpId: rpId, allowCredentials: allowCredentials, provider: provider))
    }

    /// Polls the held login (`get_activity`, stamped with the verification-token attested key)
    /// until it completes, then stores and returns the (scoped) session.
    /// - Throws: `ZeroXKeyActivityError.authenticatorsNeeded` if still held after `maxAttempts`;
    ///   `.failed` / `.rejected` if the login failed or the approval was rejected.
    @_spi(Experimental)
    @discardableResult
    public func resumeOtpLogin(_ pending: PendingOtpLogin, maxAttempts: Int = 30, intervalSeconds: TimeInterval = 1) async throws -> String {
        let apiKey = try config.keyManager.stamper(forPublicKey: pending.publicKey)
        let attested = AttestedStamper(attestedIdentity: pending.verificationToken, scheme: .p256VerificationToken, apiKey: apiKey)
        let client = try baseClient(stamper: attested, organizationId: pending.organizationId)
        var statuses = pending.mfaStatuses
        for attempt in 0..<max(1, maxAttempts) {
            if attempt > 0 { try await sleep(intervalSeconds) }
            guard let activity = try await client.getActivity(
                TGetActivityBody(activityId: pending.activityId, organizationId: pending.organizationId)).activity else {
                throw ZeroXKeyError.badResponse("get_activity returned no activity for \(pending.activityId)")
            }
            switch activity.status.rawValue {
            case "ACTIVITY_STATUS_COMPLETED":
                guard let jwt = activity.result?.stampLoginResult?.session, !jwt.isEmpty else {
                    throw ZeroXKeyActivityError.missingResult(activityId: pending.activityId, resultKey: "stampLoginResult")
                }
                try await storeSession(jwt: jwt, sessionKey: pending.sessionKey)
                return jwt
            case "ACTIVITY_STATUS_FAILED":
                throw ZeroXKeyActivityError.failed(activityId: pending.activityId, status: activity.status.rawValue,
                                                   failure: Self.jsonValue(activity.failure))
            case "ACTIVITY_STATUS_REJECTED":
                throw ZeroXKeyActivityError.rejected(activityId: pending.activityId)
            case "ACTIVITY_STATUS_CONSENSUS_NEEDED":
                throw ZeroXKeyActivityError.consensusNeeded(activityId: pending.activityId,
                                                            fingerprint: activity.fingerprint.isEmpty ? nil : activity.fingerprint)
            default:
                continue   // still AUTHENTICATORS_NEEDED (or not yet terminal)
            }
        }
        // Decoding failures propagate; the statuses are what the caller acts on.
        statuses = try await client.getMfaStatus(TGetMfaStatusBody(activityId: pending.activityId, organizationId: pending.organizationId)).mfaStatuses
        throw ZeroXKeyActivityError.authenticatorsNeeded(activityId: pending.activityId, mfaStatuses: statuses)
    }

    /// `failure` as the untyped value `ZeroXKeyActivityError.failed` carries (as `ZeroXKeyClient` does).
    static func jsonValue(_ failure: rpcStatus?) -> JSONValue? {
        guard let failure, let data = try? JSONEncoder().encode(failure) else { return nil }
        return try? JSONDecoder().decode(JSONValue.self, from: data)
    }
}
