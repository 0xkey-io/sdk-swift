import Foundation

/// High-level SDK errors. HTTP and activity failures surface unchanged as
/// `ZeroXKeyRequestError` / `ZeroXKeyActivityError` from `ZeroXKeyHttp`.
public enum ZeroXKeyError: Error, Sendable, Equatable {
    /// Called before `ZeroXKeyContext.configure(_:)`.
    case notConfigured
    /// A method that needs the Auth Proxy was called without `authProxyConfigId`.
    case missingAuthProxyConfiguration
    case noActiveSession
    case sessionExpired
    /// A `refreshSession` result was discarded: the session was logged out, replaced or switched
    /// while the refresh was in flight. The state after that change is kept.
    case sessionChanged
    case invalidSessionToken(String)
    /// The session JWT is not signed by the notarizer key of `ZeroXKeyConfig.trustAnchors` (or the
    /// key passed to `ZeroXKeySession.verified`), or its signature is malformed. The JWT was not
    /// stored or activated.
    case sessionJwtSignatureInvalid
    case invalidVerificationToken(String)
    case keyPairNotFound(publicKey: String)
    case keychain(status: Int32)
    case missingPasskeyProvider
    case missingRpId
    case missingOrganizationId
    case badResponse(String)
    case invalidArgument(String)
    case unsupportedAddressFormat(String)
    /// Capability that 0xkey does not offer; the SDK refuses rather than
    /// calling a non-existent endpoint.
    case unsupportedBy0xkey(String)
    /// `get_send_transaction_status` reported `FAILED` or `CANCELLED`.
    case transactionFailed(sendTransactionStatusId: String, status: String, message: String?)
    /// The transaction did not reach a terminal status within the polling timeout.
    case transactionPollingTimedOut(sendTransactionStatusId: String, lastStatus: String?)
    /// A JSON-RPC broadcast (`signAndSendTransaction`) returned an error.
    case broadcastFailed(String)
}
