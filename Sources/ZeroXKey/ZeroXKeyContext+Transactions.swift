import Foundation
import ZeroXKeyEncoding
import ZeroXKeyHttp

/// Transaction sending (sdk-js core.ts:3412-3970).
///
/// Two paths, as in sdk-js:
/// - **0xkey-broadcast** (`ethSendTransaction` / `solSendTransaction` / `tronSendTransaction`):
///   0xkey signs and submits, returns a `sendTransactionStatusId`; follow with
///   `pollTransactionStatus`.
/// - **Self-broadcast** (`signAndSendTransaction`): `sign_transaction`, then JSON-RPC to the
///   caller's `rpcUrl`; returns the chain's transaction hash / signature.
extension ZeroXKeyContext {
    /// Terminal `txStatus` values (sdk-js core.ts:3937, 3951).
    nonisolated public static let successfulTransactionStatuses: Set<String> = ["COMPLETED", "INCLUDED"]
    nonisolated public static let failedTransactionStatuses: Set<String> = ["FAILED", "CANCELLED"]

    /// Submits an Ethereum transaction through 0xkey and returns the `sendTransactionStatusId`.
    /// With `sponsor == true` the gas fields are dropped (0xkey gas station pays), otherwise
    /// `gasStationNonce` is dropped (sdk-js core.ts:3669-3678).
    @discardableResult
    public func ethSendTransaction(_ transaction: TEthSendTransactionBody) async throws -> String {
        var body = transaction
        if body.sponsor == true {
            body.gasLimit = nil
            body.maxFeePerGas = nil
            body.maxPriorityFeePerGas = nil
        } else {
            body.sponsor = nil
            body.gasStationNonce = nil
        }
        let res = try await sessionClient().ethSendTransaction(body)
        return try Self.requireStatusId(res.sendTransactionStatusId)
    }

    /// Submits a Solana transaction through 0xkey and returns the `sendTransactionStatusId`.
    @discardableResult
    public func solSendTransaction(_ transaction: TSolSendTransactionBody) async throws -> String {
        try Self.requireStatusId(try await sessionClient().solSendTransaction(transaction).sendTransactionStatusId)
    }

    /// Submits a TRX / TRC-20 transfer through 0xkey (server builds the transaction).
    @discardableResult
    public func tronSendTransaction(_ transaction: TTronSendTransactionBody) async throws -> String {
        try Self.requireStatusId(try await sessionClient().tronSendTransaction(transaction).sendTransactionStatusId)
    }

    /// Polls `get_send_transaction_status` until a terminal status (sdk-js
    /// `pollTransactionStatus`, core.ts:3899: every 500 ms, 1 minute timeout).
    /// Returns the status payload (`eth.txHash`, `sol.signature`, …) on `COMPLETED` / `INCLUDED`;
    /// throws `transactionFailed` on `FAILED` / `CANCELLED`, `transactionPollingTimedOut` otherwise.
    public func pollTransactionStatus(
        sendTransactionStatusId: String, organizationId: String? = nil,
        pollingInterval: TimeInterval = 0.5, timeout: TimeInterval = 60
    ) async throws -> TGetSendTransactionStatusResponse {
        let c = try sessionClient()
        let deadline = now().addingTimeInterval(timeout)
        var last: String?
        while true {
            try await sleep(pollingInterval)
            try Task.checkCancellation()
            let res = try await c.getSendTransactionStatus(TGetSendTransactionStatusBody(
                sendTransactionStatusId: sendTransactionStatusId, organizationId: organizationId))
            last = res.txStatus
            if Self.successfulTransactionStatuses.contains(res.txStatus) { return res }
            if Self.failedTransactionStatuses.contains(res.txStatus) {
                throw ZeroXKeyError.transactionFailed(
                    sendTransactionStatusId: sendTransactionStatusId, status: res.txStatus,
                    message: res.error?.message ?? res.txError)
            }
            if now() >= deadline {
                throw ZeroXKeyError.transactionPollingTimedOut(sendTransactionStatusId: sendTransactionStatusId, lastStatus: last)
            }
        }
    }

    /// Signs with an embedded wallet account and broadcasts via the caller's RPC
    /// (sdk-js `signAndSendTransaction` + `broadcastTransaction`, utils.ts:510-593).
    /// Ethereum: `eth_sendRawTransaction` with `0x`-prefixed hex. Solana: `sendTransaction`
    /// with base58. Tron: `POST <rpcUrl>/wallet/broadcasthex`. Returns the tx hash / signature.
    public func signAndSendTransaction(
        signWith: String, unsignedTransaction: String, type: v1TransactionType, rpcUrl: String
    ) async throws -> String {
        guard let url = URL(string: rpcUrl), Self.isAllowedRpcURL(url) else {
            throw ZeroXKeyError.invalidArgument("rpcUrl")
        }
        let signed = try await signTransaction(signWith: signWith, unsignedTransaction: unsignedTransaction, type: type)
        return try await Self.broadcast(signedTransaction: signed, type: type, rpcURL: url, session: config.urlSession)
    }

    nonisolated static func requireStatusId(_ id: String) throws -> String {
        guard !id.isEmpty else { throw ZeroXKeyError.badResponse("missing sendTransactionStatusId") }
        return id
    }

    nonisolated static func broadcast(
        signedTransaction: String, type: v1TransactionType, rpcURL: URL, session: URLSession
    ) async throws -> String {
        let hex = signedTransaction.hasPrefix("0x") ? String(signedTransaction.dropFirst(2)) : signedTransaction
        let url: URL
        let body: [String: Any]
        switch type {
        case .TRANSACTION_TYPE_ETHEREUM:
            url = rpcURL
            body = ["jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": ["0x" + hex]]
        case .TRANSACTION_TYPE_SOLANA:
            url = rpcURL
            body = ["jsonrpc": "2.0", "id": 1, "method": "sendTransaction",
                    "params": [Base58.encode(try Hex.decode(hex)), ["encoding": "base58"]]]
        case .TRANSACTION_TYPE_TRON:
            url = rpcURL.appendingPathComponent("wallet/broadcasthex")
            body = ["transaction": hex]
        default:
            throw ZeroXKeyError.unsupportedAddressFormat(type.rawValue)
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _) = try await session.data(for: req)
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ZeroXKeyError.broadcastFailed(String(decoding: data.prefix(200), as: UTF8.self))
        }
        if type == .TRANSACTION_TYPE_TRON {
            guard json["result"] as? Bool == true, let txid = json["txid"] as? String else {
                throw ZeroXKeyError.broadcastFailed("Tron RPC error: \(json["message"] as? String ?? "unknown")")
            }
            return txid
        }
        if let err = json["error"] as? [String: Any] {
            throw ZeroXKeyError.broadcastFailed("RPC error: \(err["message"] as? String ?? "unknown")")
        }
        guard let result = json["result"] as? String else { throw ZeroXKeyError.broadcastFailed("RPC returned no result") }
        return result
    }
}

extension ZeroXKeyContext {
    /// `https` only, except plain `http` to a loopback host (`localhost`, `127.0.0.0/8`, `::1`, no
    /// user name or password) for local nodes: a signed transaction sent in the clear can be withheld
    /// or replayed elsewhere. Independent of `config.transportSecurity`, which covers the 0xkey endpoints.
    package nonisolated static func isAllowedRpcURL(_ url: URL) -> Bool {
        ZeroXKeyTransportSecurity.dangerouslyAllowInsecureLoopback.allows(url)
    }
}
