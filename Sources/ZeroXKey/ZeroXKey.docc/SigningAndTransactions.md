# Signing and Transactions

Sign messages, raw payloads and transactions with wallet accounts, send transactions, and export or import wallets.

## Overview

All methods on this page need an active session and throw ``ZeroXKeyError/noActiveSession`` or ``ZeroXKeyError/sessionExpired`` otherwise. Keys never leave 0xkey's enclave: the SDK asks it to sign with a wallet account, identified by its address (`signWith`).

Wallets and accounts come from ``ZeroXKeyContext/refreshWallets()``, which fills ``ZeroXKeyContext/wallets``. ``ZeroXKeyContext/createWallet(walletName:accounts:mnemonicLength:)`` creates one, by default with an Ethereum and a Solana account (``AddressFormatDefaults/defaultWalletAccounts``).

```swift
let ctx = ZeroXKeyContext.shared
let wallets = try await ctx.refreshWallets()
guard let account = wallets.first?.accounts.first else { return }
```

## Sign a message

``ZeroXKeyContext/signMessage(signWith:addressFormat:message:encoding:hashFunction:addEthereumPrefix:)`` signs a string. Encoding and hash function default from the address format (``AddressFormatDefaults``). For Ethereum the EIP-191 prefix is added unless you pass `addEthereumPrefix: false`. The result is a ``SignRawPayloadResult`` with `r`, `s` and `v`.

```swift
let sig = try await ctx.signMessage(
    signWith: account.address,
    addressFormat: .ADDRESS_FORMAT_ETHEREUM,
    message: "hello")
```

There is also ``ZeroXKeyContext/signMessage(signWith:message:encoding:hashFunction:addEthereumPrefix:)`` taking the `v1WalletAccount` directly.

## Sign a raw payload

``ZeroXKeyContext/signRawPayload(signWith:payload:encoding:hashFunction:)`` signs bytes you have already prepared:

```swift
let sig = try await ctx.signRawPayload(
    signWith: account.address,
    payload: "0x<hex digest or bytes>",
    encoding: .PAYLOAD_ENCODING_HEXADECIMAL,
    hashFunction: .HASH_FUNCTION_NOT_APPLICABLE)
```

## Sign a transaction

``ZeroXKeyContext/signTransaction(signWith:unsignedTransaction:type:)-(String,_,_)`` takes the **unsigned transaction as hex** and returns the **signed transaction as hex**. The SDK does not build or serialize transactions. For Ethereum (`.TRANSACTION_TYPE_ETHEREUM`) pass the RLP encoding of an EIP-1559 (type 2) transaction, `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList])`. The `0x` prefix is optional.

```swift
// Unsigned EIP-1559 transaction, built by your backend (which knows nonce and fees)
// or by an RLP library of your choice.
let unsigned = try await backend.prepareTransfer(to: recipient, amountWei: "1000000000000000")
let signed = try await ctx.signTransaction(
    signWith: account.address, unsignedTransaction: unsigned, type: .TRANSACTION_TYPE_ETHEREUM)
// Broadcast `signed` yourself (eth_sendRawTransaction).
```

An overload takes a `v1WalletAccount` instead of the address.

## Sign and broadcast through your own RPC

``ZeroXKeyContext/signAndSendTransaction(signWith:unsignedTransaction:type:rpcUrl:)`` signs, then submits the transaction to the JSON-RPC endpoint you give and returns the transaction hash (or signature).

```swift
let txHash = try await ctx.signAndSendTransaction(
    signWith: account.address, unsignedTransaction: unsigned,
    type: .TRANSACTION_TYPE_ETHEREUM, rpcUrl: "https://rpc.example.org")
```

- Ethereum: `eth_sendRawTransaction`. Solana: `sendTransaction` with a base58 transaction. Tron: `POST <rpcUrl>/wallet/broadcasthex`.
- `rpcUrl` must be `https`. Plain `http` is accepted only for `localhost`, `127.0.0.0/8` and `::1` without user name or password, for local nodes (independent of ``ZeroXKeyConfig/transportSecurity``). Any other URL throws ``ZeroXKeyError/invalidArgument(_:)`` with `"rpcUrl"` before anything is signed.
- A JSON-RPC error throws ``ZeroXKeyError/broadcastFailed(_:)``.

## Let 0xkey broadcast

``ZeroXKeyContext/ethSendTransaction(_:)`` has 0xkey build, sign and submit the transaction, optionally with gas sponsorship. It returns a `sendTransactionStatusId`. Follow it with ``ZeroXKeyContext/pollTransactionStatus(sendTransactionStatusId:organizationId:pollingInterval:timeout:)``:

```swift
let statusId = try await ctx.ethSendTransaction(TEthSendTransactionBody(
    from: account.address, caip2: "eip155:8453", to: recipient,
    sponsor: true, value: "1000"))
let status = try await ctx.pollTransactionStatus(sendTransactionStatusId: statusId)
let hash = status.eth?.txHash
```

- With `sponsor == true` the gas fields (`gasLimit`, `maxFeePerGas`, `maxPriorityFeePerGas`) are dropped because the gas station pays. Otherwise `gasStationNonce` is dropped.
- ``ZeroXKeyContext/solSendTransaction(_:)`` and ``ZeroXKeyContext/tronSendTransaction(_:)`` are the Solana and Tron counterparts.
- Polling checks every 0.5 s for up to 60 s by default. `COMPLETED` and `INCLUDED` return the status payload. `FAILED` and `CANCELLED` throw ``ZeroXKeyError/transactionFailed(sendTransactionStatusId:status:message:)``. A timeout throws ``ZeroXKeyError/transactionPollingTimedOut(sendTransactionStatusId:lastStatus:)``.

Activities that need more than the session's approval surface as `ZeroXKeyActivityError` (`consensusNeeded`, `authenticatorsNeeded(activityId:mfaStatuses:)`), never as success.

## Export and import

Export decrypts locally. The SDK generates a one-time P-256 key in memory, asks 0xkey to encrypt the secret to it, verifies the bundle signature against the 0xkey signer enclave key, and decrypts. Treat the returned strings as secrets: do not log them or keep them longer than needed.

- ``ZeroXKeyContext/exportWallet(walletId:dangerouslyOverrideSignerPublicKey:)`` returns the mnemonic.
- ``ZeroXKeyContext/exportWalletAccount(address:keyFormat:dangerouslyOverrideSignerPublicKey:)`` returns one account's private key, as hex by default.

Import encrypts to a target key issued by the enclave (HPKE, `0xkey_hpke`):

```swift
let walletId = try await ctx.importWallet(walletName: "Imported", mnemonic: phrase)
```

- ``ZeroXKeyContext/importWallet(walletName:mnemonic:accounts:dangerouslyOverrideSignerPublicKey:)`` imports a mnemonic and refreshes `wallets`.
- ``ZeroXKeyContext/importPrivateKey(privateKey:privateKeyName:keyFormat:curve:addressFormats:dangerouslyOverrideSignerPublicKey:)`` imports a raw private key and returns its ID.

The `dangerouslyOverrideSignerPublicKey` parameters exist for tests. Do not set them in production.
