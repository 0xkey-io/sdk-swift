// Emits Swift-produced artifacts for the Swift -> sdk-js direction of the
// cross-language vectors. Uses only the public, randomized APIs (real CryptoKit
// signatures and fresh HPKE ephemeral keys); the node script
// `Scripts/vectors/verify-swift-output.mjs` verifies/decrypts them with sdk-js.
//
// Usage: swift run ZeroXKeyVectorEmitter <Tests/Fixtures dir> <output.json>
import Foundation
import ZeroXKeyCrypto
import ZeroXKeyEncoding
import ZeroXKeyStamper

func load(_ dir: URL, _ name: String) throws -> [String: Any] {
    let data = try Data(contentsOf: dir.appendingPathComponent("\(name).json"))
    return try JSONSerialization.jsonObject(with: data) as! [String: Any]
}

let args = CommandLine.arguments
guard args.count == 3 else {
    FileHandle.standardError.write(Data("usage: ZeroXKeyVectorEmitter <fixturesDir> <out.json>\n".utf8))
    exit(2)
}
let fixtures = URL(fileURLWithPath: args[1])
let outURL = URL(fileURLWithPath: args[2])

var output: [String: Any] = [:]

// API key stamps over the fixture payloads.
let apiCases = try load(fixtures, "api-key-stamp")["cases"] as! [[String: Any]]
output["apiKeyStamps"] = try apiCases.map { c -> [String: String] in
    let stamper = try ApiKeyStamper(apiPublicKey: c["publicKey"] as! String, apiPrivateKey: c["privateKey"] as! String)
    let payload = c["payload"] as! String
    return ["publicKey": stamper.apiPublicKey, "payload": payload, "stampHeaderValue": try stamper.stampSync(payload: payload).stampHeaderValue]
}

// HPKE to the fixture receiver.
let hpke = try load(fixtures, "hpke")
let receiver = hpke["receiver"] as! [String: String]
let plaintexts = ["", "hello from swift", "leaf lady until indicate praise final route toast cake minimum insect unknown", String(repeating: "x", count: 777)]
output["hpke"] = try plaintexts.map { p -> [String: String] in
    let sealed = try ZeroXKeyHPKE.encrypt(plaintext: Data(p.utf8), recipientPublicKey: Hex.decode(receiver["publicKeyUncompressed"]!))
    return ["plaintextHex": Hex.encode(Data(p.utf8)), "sealedHex": Hex.encode(sealed), "formatted": try ZeroXKeyHPKE.formatBundle(sealed)]
}

// Credential bundle (base58check) to the fixture embedded key.
let cred = try load(fixtures, "credential-bundle")
let embedded = cred["embedded"] as! [String: String]
let sessionKey = generateP256KeyPair()
let credSealed = try ZeroXKeyHPKE.encrypt(plaintext: Hex.decode(sessionKey.privateKey), recipientPublicKey: Hex.decode(embedded["publicKeyUncompressed"]!))
output["credentialBundle"] = ["bundle": Base58Check.encode(credSealed), "expectedHex": sessionKey.privateKey]

// Import bundles.
let imp = try load(fixtures, "import-bundle")
let importBundle = imp["importBundle"] as! String
let userId = imp["userId"] as! String
let orgId = imp["organizationId"] as! String
let signer = imp["signerPublicKey"] as! String
output["importBundles"] = try (imp["cases"] as! [[String: Any]]).map { c -> [String: String] in
    let input = c["input"] as! String
    let out: String
    if (c["kind"] as! String) == "wallet" {
        out = try encryptWalletToBundle(mnemonic: input, importBundle: importBundle, userId: userId, organizationId: orgId, dangerouslyOverrideSignerPublicKey: signer)
    } else {
        out = try encryptPrivateKeyToBundle(privateKey: input, keyFormat: KeyFormat(rawValue: c["keyFormat"] as! String)!, importBundle: importBundle,
                                            userId: userId, organizationId: orgId, dangerouslyOverrideSignerPublicKey: signer)
    }
    return ["label": c["label"] as! String, "bundle": out, "plaintextHex": c["plaintextHex"] as! String]
}

// OTP attempt bundle.
let otp = try load(fixtures, "otp-bundle")
let otpSigner = otp["signerPublicKey"] as! String
output["otpBundle"] = [
    "bundle": try encryptOtpAttemptBundle(otpCode: otp["otpCode"] as! String, publicKey: otp["publicKey"] as! String,
                                          otpEncryptionTargetBundle: otp["otpEncryptionTargetBundle"] as! String,
                                          dangerouslyOverrideSignerPublicKey: otpSigner),
    "plaintext": otp["plaintext"] as! String,
]

let data = try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys])
try data.write(to: outURL)
print("wrote \(outURL.path)")
