import Foundation
import ZeroXKeyHttp

/// Authentication lifecycle.
public enum AuthState: Sendable, Equatable {
    case loading
    case authenticated
    case unauthenticated
}

public enum OtpType: String, Sendable {
    case email = "OTP_TYPE_EMAIL"
    case sms = "OTP_TYPE_SMS"

    /// Auth Proxy `get_account` filter (sdk-js `OtpTypeToFilterTypeMap`, enums.ts:33-36).
    var accountFilterType: String { self == .email ? "EMAIL" : "PHONE_NUMBER" }
}

public enum AuthAction: String, Sendable {
    case login
    case signup
}

/// A wallet with its accounts.
public struct ZeroXKeyWallet: Sendable, Hashable, Identifiable {
    public var id: String { walletId }
    public let walletId: String
    public let walletName: String
    public let accounts: [v1WalletAccount]
    public let exported: Bool
    public let imported: Bool
    /// Creation / update time, seconds since epoch as the API reports them; `""` when it did not.
    /// Package-level, not part of the public API.
    package let createdAt: String
    package let updatedAt: String

    public init(walletId: String, walletName: String, accounts: [v1WalletAccount], exported: Bool, imported: Bool,
                createdAt: String = "", updatedAt: String = "") {
        self.walletId = walletId
        self.walletName = walletName
        self.accounts = accounts
        self.exported = exported
        self.imported = imported
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

/// Sub-organization parameters used at sign-up (sdk-js `CreateSubOrgParams`).
public struct CreateSubOrgParams: Sendable, Hashable {
    public var userName: String?
    public var userEmail: String?
    public var userPhoneNumber: String?
    public var userTag: String?
    public var subOrgName: String?
    public var apiKeys: [v1ApiKeyParamsV2]
    public var authenticators: [v1AuthenticatorParamsV2]
    public var oauthProviders: [v1OauthProviderParams]
    public var customWallet: v1WalletParams?

    public init(
        userName: String? = nil, userEmail: String? = nil, userPhoneNumber: String? = nil, userTag: String? = nil,
        subOrgName: String? = nil, apiKeys: [v1ApiKeyParamsV2] = [], authenticators: [v1AuthenticatorParamsV2] = [],
        oauthProviders: [v1OauthProviderParams] = [], customWallet: v1WalletParams? = nil
    ) {
        self.userName = userName
        self.userEmail = userEmail
        self.userPhoneNumber = userPhoneNumber
        self.userTag = userTag
        self.subOrgName = subOrgName
        self.apiKeys = apiKeys
        self.authenticators = authenticators
        self.oauthProviders = oauthProviders
        self.customWallet = customWallet
    }

    func merged(over defaults: CreateSubOrgParams?) -> CreateSubOrgParams {
        guard let d = defaults else { return self }
        return CreateSubOrgParams(
            userName: userName ?? d.userName, userEmail: userEmail ?? d.userEmail,
            userPhoneNumber: userPhoneNumber ?? d.userPhoneNumber, userTag: userTag ?? d.userTag,
            subOrgName: subOrgName ?? d.subOrgName,
            apiKeys: apiKeys.isEmpty ? d.apiKeys : apiKeys,
            authenticators: authenticators.isEmpty ? d.authenticators : authenticators,
            oauthProviders: oauthProviders.isEmpty ? d.oauthProviders : oauthProviders,
            customWallet: customWallet ?? d.customWallet)
    }
}

public struct InitOtpResult: Sendable, Equatable {
    public let otpId: String
    public let otpEncryptionTargetBundle: String
}

/// Result of `verifyOtp`. The verification token proves the contact and lets whoever holds it log
/// in or sign up, so `description`, `debugDescription` and reflection (`dump`) redact it; read
/// `verificationToken` itself where you need the value.
public struct VerifyOtpResult: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Empty when the contact has no sub-organization yet.
    public let subOrganizationId: String
    public let verificationToken: String

    package init(subOrganizationId: String, verificationToken: String) {
        self.subOrganizationId = subOrganizationId
        self.verificationToken = verificationToken
    }

    public var description: String {
        "VerifyOtpResult(subOrganizationId: \(subOrganizationId), verificationToken: <redacted>)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["subOrganizationId": subOrganizationId, "verificationToken": "<redacted>"], displayStyle: .struct)
    }
}

public struct AuthResult: Sendable, Equatable {
    public let sessionToken: String
    public let action: AuthAction
}

public struct SignRawPayloadResult: Sendable, Equatable {
    public let r: String
    public let s: String
    public let v: String

    public init(r: String, s: String, v: String) {
        self.r = r
        self.s = s
        self.v = v
    }
}

/// Payload defaults per address format (sdk-js `addressFormatConfig`,
/// sdk-js `packages/core/src/utils.ts:135-230`).
public enum AddressFormatDefaults {
    public static func encoding(for format: v1AddressFormat) throws -> v1PayloadEncoding {
        try entry(format).0
    }

    public static func hashFunction(for format: v1AddressFormat) throws -> v1HashFunction {
        try entry(format).1
    }

    static func entry(_ f: v1AddressFormat) throws -> (v1PayloadEncoding, v1HashFunction) {
        let hex = v1PayloadEncoding.PAYLOAD_ENCODING_HEXADECIMAL
        switch f.rawValue {
        case "ADDRESS_FORMAT_ETHEREUM": return (hex, .HASH_FUNCTION_KECCAK256)
        case "ADDRESS_FORMAT_SOLANA", "ADDRESS_FORMAT_SUI", "ADDRESS_FORMAT_APTOS":
            return (hex, .HASH_FUNCTION_NOT_APPLICABLE)
        case "ADDRESS_FORMAT_COSMOS": return (.PAYLOAD_ENCODING_TEXT_UTF8, .HASH_FUNCTION_SHA256)
        case "ADDRESS_FORMAT_UNCOMPRESSED", "ADDRESS_FORMAT_COMPRESSED", "ADDRESS_FORMAT_TRON":
            return (hex, .HASH_FUNCTION_SHA256)
        case let s where s.hasPrefix("ADDRESS_FORMAT_BITCOIN_"):
            return (hex, .HASH_FUNCTION_SHA256)
        default:
            throw ZeroXKeyError.unsupportedAddressFormat(f.rawValue)
        }
    }

    /// `defaultEthereumAccountAtIndex` / `defaultSolanaAccountAtIndex`
    /// (sdk-js `packages/core/src/0xkey-helpers.ts:8-17,453-462`).
    public static func ethereumAccount(index: Int = 0) -> v1WalletAccountParams {
        v1WalletAccountParams(curve: .CURVE_SECP256K1, pathFormat: .PATH_FORMAT_BIP32,
                              path: "m/44'/60'/\(index)'/0/0", addressFormat: .ADDRESS_FORMAT_ETHEREUM)
    }

    public static func solanaAccount(index: Int = 0) -> v1WalletAccountParams {
        v1WalletAccountParams(curve: .CURVE_ED25519, pathFormat: .PATH_FORMAT_BIP32,
                              path: "m/44'/501'/\(index)'/0'", addressFormat: .ADDRESS_FORMAT_SOLANA)
    }

    /// sdk-js `createWallet` default: one Ethereum and one Solana account.
    public static var defaultWalletAccounts: [v1WalletAccountParams] { [ethereumAccount(), solanaAccount()] }
}
