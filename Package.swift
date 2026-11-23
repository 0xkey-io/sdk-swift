// swift-tools-version: 6.0
// 0xkey Swift SDK.
import PackageDescription

let package = Package(
    name: "ZeroXKeySDK",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "ZeroXKey", targets: ["ZeroXKey"]),
        .library(name: "ZeroXKeyHttp", targets: ["ZeroXKeyHttp"]),
        .library(name: "ZeroXKeyEncoding", targets: ["ZeroXKeyEncoding"]),
        .library(name: "ZeroXKeyCrypto", targets: ["ZeroXKeyCrypto"]),
        .library(name: "ZeroXKeyStamper", targets: ["ZeroXKeyStamper"]),
        .library(name: "ZeroXKeyPasskeys", targets: ["ZeroXKeyPasskeys"]),
    ],
    targets: [
        // MARK: - Library modules
        .target(name: "ZeroXKeyEncoding"),
        .target(name: "ZeroXKeyCrypto", dependencies: ["ZeroXKeyEncoding"]),
        .target(name: "ZeroXKeyStamper", dependencies: ["ZeroXKeyEncoding", "ZeroXKeyCrypto"]),
        .target(name: "ZeroXKeyHttp", dependencies: ["ZeroXKeyEncoding", "ZeroXKeyStamper"]),
        .target(name: "ZeroXKeyPasskeys", dependencies: ["ZeroXKeyEncoding", "ZeroXKeyStamper"]),
        .target(
            name: "ZeroXKey",
            dependencies: [
                "ZeroXKeyEncoding", "ZeroXKeyCrypto", "ZeroXKeyStamper",
                "ZeroXKeyHttp", "ZeroXKeyPasskeys",
            ]
        ),

        // MARK: - Cross-language vector emitter (Swift -> sdk-js direction)
        .executableTarget(
            name: "ZeroXKeyVectorEmitter",
            dependencies: ["ZeroXKeyEncoding", "ZeroXKeyCrypto", "ZeroXKeyStamper"]
        ),

        // MARK: - Tests
        .target(
            name: "ZeroXKeyTestSupport",
            dependencies: ["ZeroXKeyEncoding"],
            path: "Tests/ZeroXKeyTestSupport"
        ),
        .testTarget(
            name: "ZeroXKeyEncodingTests",
            dependencies: ["ZeroXKeyEncoding", "ZeroXKeyTestSupport"]
        ),
        .testTarget(
            name: "ZeroXKeyCryptoTests",
            dependencies: ["ZeroXKeyCrypto", "ZeroXKeyEncoding", "ZeroXKeyTestSupport"]
        ),
        .testTarget(
            name: "ZeroXKeyStamperTests",
            dependencies: ["ZeroXKeyStamper", "ZeroXKeyCrypto", "ZeroXKeyEncoding", "ZeroXKeyTestSupport"]
        ),
        .testTarget(
            name: "ZeroXKeyHttpTests",
            dependencies: ["ZeroXKeyHttp", "ZeroXKeyStamper", "ZeroXKeyCrypto", "ZeroXKeyEncoding", "ZeroXKeyTestSupport"]
        ),
        .testTarget(
            name: "ZeroXKeyPasskeysTests",
            dependencies: ["ZeroXKeyPasskeys", "ZeroXKeyStamper"]
        ),
        .testTarget(
            name: "ZeroXKeyTests",
            dependencies: [
                "ZeroXKey", "ZeroXKeyHttp", "ZeroXKeyStamper", "ZeroXKeyCrypto", "ZeroXKeyEncoding", "ZeroXKeyTestSupport",
            ]
        ),
    ]
)
