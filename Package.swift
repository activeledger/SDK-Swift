// swift-tools-version: 5.9
import PackageDescription

// secp256k1 comes from swift-secp256k1 (libsecp256k1), which gives RFC 6979
// deterministic, low-S signatures byte-identical to @noble/curves. swift-crypto
// supplies SHA-2, HMAC, HKDF and PBKDF2 for BIP-39 seed derivation.
//
// The post-quantum schemes are backed by the vendored PQClean "clean"
// implementations (the same code liboqs wraps), split into three C targets:
//   CPQCommon - SHA-3/SHAKE (fips202) and the seeded randombytes that makes
//               key generation a deterministic function of a seed.
//   CMLDSA    - ML-DSA-65 (FIPS 204). In the core: always available.
//   CFalcon   - Falcon-512. In the ActiveledgerFalcon add-on: native, opt-in.
//
// HTTP uses URLSession on Apple platforms. On Linux, swift-corelibs-foundation's
// URLSession fails to POST a body ("Failure writing output to destination"), so
// there the SDK uses AsyncHTTPClient instead - linked on Linux only, so Apple
// consumers never compile or link swift-nio.
let package = Package(
    name: "Activeledger",
    platforms: [.iOS(.v15), .macOS(.v12), .tvOS(.v15), .watchOS(.v8)],
    products: [
        .library(name: "Activeledger", targets: ["Activeledger"]),
        .library(name: "ActiveledgerFalcon", targets: ["ActiveledgerFalcon"]),
    ],
    dependencies: [
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", exact: "0.23.2"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.8.0"),
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.63.0"),
    ],
    targets: [
        // Shared C: SHA-3/SHAKE and the seeded randombytes source.
        .target(name: "CPQCommon"),

        // ML-DSA-65 (FIPS 204), vendored PQClean.
        .target(
            name: "CMLDSA",
            dependencies: ["CPQCommon"],
            cSettings: [.headerSearchPath("pqclean")]),

        // Falcon-512, vendored PQClean.
        .target(
            name: "CFalcon",
            dependencies: ["CPQCommon"],
            cSettings: [.headerSearchPath("pqclean")]),

        .target(
            name: "Activeledger",
            dependencies: [
                .product(name: "P256K", package: "swift-secp256k1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                "CMLDSA",
                // Linux-only HTTP client; Apple platforms use URLSession.
                .product(name: "AsyncHTTPClient", package: "async-http-client",
                         condition: .when(platforms: [.linux])),
                .product(name: "NIOCore", package: "swift-nio",
                         condition: .when(platforms: [.linux])),
                .product(name: "NIOFoundationCompat", package: "swift-nio",
                         condition: .when(platforms: [.linux])),
            ]),

        .target(
            name: "ActiveledgerFalcon",
            dependencies: ["Activeledger", "CFalcon"]),

        // A runnable end-to-end demo: `swift run Example [nodeURL] [keyType]`.
        .executableTarget(
            name: "Example",
            dependencies: ["Activeledger", "ActiveledgerFalcon"]),

        .testTarget(
            name: "ActiveledgerTests",
            dependencies: ["Activeledger", "ActiveledgerFalcon"]),
    ]
)
