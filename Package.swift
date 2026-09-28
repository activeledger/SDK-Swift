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
            ]),

        .target(
            name: "ActiveledgerFalcon",
            dependencies: ["Activeledger", "CFalcon"]),

        .testTarget(
            name: "ActiveledgerTests",
            dependencies: ["Activeledger", "ActiveledgerFalcon"]),
    ]
)
