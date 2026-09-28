// swift-tools-version: 5.9
import PackageDescription

// secp256k1 comes from swift-secp256k1 (libsecp256k1), which gives RFC 6979
// deterministic, low-S signatures byte-identical to @noble/curves. swift-crypto
// supplies SHA-2, HMAC, HKDF and PBKDF2 for BIP-39 seed derivation. The
// post-quantum schemes (ML-DSA-65, Falcon-512) arrive later, liboqs-backed.
let package = Package(
    name: "Activeledger",
    platforms: [.iOS(.v15), .macOS(.v12), .tvOS(.v15), .watchOS(.v8)],
    products: [
        .library(name: "Activeledger", targets: ["Activeledger"]),
    ],
    dependencies: [
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", exact: "0.23.2"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.8.0"),
    ],
    targets: [
        .target(
            name: "Activeledger",
            dependencies: [
                .product(name: "P256K", package: "swift-secp256k1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]),
        .testTarget(name: "ActiveledgerTests", dependencies: ["Activeledger"]),
    ]
)
