// swift-tools-version: 5.9
import PackageDescription

// secp256k1 comes from swift-secp256k1 (libsecp256k1), which gives RFC 6979
// deterministic, low-S signatures byte-identical to @noble/curves. ML-DSA-65
// and the rest of the core are added in later commits. Falcon-512 will arrive
// as a separate `ActiveledgerFalcon` product (liboqs-backed).
let package = Package(
    name: "Activeledger",
    platforms: [.iOS(.v15), .macOS(.v12), .tvOS(.v15), .watchOS(.v8)],
    products: [
        .library(name: "Activeledger", targets: ["Activeledger"]),
    ],
    dependencies: [
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", exact: "0.23.2"),
    ],
    targets: [
        .target(
            name: "Activeledger",
            dependencies: [
                .product(name: "P256K", package: "swift-secp256k1"),
            ]),
        .testTarget(name: "ActiveledgerTests", dependencies: ["Activeledger"]),
    ]
)
