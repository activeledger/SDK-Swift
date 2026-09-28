// swift-tools-version: 5.9
import PackageDescription

// The core SDK has no external dependencies yet; swift-crypto and a
// secp256k1 binding are added in the commits that first need them, so this
// scaffold builds on its own. Falcon-512 arrives as a separate
// `ActiveledgerFalcon` product (liboqs-backed), mirroring the Dart SDK's
// add-on; ML-DSA-65 lives in the core.
let package = Package(
    name: "Activeledger",
    platforms: [.iOS(.v15), .macOS(.v12), .tvOS(.v15), .watchOS(.v8)],
    products: [
        .library(name: "Activeledger", targets: ["Activeledger"]),
    ],
    targets: [
        .target(name: "Activeledger"),
        .testTarget(name: "ActiveledgerTests", dependencies: ["Activeledger"]),
    ]
)
