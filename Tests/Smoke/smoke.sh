#!/usr/bin/env bash
# Smoke test: build a throwaway consumer package outside the repo, with a path
# dependency on this package, and run it against an in-process loopback server.
# Generates secp256k1 and ml-dsa-65 keys, onboards, signs, verifies and submits a
# committed and a rejected (HTTP 200) transaction.
#
#   Tests/Smoke/smoke.sh
#
# No network at run time. Dependency checkouts come from SwiftPM's cache; the
# repo's Package.resolved is copied so the same versions are used.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/activeledger-smoke.XXXXXX")"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/Sources/smoke"
cp "$here/main.swift" "$work/Sources/smoke/main.swift"
cp "$repo/Tests/ActiveledgerTests/LoopbackServer.swift" "$work/Sources/smoke/LoopbackServer.swift"
[ -f "$repo/Package.resolved" ] && cp "$repo/Package.resolved" "$work/Package.resolved"

# The package is referred to by its directory name (its SwiftPM identity).
cat > "$work/Package.swift" <<PKG
// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "smoke",
    platforms: [.macOS(.v12)],
    dependencies: [.package(path: "$repo")],
    targets: [
        .executableTarget(name: "smoke", dependencies: [
            .product(name: "Activeledger", package: "$(basename "$repo")"),
        ]),
    ]
)
PKG

cd "$work"
swift build 2>&1 | tail -n 5
swift run --skip-build smoke
