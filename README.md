<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23-dark.png">
  <img src="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23.png" alt="Activeledger" width="300"/>
</picture>

[![licence](https://img.shields.io/badge/licence-MIT-blue)](https://github.com/activeledger/SDK-Swift/blob/main/LICENSE)

# Activeledger SDK for Swift

Swift and iOS SDK for [Activeledger](https://github.com/activeledger/activeledger),
with post-quantum identity support.

**Requires Activeledger 4.7.0+** for `ml-dsa-65` and `falcon-512`.

A port of the [JavaScript SDK](https://github.com/activeledger/SDK-JS): the
same handlers, the same key file format, and byte-for-byte the same
signatures, checked against the JavaScript SDK's cross-language vectors.

secp256k1 and ML-DSA-65 are in the core `Activeledger` library. Falcon-512
comes through the `ActiveledgerFalcon` add-on (liboqs-backed), so
`KeyType.preferredPostQuantum` is Falcon when it is enabled and ML-DSA-65
otherwise.

## Install

Swift Package Manager:

```swift
.package(url: "https://github.com/activeledger/SDK-Swift.git", from: "1.0.0")
```

```swift
.product(name: "Activeledger", package: "SDK-Swift")
```

## Licence

MIT
