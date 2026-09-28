/// The Activeledger SDK for Swift and iOS.
///
/// A port of the [JavaScript SDK](https://github.com/activeledger/SDK-JS),
/// the reference implementation: the same handlers, the same key file format,
/// and byte-for-byte the same signatures, checked against the JavaScript
/// SDK's cross-language vectors.
///
/// secp256k1 and ML-DSA-65 live in this core library. Falcon-512 arrives
/// through the separate `ActiveledgerFalcon` product.
public enum Activeledger {
    /// SDK version.
    public static let version = "0.0.1"
}
