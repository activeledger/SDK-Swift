import Foundation

/// The key types Activeledger understands, and their exact wire strings.
///
/// **These strings are the whole contract.** The value travels from
/// `$tx.$i[label].type` into the identity stream verbatim and comes back at
/// verification time. Two consequences worth knowing:
///
/// - A typo in the string, or a key of the wrong length, surfaces as **1220
///   "Signature Incorrect"**, never as "unknown algorithm".
/// - **The ledger defaults a missing type to `rsa`.** This SDK always sends
///   it explicitly.
public enum KeyType: String, CaseIterable, Sendable {
    /// secp256k1 ECDSA. Keys are `0x`-prefixed hex; signatures are SHA-256,
    /// then ECDSA, then DER.
    case secp256k1 = "secp256k1"

    /// ML-DSA-65 (FIPS 204). The conservative post-quantum choice: a
    /// finalised standard, at the cost of 1952-byte public keys and
    /// 3309-byte signatures. Always available in the core.
    case mlDsa65 = "ml-dsa-65"

    /// Falcon-512 (FN-DSA). Roughly a fifth of ML-DSA-65's signature size.
    /// Its signature length **varies** (649-662 bytes) - never assume a
    /// fixed width. Needs the `ActiveledgerFalcon` add-on.
    case falcon512 = "falcon-512"

    /// RSA, for legacy identities only. Existing PEM keys sign and verify;
    /// new ones cannot be generated.
    case rsa = "rsa"

    /// The exact string the ledger stores and compares.
    public var wire: String { rawValue }

    /// True for the post-quantum schemes, whose keys are base64 raw bytes.
    public var isPostQuantum: Bool { self == .mlDsa65 || self == .falcon512 }

    /// The post-quantum members of `KeyType`.
    public static let postQuantum: [KeyType] = [.mlDsa65, .falcon512]

    /// The best post-quantum scheme available in this process: Falcon-512
    /// when the `ActiveledgerFalcon` add-on is enabled, otherwise ML-DSA-65.
    public static var preferredPostQuantum: KeyType {
        PostQuantum.isAvailable(.falcon512) ? .falcon512 : .mlDsa65
    }

    /// Parse a wire string, throwing on anything unrecognised.
    ///
    /// Deliberately strict and case-sensitive. `bitcoin` and `ethereum`
    /// parse as ``secp256k1`` because the ledger routes them to identical
    /// verification; they are never emitted.
    public static func fromWire(_ value: String) throws -> KeyType {
        if let t = KeyType(rawValue: value) { return t }
        if value == "bitcoin" || value == "ethereum" { return .secp256k1 }
        throw ActiveledgerError.invalidArgument(
            "Unknown key type '\(value)' - expected one of "
                + allCases.map(\.wire).joined(separator: ", "))
    }
}
