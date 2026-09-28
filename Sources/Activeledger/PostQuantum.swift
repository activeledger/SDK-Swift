import Foundation

/// A pluggable post-quantum signature scheme (ML-DSA-65, Falcon-512).
///
/// The core SDK registers ML-DSA-65. Falcon-512 is registered by the
/// `ActiveledgerFalcon` add-on at startup via ``PostQuantum/register(_:for:)``.
public protocol PostQuantumScheme {
    /// The key type this scheme implements.
    var keyType: KeyType { get }

    /// Generate a keypair, optionally from the algorithm's own seed.
    /// `seed` is the raw algorithm seed (not a BIP-39 seed), of the length
    /// ``seedSize`` requires; `nil` means use fresh randomness.
    func generateKeyPair(seed: Data?) throws -> (publicKey: Data, privateKey: Data)

    /// Sign `message` (hedged: two signatures over one message differ, and
    /// both verify).
    func sign(_ message: Data, privateKey: Data) throws -> Data

    /// Verify `signature` over `message`.
    func verify(_ signature: Data, message: Data, publicKey: Data) -> Bool

    /// The exact seed length this scheme derives a key from.
    var seedSize: Int { get }

    /// The public-key length in bytes (1952 for ML-DSA-65, 897 for Falcon-512).
    var publicKeyBytes: Int { get }

    /// The private-key length in bytes (4032 for ML-DSA-65, 1281 for Falcon-512).
    var privateKeyBytes: Int { get }
}

/// Process-wide registry of the available post-quantum schemes.
public enum PostQuantum {
    private static var schemes: [KeyType: PostQuantumScheme] = [:]
    private static let lock = NSLock()

    /// Register `scheme` for `type`. Called once at startup (the core does
    /// this for ML-DSA-65; the Falcon add-on for Falcon-512).
    public static func register(_ scheme: PostQuantumScheme, for type: KeyType) {
        lock.lock(); defer { lock.unlock() }
        schemes[type] = scheme
    }

    /// Whether an implementation for `type` is present in this process.
    public static func isAvailable(_ type: KeyType) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return schemes[type] != nil
    }

    /// The registered scheme for `type`, or throws `keyTypeUnavailable`.
    public static func scheme(for type: KeyType) throws -> PostQuantumScheme {
        lock.lock(); defer { lock.unlock() }
        guard let s = schemes[type] else {
            throw ActiveledgerError.keyTypeUnavailable(
                "\(type.wire) is not available in this process"
                    + (type == .falcon512
                        ? " - link the ActiveledgerFalcon product to enable it"
                        : ""))
        }
        return s
    }
}
