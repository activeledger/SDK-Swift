import Foundation
import Crypto
import _CryptoExtras

/// BIP-39 recovery phrases, and the seed each key type derives from one.
///
/// Two layers, and conflating them is the mistake this is arranged to
/// prevent. A phrase becomes a 64-byte BIP-39 seed (``toSeed(_:passphrase:validate:)``);
/// that seed becomes the seed the chosen algorithm actually takes
/// (``deriveSeed(_:bip39Seed:)``).
///
/// ```text
/// BIP-39 seed S = PBKDF2-HMAC-SHA512(phrase, "mnemonic" + passphrase, 2048, 64)
///
/// ml-dsa-65   HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)
/// falcon-512  HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)
/// secp256k1   HMAC-SHA512("Bitcoin seed", S)[0..32]
/// ```
///
/// Identical in every Activeledger SDK, and checked against the
/// cross-language `seed-vectors.json`.
public enum Recovery {
    /// A BIP-39 seed is always 64 bytes.
    public static let bip39SeedBytes = 64

    private static let iterations = 2048

    /// Each algorithm's own seed length.
    public static let seedSizes: [KeyType: Int] = [
        .secp256k1: 32, .mlDsa65: 32, .falcon512: 48,
    ]

    private static let wordIndex: [String: Int] = {
        var m = [String: Int](minimumCapacity: bip39English.count)
        for (i, w) in bip39English.enumerated() { m[w] = i }
        return m
    }()

    /// The seed length `type` takes.
    public static func seedSize(_ type: KeyType) throws -> Int {
        guard let size = seedSizes[type] else {
            throw ActiveledgerError.invalidArgument("\(type.wire) keys cannot be derived from a seed")
        }
        return size
    }

    /// A new random English mnemonic. `strength` is entropy bits: 128 (12
    /// words, default), 160, 192, 224 or 256 (24 words).
    public static func generateMnemonic(strength: Int = 128) throws -> String {
        guard strength >= 128, strength <= 256, strength % 32 == 0 else {
            throw ActiveledgerError.invalidArgument("strength must be 128, 160, 192, 224 or 256")
        }
        var entropy = [UInt8](repeating: 0, count: strength / 8)
        for i in entropy.indices { entropy[i] = UInt8.random(in: 0...255) }
        return try mnemonic(fromEntropy: entropy)
    }

    static func mnemonic(fromEntropy entropy: [UInt8]) throws -> String {
        let hash = Array(SHA256.hash(data: entropy))
        var bits = entropy.map { byteBits($0) }.joined()
        let checksumBits = entropy.count * 8 / 32
        bits += String(byteBits(hash[0]).prefix(checksumBits))
        let all = Array(bits)
        var words = [String]()
        var i = 0
        while i < all.count {
            let chunk = String(all[i..<(i + 11)])
            words.append(bip39English[Int(chunk, radix: 2)!])
            i += 11
        }
        return words.joined(separator: " ")
    }

    /// Check a phrase - wordlist AND checksum - returning it normalised and
    /// single-spaced. A mistyped phrase that is not checked derives a valid
    /// key for an identity nobody owns, so validation is on by default.
    @discardableResult
    public static func validate(_ phrase: String) throws -> String {
        let words = nfkd(phrase).split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" || $0 == "\r" })
            .map(String.init).filter { !$0.isEmpty }
        guard words.count >= 12, words.count <= 24, words.count % 3 == 0 else {
            throw ActiveledgerError.invalidArgument(
                "a BIP-39 phrase is 12, 15, 18, 21 or 24 words, got \(words.count)")
        }
        var bits = ""
        for (i, w) in words.enumerated() {
            guard let index = wordIndex[w] else {
                throw ActiveledgerError.invalidArgument(
                    "word \(i + 1) (\"\(w)\") is not in the BIP-39 English wordlist")
            }
            let b = String(index, radix: 2)
            bits += String(repeating: "0", count: 11 - b.count) + b
        }
        let all = Array(bits)
        let checksumBits = words.count / 3
        let entropyBits = all.count - checksumBits
        var entropy = [UInt8]()
        var i = 0
        while i < entropyBits { entropy.append(UInt8(String(all[i..<(i + 8)]), radix: 2)!); i += 8 }
        let hash = Array(SHA256.hash(data: entropy))
        let expected = String(byteBits(hash[0]).prefix(checksumBits))
        guard String(all[entropyBits...]) == expected else {
            throw ActiveledgerError.invalidArgument(
                "the BIP-39 checksum does not match - the phrase has a typo or the words are in "
                    + "the wrong order. Pass validate: false to derive from a non-mnemonic string.")
        }
        return words.joined(separator: " ")
    }

    /// Turn a recovery phrase into its 64-byte BIP-39 seed.
    public static func toSeed(_ phrase: String, passphrase: String = "", validate doValidate: Bool = true)
        throws -> [UInt8] {
        let checked = doValidate ? try validate(phrase) : nfkd(phrase)
        let salt = Data(("mnemonic" + nfkd(passphrase)).utf8)
        let key = try KDF.Insecure.PBKDF2.deriveKey(
            from: Data(checked.utf8),
            salt: salt,
            using: .sha512,
            outputByteCount: bip39SeedBytes,
            unsafeUncheckedRounds: iterations)
        return key.withUnsafeBytes { [UInt8]($0) }
    }

    /// Turn a 64-byte BIP-39 seed into the seed `type` takes.
    public static func deriveSeed(_ type: KeyType, bip39Seed: [UInt8]) throws -> [UInt8] {
        guard bip39Seed.count == bip39SeedBytes else {
            throw ActiveledgerError.invalidArgument(
                "a BIP-39 seed is \(bip39SeedBytes) bytes, got \(bip39Seed.count)")
        }
        let size = try seedSize(type)
        if type == .secp256k1 { return deriveBip32MasterKey(bip39Seed) }
        // Empty salt == RFC 5869's HashLen zero bytes for HMAC.
        let derived = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: bip39Seed),
            salt: Data(),
            info: Data("activeledger-seed-v1:\(type.wire)".utf8),
            outputByteCount: size)
        return derived.withUnsafeBytes { [UInt8]($0) }
    }

    /// BIP-32's master-key step applied to a BIP-39 seed - the whole of the
    /// secp256k1 derivation (no child paths).
    public static func deriveBip32MasterKey(_ bip39Seed: [UInt8]) -> [UInt8] {
        let mac = HMAC<SHA512>.authenticationCode(
            for: bip39Seed, using: SymmetricKey(data: Data("Bitcoin seed".utf8)))
        return Array(Array(mac).prefix(32))
    }

    /// The legacy scheme: SHA256(phrase) used directly as a secp256k1 scalar.
    /// Recovery only, never for new keys; deliberately does not validate.
    public static func legacySeed(_ phrase: String) -> [UInt8] {
        Array(SHA256.hash(data: Data(phrase.utf8)))
    }

    // MARK: helpers

    private static func byteBits(_ b: UInt8) -> String {
        let s = String(b, radix: 2)
        return String(repeating: "0", count: 8 - s.count) + s
    }

    /// NFKD normalisation, as BIP-39 requires.
    private static func nfkd(_ s: String) -> String { s.decomposedStringWithCompatibilityMapping }
}
