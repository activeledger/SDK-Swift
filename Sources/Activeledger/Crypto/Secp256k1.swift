import Foundation
import P256K

/// secp256k1, encoded the way Activeledger stores it: `0x`-prefixed hex keys,
/// base64 DER signatures. Signing is RFC 6979 deterministic and low-S (so it
/// is byte-identical to @noble/curves and libsecp256k1); verification accepts
/// high-S as well, because the ledger produces high-S through OpenSSL.
public enum Secp256k1 {
    public static let publicCompressedBytes = 33
    public static let publicUncompressedBytes = 65
    public static let privateBytes = 32

    /// The curve order n, big-endian.
    static let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]
    /// n >> 1 (the low-S threshold), big-endian.
    static let halfOrder: [UInt8] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    ]

    // MARK: keys

    /// The key pair for a 32-byte private scalar. Refused (not reduced mod n)
    /// when the scalar is 0 or >= n: reducing produces a working key for a
    /// different identity, silently.
    public static func keyPair(fromScalar scalar: [UInt8], compressed: Bool)
        throws -> (publicKey: [UInt8], privateKey: [UInt8]) {
        guard scalar.count == privateBytes else {
            throw ActiveledgerError.invalidArgument(
                "secp256k1 needs a 32-byte seed, got \(scalar.count)")
        }
        guard isValidScalar(scalar) else {
            throw ActiveledgerError.invalidArgument(
                "seed is not a valid secp256k1 private key - the scalar must be in [1, n-1]")
        }
        let format: P256K.Format = compressed ? .compressed : .uncompressed
        let key = try P256K.Signing.PrivateKey(dataRepresentation: Data(scalar), format: format)
        return ([UInt8](key.publicKey.dataRepresentation), scalar)
    }

    /// Whether `scalar` is a usable private key: in [1, n-1].
    public static func isValidScalar(_ scalar: [UInt8]) -> Bool {
        let d = pad32(scalar)
        return !isZero(d) && compare(d, order) < 0
    }

    // MARK: sign / verify

    /// Sign `message` (RFC 6979, low-S), returning DER bytes.
    public static func sign(_ message: Data, privateScalar: [UInt8]) throws -> [UInt8] {
        let key = try P256K.Signing.PrivateKey(dataRepresentation: Data(privateScalar))
        let signature = key.signature(for: message)
        return [UInt8](signature.derRepresentation)
    }

    /// Verify a DER signature, accepting HIGH-S as well as low (the ledger
    /// emits high-S freely, so rejecting it would reject about half of
    /// everything it signs).
    public static func verify(_ message: Data, der: [UInt8], publicKey: [UInt8]) -> Bool {
        do {
            let (r, s) = try DER.decodeSignature(der)
            guard !isZero(pad32(r)), compare(pad32(r), order) < 0,
                  !isZero(pad32(s)), compare(pad32(s), order) < 0 else { return false }
            let normalized = DER.encodeSignature(r: r, s: lowS(s))
            let format: P256K.Format =
                publicKey.count == publicCompressedBytes ? .compressed : .uncompressed
            let pub = try P256K.Signing.PublicKey(dataRepresentation: Data(publicKey), format: format)
            let sig = try P256K.Signing.ECDSASignature(derRepresentation: Data(normalized))
            return pub.isValidSignature(sig, for: message)
        } catch {
            return false
        }
    }

    /// Whether a DER signature's S is in the upper half of the curve order.
    public static func isHighS(_ der: [UInt8]) -> Bool {
        guard let s = try? DER.decodeSignature(der).s else { return false }
        return compare(pad32(s), halfOrder) > 0
    }

    /// Fold S into the lower half of the curve order.
    static func lowS(_ s: [UInt8]) -> [UInt8] {
        let padded = pad32(s)
        return compare(padded, halfOrder) > 0 ? subtract(order, padded) : padded
    }

    // MARK: hex

    /// `0x` + lowercase hex.
    public static func toHex(_ bytes: [UInt8]) -> String {
        "0x" + bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Decode an `0x`-prefixed hex key. The prefix is required, not tolerated.
    public static func fromHex(_ value: String, _ what: String) throws -> [UInt8] {
        guard value.hasPrefix("0x") else {
            throw ActiveledgerError.invalidArgument(
                "secp256k1 \(what) key must start with '0x' - that prefix is part of "
                    + "what the ledger stores. Post-quantum keys are base64; these are not.")
        }
        let body = value.dropFirst(2)
        guard body.count % 2 == 0 else {
            throw ActiveledgerError.invalidArgument(
                "secp256k1 \(what) key has an odd number of hex digits (\(body.count))")
        }
        var out = [UInt8]()
        out.reserveCapacity(body.count / 2)
        var idx = body.startIndex
        while idx < body.endIndex {
            let next = body.index(idx, offsetBy: 2)
            guard let byte = UInt8(body[idx..<next], radix: 16) else {
                throw ActiveledgerError.invalidArgument("secp256k1 \(what) key is not valid hex")
            }
            out.append(byte)
            idx = next
        }
        return out
    }

    // MARK: 32-byte big-endian helpers

    private static func pad32(_ b: [UInt8]) -> [UInt8] {
        if b.count == 32 { return b }
        if b.count > 32 { return Array(b.suffix(32)) }
        return [UInt8](repeating: 0, count: 32 - b.count) + b
    }

    private static func isZero(_ b: [UInt8]) -> Bool { b.allSatisfy { $0 == 0 } }

    /// -1, 0, 1 for a<b, a==b, a>b (both 32-byte big-endian).
    private static func compare(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for i in 0..<32 {
            if a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
        }
        return 0
    }

    /// a - b (both 32-byte big-endian, a >= b).
    private static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var diff = Int(a[i]) - Int(b[i]) - borrow
            if diff < 0 { diff += 256; borrow = 1 } else { borrow = 0 }
            out[i] = UInt8(diff)
        }
        return out
    }
}
