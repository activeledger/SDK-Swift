import Foundation
import Activeledger
import CFalcon

/// Falcon-512 (FN-DSA), backed by the vendored PQClean implementation.
///
/// Byte forms are the ledger's: keys INCLUDE their 1-byte header (0x09 public,
/// 0x59 private), so they are 897 and 1281 bytes, and signatures are the
/// compressed, variable-length form (649-662 bytes, header 0x39) - not the
/// fixed-length "Falcon-padded-512" form the ledger does not expect.
///
/// Signing is randomised, as in the reference SDK: two signatures over one
/// message differ, and both verify. A key derived from a seed is a pure
/// function of that seed - the same identity every Activeledger SDK derives.
public struct Falcon512Scheme: PostQuantumScheme {
    public init() {}

    public static let publicHeader: UInt8 = 0x09
    public static let privateHeader: UInt8 = 0x59
    public static let signatureHeader: UInt8 = 0x39

    public var keyType: KeyType { .falcon512 }
    public var seedSize: Int { Int(AL_FALCON512_SEEDBYTES) }
    public var publicKeyBytes: Int { Int(AL_FALCON512_PUBLICKEYBYTES) }
    public var privateKeyBytes: Int { Int(AL_FALCON512_SECRETKEYBYTES) }

    public func generateKeyPair(seed: Data?) throws -> (publicKey: Data, privateKey: Data) {
        var pk = [UInt8](repeating: 0, count: publicKeyBytes)
        var sk = [UInt8](repeating: 0, count: privateKeyBytes)
        let rc: Int32
        if let seed {
            guard seed.count == seedSize else {
                throw ActiveledgerError.invalidArgument(
                    "falcon-512 needs a \(seedSize)-byte seed, got \(seed.count)")
            }
            let s = [UInt8](seed)
            rc = al_falcon512_keypair_from_seed(&pk, &sk, s, s.count)
        } else {
            rc = al_falcon512_keypair(&pk, &sk)
        }
        guard rc == 0 else {
            throw ActiveledgerError.invalidArgument(
                "falcon-512 key generation failed"
                    + (seed != nil ? " - this build did not derive a portable key from the seed" : ""))
        }
        return (Data(pk), Data(sk))
    }

    public func sign(_ message: Data, privateKey: Data) throws -> Data {
        guard privateKey.count == privateKeyBytes else {
            throw ActiveledgerError.invalidArgument(
                "falcon-512 private key should be \(privateKeyBytes) bytes, got \(privateKey.count)"
                    + (privateKey.count == privateKeyBytes - 1
                        ? " - this looks like a key with its header byte stripped" : ""))
        }
        guard privateKey.first == Self.privateHeader else {
            throw ActiveledgerError.invalidArgument("falcon-512 private key should start with 0x59")
        }
        var sig = [UInt8](repeating: 0, count: Int(AL_FALCON512_SIGNATUREBYTES))
        var siglen = 0
        let msg = [UInt8](message)
        let sk = [UInt8](privateKey)
        let rc = al_falcon512_sign(&sig, &siglen, msg, msg.count, sk)
        guard rc == 0 else {
            throw ActiveledgerError.invalidArgument("falcon-512 signing failed")
        }
        return Data(sig.prefix(siglen))
    }

    public func verify(_ signature: Data, message: Data, publicKey: Data) -> Bool {
        guard publicKey.count == publicKeyBytes, publicKey.first == Self.publicHeader else {
            return false
        }
        guard signature.first == Self.signatureHeader else { return false }
        let sg = [UInt8](signature)
        let msg = [UInt8](message)
        let pk = [UInt8](publicKey)
        return al_falcon512_verify(sg, sg.count, msg, msg.count, pk) == 0
    }
}
