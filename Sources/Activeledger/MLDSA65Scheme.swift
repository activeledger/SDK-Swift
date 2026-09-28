import Foundation
import CMLDSA

/// ML-DSA-65 (FIPS 204), backed by the vendored PQClean implementation.
///
/// Registered automatically - it is always available, as in every Activeledger
/// SDK. Keys are the raw FIPS 204 byte forms (1952-byte public, 4032-byte
/// private); a key derived from a seed is a pure function of that seed, so the
/// same seed yields the same identity here and in the JavaScript and Dart SDKs.
public struct MLDSA65Scheme: PostQuantumScheme {
    public init() {}

    public var keyType: KeyType { .mlDsa65 }
    public var seedSize: Int { Int(AL_MLDSA65_SEEDBYTES) }
    public var publicKeyBytes: Int { Int(AL_MLDSA65_PUBLICKEYBYTES) }
    public var privateKeyBytes: Int { Int(AL_MLDSA65_SECRETKEYBYTES) }

    public func generateKeyPair(seed: Data?) throws -> (publicKey: Data, privateKey: Data) {
        var pk = [UInt8](repeating: 0, count: publicKeyBytes)
        var sk = [UInt8](repeating: 0, count: privateKeyBytes)
        let rc: Int32
        if let seed {
            guard seed.count == seedSize else {
                throw ActiveledgerError.invalidArgument(
                    "ml-dsa-65 needs a \(seedSize)-byte seed, got \(seed.count)")
            }
            let s = [UInt8](seed)
            rc = al_mldsa65_keypair_from_seed(&pk, &sk, s, s.count)
        } else {
            rc = al_mldsa65_keypair(&pk, &sk)
        }
        guard rc == 0 else {
            throw ActiveledgerError.invalidArgument(
                "ml-dsa-65 key generation failed"
                    + (seed != nil ? " - this build did not derive a portable key from the seed" : ""))
        }
        return (Data(pk), Data(sk))
    }

    public func sign(_ message: Data, privateKey: Data) throws -> Data {
        guard privateKey.count == privateKeyBytes else {
            throw ActiveledgerError.invalidArgument(
                "ml-dsa-65 private key should be \(privateKeyBytes) bytes, got \(privateKey.count)")
        }
        var sig = [UInt8](repeating: 0, count: Int(AL_MLDSA65_SIGNATUREBYTES))
        var siglen = 0
        let msg = [UInt8](message)
        let sk = [UInt8](privateKey)
        let rc = al_mldsa65_sign(&sig, &siglen, msg, msg.count, sk)
        guard rc == 0 else {
            throw ActiveledgerError.invalidArgument("ml-dsa-65 signing failed")
        }
        return Data(sig.prefix(siglen))
    }

    public func verify(_ signature: Data, message: Data, publicKey: Data) -> Bool {
        guard publicKey.count == publicKeyBytes else { return false }
        let sg = [UInt8](signature)
        let msg = [UInt8](message)
        let pk = [UInt8](publicKey)
        return al_mldsa65_verify(sg, sg.count, msg, msg.count, pk) == 0
    }
}
