import Foundation
import Crypto
import _CryptoExtras
import P256K

/// Generates keys and signs and verifies strings - the Swift counterpart of
/// the JavaScript SDK's `ICryptoProvider`. Supply your own to sign in an HSM
/// or secure enclave without touching the handlers.
public protocol CryptoProvider {
    /// A fresh key of `type`. `compressed` applies to secp256k1 only.
    func generate(type: KeyType, compressed: Bool) throws -> KeyMaterial

    /// The key for the algorithm's own `seed` (32 bytes for secp256k1 and
    /// ml-dsa-65, 48 for falcon-512). No KDF; a wrong length is refused.
    func generateFromSeed(_ seed: [UInt8], type: KeyType, compressed: Bool) throws -> KeyMaterial

    /// Sign the UTF-8 bytes of `data`, returning the signature as base64.
    func sign(_ data: String, privateKey: String, type: KeyType) throws -> String

    /// Verify a base64 `signature` over the UTF-8 bytes of `data`. Returns
    /// false, never throws, for a malformed signature or key.
    func verify(_ data: String, signature: String, publicKey: String, type: KeyType) -> Bool
}

extension CryptoProvider {
    public func generate(type: KeyType = .secp256k1, compressed: Bool = false) throws -> KeyMaterial {
        try generate(type: type, compressed: compressed)
    }
    public func sign(_ data: String, privateKey: String, type: KeyType = .secp256k1) throws -> String {
        try sign(data, privateKey: privateKey, type: type)
    }
    public func verify(_ data: String, signature: String, publicKey: String, type: KeyType = .secp256k1) -> Bool {
        verify(data, signature: signature, publicKey: publicKey, type: type)
    }
}

/// The built-in `CryptoProvider`.
public struct DefaultCryptoProvider: CryptoProvider {
    public init() {}

    public func generate(type: KeyType, compressed: Bool) throws -> KeyMaterial {
        if type.isPostQuantum {
            let scheme = try PostQuantum.scheme(for: type)
            let (pub, prv) = try scheme.generateKeyPair(seed: nil)
            return KeyMaterial(publicKey: pub.base64EncodedString(), privateKey: prv.base64EncodedString())
        }
        try requireSecp256k1(type)
        var scalar = [UInt8](repeating: 0, count: 32)
        repeat { for i in scalar.indices { scalar[i] = UInt8.random(in: 0...255) } }
            while !Secp256k1.isValidScalar(scalar)
        let (pub, prv) = try Secp256k1.keyPair(fromScalar: scalar, compressed: compressed)
        return KeyMaterial(publicKey: Secp256k1.toHex(pub), privateKey: Secp256k1.toHex(prv))
    }

    public func generateFromSeed(_ seed: [UInt8], type: KeyType, compressed: Bool) throws -> KeyMaterial {
        if type.isPostQuantum {
            let scheme = try PostQuantum.scheme(for: type)
            guard seed.count == scheme.seedSize else {
                throw ActiveledgerError.invalidArgument(
                    "\(type.wire) needs a \(scheme.seedSize)-byte seed, got \(seed.count)")
            }
            let (pub, prv) = try scheme.generateKeyPair(seed: Data(seed))
            return KeyMaterial(publicKey: pub.base64EncodedString(), privateKey: prv.base64EncodedString())
        }
        try requireSecp256k1(type)
        let (pub, prv) = try Secp256k1.keyPair(fromScalar: seed, compressed: compressed)
        return KeyMaterial(publicKey: Secp256k1.toHex(pub), privateKey: Secp256k1.toHex(prv))
    }

    public func sign(_ data: String, privateKey: String, type: KeyType) throws -> String {
        let message = Data(data.utf8)

        if type.isPostQuantum {
            let scheme = try PostQuantum.scheme(for: type)
            let prv = try base64(privateKey, type, "private")
            guard prv.count == scheme.privateKeyBytes else {
                throw ActiveledgerError.invalidArgument(
                    "\(type.wire) private key should be \(scheme.privateKeyBytes) bytes, got \(prv.count)")
            }
            return try scheme.sign(message, privateKey: prv).base64EncodedString()
        }

        if looksLikePem(privateKey) {
            // Sign with whatever the PEM actually holds: a legacy identity's
            // type string is not always accurate.
            if let rsa = try? _RSA.Signing.PrivateKey(pemRepresentation: privateKey) {
                let sig = try rsa.signature(for: message, padding: .insecurePKCS1v1_5)
                return sig.rawRepresentation.base64EncodedString()
            }
            let ec = try P256K.Signing.PrivateKey(pemRepresentation: privateKey)
            let der = try Secp256k1.sign(message, privateScalar: [UInt8](ec.dataRepresentation))
            return Data(der).base64EncodedString()
        }

        if type == .rsa {
            throw ActiveledgerError.invalidArgument("An rsa private key must be PEM")
        }
        let scalar = try Secp256k1.fromHex(privateKey, "private")
        let der = try Secp256k1.sign(message, privateScalar: scalar)
        return Data(der).base64EncodedString()
    }

    public func verify(_ data: String, signature: String, publicKey: String, type: KeyType) -> Bool {
        guard let sig = Data(base64Encoded: signature) else { return false }
        let message = Data(data.utf8)
        do {
            if type.isPostQuantum {
                let scheme = try PostQuantum.scheme(for: type)
                return scheme.verify(sig, message: message, publicKey: try base64(publicKey, type, "public"))
            }
            if looksLikePem(publicKey) {
                if let rsa = try? _RSA.Signing.PublicKey(pemRepresentation: publicKey) {
                    return rsa.isValidSignature(
                        _RSA.Signing.RSASignature(rawRepresentation: sig),
                        for: message, padding: .insecurePKCS1v1_5)
                }
                let ec = try P256K.Signing.PublicKey(pemRepresentation: publicKey)
                return Secp256k1.verify(message, der: [UInt8](sig), publicKey: [UInt8](ec.dataRepresentation))
            }
            if type == .rsa { return false }
            return Secp256k1.verify(message, der: [UInt8](sig),
                                    publicKey: try Secp256k1.fromHex(publicKey, "public"))
        } catch {
            return false
        }
    }

    // MARK: helpers

    private func requireSecp256k1(_ type: KeyType) throws {
        guard type == .secp256k1 else {
            throw ActiveledgerError.invalidArgument(
                "Cannot generate a \"\(type.wire)\" key - supported types are secp256k1, ml-dsa-65 and falcon-512")
        }
    }

    private func looksLikePem(_ s: String) -> Bool { s.contains("-----BEGIN") }

    private func base64(_ value: String, _ type: KeyType, _ what: String) throws -> Data {
        if value.hasPrefix("0x") {
            throw ActiveledgerError.invalidArgument(
                "\(type.wire) \(what) key looks like hex - post-quantum keys are base64 of the raw bytes")
        }
        guard let d = Data(base64Encoded: value) else {
            throw ActiveledgerError.invalidArgument("\(type.wire) \(what) key is not valid base64")
        }
        return d
    }
}
