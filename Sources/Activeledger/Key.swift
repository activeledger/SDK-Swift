import Foundation

/// The encoded halves of a key pair, as the ledger and key files carry them.
///
/// secp256k1 keys are `0x`-prefixed hex, post-quantum keys are base64 of the
/// raw bytes, and legacy RSA keys are PEM. Serialises to the JavaScript SDK's
/// shape - `{"pub":{"pkcs8pem":...},"prv":{"pkcs8pem":...}}` - so key files
/// move between the two unchanged. The field is called `pkcs8pem` there for
/// historical reasons; it is not PEM for anything but RSA.
public struct KeyMaterial: Codable, Equatable, Sendable {
    /// Give this to the ledger.
    public let publicKey: String
    /// Keep this.
    public let privateKey: String

    public init(publicKey: String, privateKey: String) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    private struct Half: Codable { let pkcs8pem: String }
    private enum CodingKeys: String, CodingKey { case pub, prv }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        publicKey = try c.decode(Half.self, forKey: .pub).pkcs8pem
        privateKey = try c.decode(Half.self, forKey: .prv).pkcs8pem
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(Half(pkcs8pem: privateKey), forKey: .prv)
        try c.encode(Half(pkcs8pem: publicKey), forKey: .pub)
    }
}

extension KeyMaterial {
    /// Throw unless the private and public halves belong together. secp256k1
    /// (hex): the public key must be a valid point and equal the one derived
    /// from the scalar. Post-quantum: a signature made with the private key
    /// must verify under the public key (skipped when the scheme is not
    /// registered, as with Falcon-512 without its add-on). PEM keys (RSA and
    /// legacy) are not checked here.
    func requireConsistent(type: KeyType) throws {
        if type.isPostQuantum {
            guard PostQuantum.isAvailable(type) else { return }
            let scheme = try PostQuantum.scheme(for: type)
            guard let pub = Data(base64Encoded: publicKey), pub.count == scheme.publicKeyBytes,
                  let prv = Data(base64Encoded: privateKey), prv.count == scheme.privateKeyBytes else {
                throw ActiveledgerError.invalidArgument(
                    "\(type.wire) key pair is malformed: the public key must be base64 of "
                        + "\(scheme.publicKeyBytes) bytes and the private key of \(scheme.privateKeyBytes)")
            }
            let probe = Data("activeledger key pair check".utf8)
            let signature = try scheme.sign(probe, privateKey: prv)
            guard scheme.verify(signature, message: probe, publicKey: pub) else {
                throw ActiveledgerError.invalidArgument(
                    "\(type.wire) public key does not belong to the private key")
            }
            return
        }
        guard type == .secp256k1, !publicKey.contains("-----BEGIN"),
              !privateKey.contains("-----BEGIN") else { return }
        let pub = try Secp256k1.fromHex(publicKey, "public")
        _ = try Secp256k1.parsePublicKey(pub)
        let derived = try Secp256k1.keyPair(
            fromScalar: Secp256k1.fromHex(privateKey, "private"),
            compressed: pub.count == Secp256k1.publicCompressedBytes).publicKey
        guard derived == pub else {
            throw ActiveledgerError.invalidArgument(
                "secp256k1 public key does not belong to the private key")
        }
    }
}

/// A named key, and the identity (stream id) it controls once onboarded.
///
/// Serialised the same way as the JavaScript SDK's `IKey`, so a key exported
/// by either SDK imports into the other.
public final class Key: Codable {
    /// The name the key is known by - the `$i` label when onboarding.
    public let name: String
    /// The signature scheme.
    public let type: KeyType
    /// The encoded key pair.
    public let key: KeyMaterial
    /// The identity stream id, set once the key has been onboarded.
    public var identity: String?
    /// The BIP-39 recovery phrase, when the key was made from one.
    public let phrase: String?

    public init(name: String, type: KeyType, key: KeyMaterial,
                identity: String? = nil, phrase: String? = nil) {
        self.name = name
        self.type = type
        self.key = key
        self.identity = identity
        self.phrase = phrase
    }

    /// The public key, as given to the ledger.
    public var publicKey: String { key.publicKey }

    private enum CodingKeys: String, CodingKey { case key, name, type, phrase, identity }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        // The ledger defaults a missing type to rsa, never what a modern key
        // is, so a guess would be wrong in the worst way - require it.
        type = try KeyType.fromWire(c.decode(String.self, forKey: .type))
        key = try c.decode(KeyMaterial.self, forKey: .key)
        try key.requireConsistent(type: type)
        identity = try c.decodeIfPresent(String.self, forKey: .identity)
        phrase = try c.decodeIfPresent(String.self, forKey: .phrase)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(key, forKey: .key)
        try c.encode(name, forKey: .name)
        try c.encode(type.wire, forKey: .type)
        try c.encodeIfPresent(phrase, forKey: .phrase)
        try c.encodeIfPresent(identity, forKey: .identity)
    }
}
