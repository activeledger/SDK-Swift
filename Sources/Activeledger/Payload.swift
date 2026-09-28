import Foundation

/// Signs and verifies arbitrary payloads - an exchange order, an attestation,
/// an auth challenge - as opposed to transactions.
public struct PayloadHandler {
    private let crypto: CryptoProvider

    public init(crypto: CryptoProvider = DefaultCryptoProvider()) {
        self.crypto = crypto
    }

    /// The exact string `sign`/`verify` operate on. `canonicalJSON` is
    /// **key-order sensitive**: the same fields in a different order produce a
    /// signature that will not verify. Persist what this returns alongside the
    /// signature, and verify that.
    public func canonical(_ payload: JSONValue) throws -> String {
        if case .string(let s) = payload { return s }
        return try canonicalJSON(payload)
    }

    /// Sign `payload` with `key`, returning a base64 signature. The key
    /// carries its own scheme.
    public func sign(_ payload: JSONValue, key: Key) throws -> String {
        try crypto.sign(canonical(payload), privateKey: key.key.privateKey, type: key.type)
    }

    /// Verify `payload` against a signer's `publicKey` and `type`. Returns
    /// false rather than throwing on malformed input.
    public func verify(_ payload: JSONValue, signature: String, publicKey: String,
                       type: KeyType = .secp256k1) -> Bool {
        guard let data = try? canonical(payload) else { return false }
        return crypto.verify(data, signature: signature, publicKey: publicKey, type: type)
    }
}
