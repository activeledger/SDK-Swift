import Foundation

/// Generates, recovers and stores keys. (`onboardKey` arrives with the
/// transaction layer.)
public struct KeyHandler {
    private let crypto: CryptoProvider

    public init(crypto: CryptoProvider = DefaultCryptoProvider()) {
        self.crypto = crypto
    }

    /// A new key. `compressed` selects a 33-byte rather than 65-byte
    /// secp256k1 public key and is ignored by the post-quantum schemes. For a
    /// post-quantum identity with the smallest signatures available, pass
    /// `type: .preferredPostQuantum`.
    public func generateKey(_ name: String, type: KeyType = .secp256k1, compressed: Bool = false)
        throws -> Key {
        Key(name: name, type: type, key: try crypto.generate(type: type, compressed: compressed))
    }

    /// Recreate a key from the algorithm's own seed (no KDF; a wrong length is
    /// refused). The same seed produces the same identity in every
    /// Activeledger SDK.
    public func generateKeyFromSeed(_ name: String, seed: [UInt8], type: KeyType = .secp256k1,
                                    compressed: Bool = false) throws -> Key {
        Key(name: name, type: type,
            key: try crypto.generateFromSeed(seed, type: type, compressed: compressed))
    }

    /// A new key with a fresh 12-word BIP-39 recovery phrase (available as
    /// `Key.phrase`).
    public func generateBip39Key(_ name: String, type: KeyType = .secp256k1,
                                 passphrase: String = "", compressed: Bool = false) throws -> Key {
        try restoreBip39Key(name, phrase: Recovery.generateMnemonic(), type: type,
                            passphrase: passphrase, compressed: compressed)
    }

    /// Recreate a key from a BIP-39 recovery phrase. Each `type` derives its
    /// own seed, so one phrase can back a secp256k1, an ml-dsa-65 and a
    /// falcon-512 identity at once. The phrase is validated unless
    /// `validate` is false. `legacy` reproduces the original
    /// `@activeledger/sdk-bip39` scheme (secp256k1 only; recovery only).
    public func restoreBip39Key(_ name: String, phrase: String, type: KeyType = .secp256k1,
                                passphrase: String = "", compressed: Bool = false,
                                legacy: Bool = false, validate: Bool = true) throws -> Key {
        if legacy && type != .secp256k1 {
            throw ActiveledgerError.invalidArgument(
                "The legacy BIP-39 scheme is secp256k1 only - it cannot derive \(type.wire)")
        }
        let seed: [UInt8]
        if legacy {
            seed = Recovery.legacySeed(phrase)
        } else {
            let bip39 = try Recovery.toSeed(phrase, passphrase: passphrase, validate: validate)
            seed = try Recovery.deriveSeed(type, bip39Seed: bip39)
        }
        return Key(name: name, type: type,
                   key: try crypto.generateFromSeed(seed, type: type, compressed: compressed),
                   phrase: phrase)
    }

    /// Onboard `key` - create its identity on the ledger - and set
    /// `key.identity` to the new stream id. Throws `ActiveledgerError.onboard`
    /// if the ledger did not create a stream.
    @discardableResult
    public func onboardKey(_ key: Key, connection: Connection, contract: String = "onboard",
                           namespace: String = "default") async throws -> LedgerResponse {
        let handler = TransactionHandler(crypto: crypto)
        let tx = try handler.buildOnboardKeyTx(key, contract: contract, namespace: namespace)
        let response = try await handler.sendTransaction(tx, connection: connection)
        guard let first = response.created.first else {
            let detail = response.errors.isEmpty ? "" : ": \(response.errors.joined(separator: "; "))"
            throw ActiveledgerError.onboard(message: "Onboarding \"\(key.name)\" created no identity\(detail)")
        }
        key.identity = first.id
        return response
    }

    /// Write `key` to `<location>/<name ?? key.name>.json` in the JavaScript
    /// SDK's key file format. The file contains the private key.
    public func exportKey(_ key: Key, to location: String, createDir: Bool = false,
                          overwrite: Bool = false, name: String? = nil) throws {
        let fm = FileManager.default
        if createDir {
            try fm.createDirectory(atPath: location, withIntermediateDirectories: true)
        }
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: location, isDirectory: &isDir), isDir.boolValue else {
            throw ActiveledgerError.invalidArgument("Unable to find location: \(location)")
        }
        let base = location.hasSuffix("/") ? String(location.dropLast()) : location
        let path = "\(base)/\(name ?? key.name).json"
        if fm.fileExists(atPath: path) && !overwrite {
            throw ActiveledgerError.invalidArgument(
                "File already exists, set overwrite to true or use a different name: \(path)")
        }
        let data = try JSONEncoder().encode(key)
        try data.write(to: URL(fileURLWithPath: path))
    }

    /// Read a key file written by `exportKey` or by the JavaScript SDK.
    public func importKey(_ path: String) throws -> Key {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Key.self, from: data)
    }
}
