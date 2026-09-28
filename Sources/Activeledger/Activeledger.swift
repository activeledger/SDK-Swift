import Foundation

/// Everything in one place, for the common case.
///
/// A port of the [JavaScript SDK](https://github.com/activeledger/SDK-JS),
/// the reference implementation: the same handlers, the same key file format,
/// and byte-for-byte the same signatures, checked against the JavaScript SDK's
/// cross-language vectors.
///
/// ```swift
/// let ledger = try Activeledger("http://localhost:5260")
///
/// let key = try ledger.generateKey("me")
/// try await ledger.onboard(key)               // sets key.identity
///
/// let tx = try ledger.transactions.labelledTransaction(
///     key: key, namespace: "default", contract: "mycontract",
///     inputLabel: "input", stream: key.identity!,
///     inputData: .object([("hello", .string("world"))]))
/// let response = try await ledger.send(tx)
/// ```
///
/// The four handlers - ``keys``, ``transactions``, ``payloads`` and
/// ``connection`` - are public, so anything the shorthands do not cover is a
/// handler call away.
///
/// There is deliberately no storage endpoint: a node's storage service
/// listens only on the node's own host. State is read through a transaction -
/// name streams in `$r` and have the contract return values with
/// `returnToRemote`, which arrive in ``LedgerResponse/responses``.
public struct Activeledger {
    /// The SDK version.
    public static let version = "1.0.0"

    /// The node transactions are sent to.
    public let connection: Connection

    /// Generates, recovers, onboards, imports and exports keys.
    public let keys: KeyHandler
    /// Builds, signs and sends transactions.
    public let transactions: TransactionHandler
    /// Signs and verifies arbitrary payloads.
    public let payloads: PayloadHandler

    /// Connect to the node at `nodeUrl` (for example
    /// `http://localhost:5260`). Throws `ActiveledgerError.invalidArgument`
    /// if the URL is not `http`/`https`.
    public init(_ nodeUrl: String, crypto: CryptoProvider = DefaultCryptoProvider()) throws {
        self.connection = try Connection(url: nodeUrl)
        self.keys = KeyHandler(crypto: crypto)
        self.transactions = TransactionHandler(crypto: crypto)
        self.payloads = PayloadHandler(crypto: crypto)
    }

    /// Connect to `scheme://address:port`.
    public init(_ scheme: String, _ address: String, _ port: Int,
                crypto: CryptoProvider = DefaultCryptoProvider()) throws {
        try self.init("\(scheme)://\(address):\(port)", crypto: crypto)
    }

    /// Generate a key. Shorthand for ``KeyHandler/generateKey(_:type:compressed:)``.
    public func generateKey(_ name: String, type: KeyType = .secp256k1,
                            compressed: Bool = false) throws -> Key {
        try keys.generateKey(name, type: type, compressed: compressed)
    }

    /// Onboard `key`, creating its identity on the ledger and setting
    /// `key.identity`. Shorthand for ``KeyHandler/onboardKey(_:connection:contract:namespace:)``.
    @discardableResult
    public func onboard(_ key: Key) async throws -> LedgerResponse {
        try await keys.onboardKey(key, connection: connection)
    }

    /// Send a signed transaction. Shorthand for ``Connection/sendTransaction(_:)``.
    public func send(_ tx: Transaction) async throws -> LedgerResponse {
        try await connection.sendTransaction(tx)
    }
}
