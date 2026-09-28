import Foundation

/// A transaction envelope: the `$tx` body, its `$sigs`, and `$selfsign`.
///
/// Signatures cover `canonicalJSON(tx)` and nothing else - not the envelope.
/// `tx` must be a `.object`, and its member order is what gets signed, because
/// the ledger does not sort keys. Build it once and sign it; if you edit it
/// after signing, sign it again.
public final class Transaction {
    /// The `$tx` body (a `.object`).
    public var tx: JSONValue
    /// Signatures, keyed by signer (identity stream id, or the `$i` label for
    /// a self-signed transaction). Insertion order preserved.
    public private(set) var sigs: [(String, String)]
    /// Whether this is a self-signed transaction.
    public var selfsign: Bool?

    public init(tx: JSONValue, sigs: [(String, String)] = [], selfsign: Bool? = nil) {
        self.tx = tx
        self.sigs = sigs
        self.selfsign = selfsign
    }

    /// Set (or replace) a signature for `signer`.
    public func setSignature(_ signature: String, for signer: String) {
        if let i = sigs.firstIndex(where: { $0.0 == signer }) {
            sigs[i] = (signer, signature)
        } else {
            sigs.append((signer, signature))
        }
    }

    /// The exact string that is signed - the fastest way to diagnose a 1220
    /// "Signature Incorrect".
    public var signedString: String { (try? canonicalJSON(tx)) ?? "" }

    /// The envelope as a JSON value, in the ledger's field order.
    public func toJSONValue() -> JSONValue {
        var members: [(String, JSONValue)] = []
        if let selfsign { members.append(("$selfsign", .bool(selfsign))) }
        members.append(("$sigs", .object(sigs.map { ($0.0, .string($0.1)) })))
        members.append(("$tx", tx))
        return .object(members)
    }
}

/// Builds, signs and sends transactions.
public struct TransactionHandler {
    private let crypto: CryptoProvider

    public init(crypto: CryptoProvider = DefaultCryptoProvider()) {
        self.crypto = crypto
    }

    /// The onboarding transaction for `key`, self-signed.
    ///
    /// `$selfsign` is true and `$sigs` is keyed by the `$i` label (the key
    /// name), not a stream id - there is no stream yet - and `type` is always
    /// present (the ledger defaults a missing type to rsa).
    public func buildOnboardKeyTx(_ key: Key, contract: String = "onboard",
                                  namespace: String = "default") throws -> Transaction {
        let tx = Transaction(
            tx: .object([
                ("$contract", .string(contract)),
                ("$i", .object([
                    (key.name, .object([
                        ("publicKey", .string(key.key.publicKey)),
                        ("type", .string(key.type.wire)),
                    ])),
                ])),
                ("$namespace", .string(namespace)),
            ]),
            selfsign: true)
        return try signTransaction(tx, key: key, selfSignLabel: key.name)
    }

    /// A transaction with one labelled input, signed by `key` (which must be
    /// onboarded). With `selfsign`, the input also carries the key's
    /// `publicKey` and `type`, and `$sigs` is keyed by `inputLabel`.
    public func labelledTransaction(
        key: Key, namespace: String, contract: String, inputLabel: String, stream: String,
        inputData: JSONValue = .object([]), entry: String? = nil,
        outputs: JSONValue? = nil, readonly: JSONValue? = nil, selfsign: Bool = false
    ) throws -> Transaction {
        guard key.identity != nil else {
            throw ActiveledgerError.invalidArgument("Key must have an identity - onboard it first.")
        }
        guard case .object(let inputPairs) = inputData else {
            throw ActiveledgerError.invalidArgument("inputData must be a JSON object")
        }
        var input = inputPairs
        input.append(("$stream", .string(stream)))
        if selfsign {
            input.append(("publicKey", .string(key.key.publicKey)))
            input.append(("type", .string(key.type.wire)))
        }
        var body: [(String, JSONValue)] = [
            ("$contract", .string(contract)),
            ("$i", .object([(inputLabel, .object(input))])),
            ("$namespace", .string(namespace)),
        ]
        if let entry { body.append(("$entry", .string(entry))) }
        if let outputs { body.append(("$o", outputs)) }
        if let readonly { body.append(("$r", readonly)) }

        let tx = Transaction(tx: .object(body), selfsign: selfsign ? true : nil)
        return try signTransaction(tx, key: key, selfSignLabel: selfsign ? inputLabel : nil)
    }

    /// Sign `tx` with `key` and add the signature to `$sigs`. Keyed by
    /// `selfSignLabel` if given, otherwise the identity, otherwise the name.
    @discardableResult
    public func signTransaction(_ tx: Transaction, key: Key, selfSignLabel: String? = nil) throws
        -> Transaction {
        let identifier = selfSignLabel ?? key.identity ?? key.name
        let signed = try canonicalJSON(tx.tx)
        let sig = try crypto.sign(signed, privateKey: key.key.privateKey, type: key.type)
        tx.setSignature(sig, for: identifier)
        return tx
    }

    /// Sign an arbitrary string with `key`, returning the base64 signature.
    public func signString(_ data: String, key: Key) throws -> String {
        try crypto.sign(data, privateKey: key.key.privateKey, type: key.type)
    }

    /// Send `tx` over `connection`.
    public func sendTransaction(_ tx: Transaction, connection: Connection) async throws
        -> LedgerResponse {
        try await connection.sendTransaction(tx)
    }
}
