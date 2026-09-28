import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import Activeledger
import ActiveledgerFalcon

/// Runs against a real Activeledger network.
///
/// Every other test checks the SDK against published vectors. This checks it
/// against running nodes, which are the only thing that actually decides
/// whether a signature is acceptable: the type string, the `$sigs` keying and
/// the exact signed bytes are all invisible to a unit test.
///
/// Start the 4-node network from an `activeledger` checkout:
///
///     npm run test:network:serve
///
/// then, with the URLs it prints:
///
///     AL_NODES=http://localhost:5510 AL_STORAGE=http://localhost:5509 \
///       swift test --filter LiveNetworkTests
///
/// Skips when `AL_NODES` is unset, so `swift test` works with no ledger.
final class LiveNetworkTests: XCTestCase {
    private var nodesEnv: String? { ProcessInfo.processInfo.environment["AL_NODES"] }
    private var storageEnv: String? { ProcessInfo.processInfo.environment["AL_STORAGE"] }

    override func setUp() {
        super.setUp()
        ActiveledgerFalcon.enable()   // register Falcon-512 (ML-DSA is built in)
    }

    private func liveLedger() throws -> Activeledger {
        let nodes = try XCTUnwrap(nodesEnv)
        let first = String(nodes.split(separator: ",").first ?? Substring(nodes))
        return try Activeledger(first)
    }

    private func requireLive() throws {
        if nodesEnv == nil {
            throw XCTSkip("AL_NODES not set - start `npm run test:network:serve` in the activeledger repo")
        }
    }

    private func unique(_ prefix: String) -> String {
        "\(prefix)\(Int(Date().timeIntervalSince1970 * 1_000_000) % 100_000_000)"
    }

    // The full lifecycle for one key type: onboard, then three transactions the
    // ledger must accept and one it must reject.
    private func runLifecycle(_ label: String, type: KeyType, compressed: Bool) async throws {
        let ledger = try liveLedger()

        // Onboard, and confirm the ledger recorded the key exactly.
        let key = try ledger.generateKey("identity", type: type, compressed: compressed)
        let onboard = try await ledger.onboard(key)
        XCTAssertTrue(onboard.committed, "\(label) onboard rejected: \(onboard.raw)")
        let identity = try XCTUnwrap(key.identity)
        XCTAssertFalse(identity.isEmpty)
        try await assertLedgerRecorded(key, connection: ledger.connection)

        // A stream-keyed transaction, signed by the onboarded identity.
        let streamTx = Transaction(tx: .object([
            ("$namespace", .string("default")),
            ("$contract", .string("namespace")),
            ("$i", .object([(identity, .object([("namespace", .string(unique("swift")))]))])),
        ]))
        try ledger.transactions.signTransaction(streamTx, key: key)
        let streamResp = try await ledger.send(streamTx)
        XCTAssertTrue(streamResp.committed, "\(label) stream tx rejected: \(streamResp.raw)")

        // A labelled transaction through the handler.
        let labelledTx = try ledger.transactions.labelledTransaction(
            key: key, namespace: "default", contract: "namespace",
            inputLabel: identity, stream: identity,
            inputData: .object([("namespace", .string(unique("swiftl")))]))
        let labelledResp = try await ledger.send(labelledTx)
        XCTAssertTrue(labelledResp.committed, "\(label) labelled tx rejected: \(labelledResp.raw)")

        // A tampered payload must be rejected: sign an honest body, then change
        // it without re-signing, so the old signature no longer covers the bytes.
        let tampered = Transaction(tx: .object([
            ("$namespace", .string("default")),
            ("$contract", .string("namespace")),
            ("$i", .object([(identity, .object([("namespace", .string(unique("swiftt")))]))])),
        ]))
        try ledger.transactions.signTransaction(tampered, key: key)
        tampered.tx = .object([
            ("$namespace", .string("default")),
            ("$contract", .string("namespace")),
            ("$i", .object([(identity, .object([("namespace", .string(unique("swiftx")))]))])),
        ])
        let tamperedResp = try await ledger.send(tampered)
        XCTAssertFalse(tamperedResp.committed, "\(label) tampered tx accepted: \(tamperedResp.raw)")
    }

    /// Reads the identity's stream from a node's storage service - only
    /// reachable because this is a local test network - and checks the ledger
    /// stored the type and public key byte-for-byte. Skipped if AL_STORAGE is
    /// unset. Fails if the meta never appears.
    private func assertLedgerRecorded(_ key: Key, connection: Connection) async throws {
        guard let storageEnv else { return }
        let storage = String(storageEnv.split(separator: ",").first ?? Substring(storageEnv))
        let identity = try XCTUnwrap(key.identity)
        let path = "\(identity):stream".addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? "\(identity):stream"
        let url = try XCTUnwrap(URL(string: "\(storage)/activeledger/\(path)"))

        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            let (data, status) = try await connection.getData(from: url)
            if status == 200,
               let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let authorities = doc["authorities"] as? [[String: Any]], let first = authorities.first {
                XCTAssertEqual(first["type"] as? String, key.type.wire)
                XCTAssertEqual(first["public"] as? String, key.publicKey)
                return
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        XCTFail("identity meta for \(identity) never appeared in storage")
    }

    // MARK: - Per-type lifecycles

    func testSecp256k1Compressed() async throws {
        try requireLive()
        try await runLifecycle("secp256k1 compressed", type: .secp256k1, compressed: true)
    }

    func testSecp256k1Uncompressed() async throws {
        try requireLive()
        try await runLifecycle("secp256k1 uncompressed", type: .secp256k1, compressed: false)
    }

    func testMLDSA65() async throws {
        try requireLive()
        try await runLifecycle("ml-dsa-65", type: .mlDsa65, compressed: false)
    }

    func testFalcon512() async throws {
        try requireLive()
        try await runLifecycle("falcon-512", type: .falcon512, compressed: false)
    }

    // A key recovered from its phrase signs for the identity it onboarded.
    func testRecoveredKeySignsForItsIdentity() async throws {
        try requireLive()
        let ledger = try liveLedger()
        let phrase = try Recovery.generateMnemonic()

        let original = try ledger.keys.restoreBip39Key("identity", phrase: phrase, type: .mlDsa65)
        try await ledger.onboard(original)
        let identity = try XCTUnwrap(original.identity)

        let recovered = try ledger.keys.restoreBip39Key("identity", phrase: phrase, type: .mlDsa65)
        recovered.identity = identity
        let tx = Transaction(tx: .object([
            ("$namespace", .string("default")),
            ("$contract", .string("namespace")),
            ("$i", .object([(identity, .object([("namespace", .string(unique("swiftr")))]))])),
        ]))
        try ledger.transactions.signTransaction(tx, key: recovered)
        let resp = try await ledger.send(tx)
        XCTAssertTrue(resp.committed, "recovered key rejected: \(resp.raw)")
    }
}
