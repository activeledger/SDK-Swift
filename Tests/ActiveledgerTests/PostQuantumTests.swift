import XCTest
@testable import Activeledger
import ActiveledgerFalcon

private struct PQVector: Codable {
    let type: String
    let message: String
    let publicKey: String
    let privateKey: String
    let signature: String
}
private struct PQFile: Codable { let vectors: [PQVector] }

private struct SeedVector: Codable {
    let type: String
    let seedName: String
    let seed: String
    let valid: Bool
    let publicKey: String?
}
private struct SeedFile: Codable { let seedVectors: [SeedVector] }

final class PostQuantumTests: XCTestCase {
    override func setUp() {
        super.setUp()
        ActiveledgerFalcon.enable()   // register Falcon-512 (ML-DSA is built in)
    }

    private func pqVectors() throws -> [PQVector] {
        let url = Vectors.directory.appendingPathComponent("pq-vectors.json")
        return try JSONDecoder().decode(PQFile.self, from: Data(contentsOf: url)).vectors
    }
    private func seedVectors() throws -> [SeedVector] {
        let url = Vectors.directory.appendingPathComponent("seed-vectors.json")
        return try JSONDecoder().decode(SeedFile.self, from: Data(contentsOf: url)).seedVectors
    }
    private func data(base64 s: String) throws -> Data {
        try XCTUnwrap(Data(base64Encoded: s))
    }
    private func data(hex s: String) -> Data {
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex, let j = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            out.append(UInt8(s[i..<j], radix: 16) ?? 0); i = j
        }
        return Data(out)
    }

    // Both post-quantum schemes are present (ML-DSA always; Falcon after enable).
    func testSchemesAvailable() {
        XCTAssertTrue(PostQuantum.isAvailable(.mlDsa65))
        XCTAssertTrue(PostQuantum.isAvailable(.falcon512))
    }

    // fromSeed reproduces the exact public key every SDK derives from the seed.
    func testSeedKeygenIsByteExact() throws {
        let vs = try seedVectors().filter { $0.type == "ml-dsa-65" || $0.type == "falcon-512" }
        XCTAssertFalse(vs.isEmpty)
        for v in vs {
            guard let expected = v.publicKey else { continue }
            let scheme = try PostQuantum.scheme(for: try KeyType.fromWire(v.type))
            let seed = data(hex: v.seed)
            XCTAssertEqual(seed.count, scheme.seedSize, "\(v.type)/\(v.seedName): seed length")
            let (pub, prv) = try scheme.generateKeyPair(seed: seed)
            XCTAssertEqual(pub.base64EncodedString(), expected,
                           "\(v.type)/\(v.seedName): derived public key")
            XCTAssertEqual(pub.count, scheme.publicKeyBytes)
            XCTAssertEqual(prv.count, scheme.privateKeyBytes)
            // Deterministic: the same seed gives the same key.
            let (pub2, _) = try scheme.generateKeyPair(seed: seed)
            XCTAssertEqual(pub, pub2, "\(v.type)/\(v.seedName): keygen is deterministic")
        }
    }

    // The reference signatures verify, and a fresh signature round-trips.
    func testSignatureVectors() throws {
        let vs = try pqVectors().filter { $0.type == "ml-dsa-65" || $0.type == "falcon-512" }
        XCTAssertFalse(vs.isEmpty)
        for v in vs {
            let scheme = try PostQuantum.scheme(for: try KeyType.fromWire(v.type))
            let pub = try data(base64: v.publicKey)
            let prv = try data(base64: v.privateKey)
            let sig = try data(base64: v.signature)
            let msg = Data(v.message.utf8)

            XCTAssertTrue(scheme.verify(sig, message: msg, publicKey: pub),
                          "\(v.type): reference signature verifies")

            let fresh = try scheme.sign(msg, privateKey: prv)
            XCTAssertTrue(scheme.verify(fresh, message: msg, publicKey: pub),
                          "\(v.type): fresh signature round-trips")

            // Tampered message must not verify.
            var tampered = msg; tampered.append(0x21)
            XCTAssertFalse(scheme.verify(sig, message: tampered, publicKey: pub),
                           "\(v.type): tampered message rejected")
        }
    }

    // Signing is hedged: two signatures over one message differ, both verify.
    func testSigningIsHedged() throws {
        for type in [KeyType.mlDsa65, .falcon512] {
            let scheme = try PostQuantum.scheme(for: type)
            let (pub, prv) = try scheme.generateKeyPair(seed: nil)
            let msg = Data("hedge me".utf8)
            let a = try scheme.sign(msg, privateKey: prv)
            let b = try scheme.sign(msg, privateKey: prv)
            XCTAssertNotEqual(a, b, "\(type.wire): hedged signatures differ")
            XCTAssertTrue(scheme.verify(a, message: msg, publicKey: pub))
            XCTAssertTrue(scheme.verify(b, message: msg, publicKey: pub))
        }
    }

    // A wrong-length seed is refused, not padded.
    func testWrongSeedLengthRejected() throws {
        for type in [KeyType.mlDsa65, .falcon512] {
            let scheme = try PostQuantum.scheme(for: type)
            XCTAssertThrowsError(try scheme.generateKeyPair(seed: Data(repeating: 0, count: 7)))
        }
    }

    // Falcon keys carry their 1-byte header; the sizes are the ledger's.
    func testFalconKeyShape() throws {
        let scheme = try PostQuantum.scheme(for: .falcon512)
        let (pub, prv) = try scheme.generateKeyPair(seed: nil)
        XCTAssertEqual(pub.count, 897)
        XCTAssertEqual(prv.count, 1281)
        XCTAssertEqual(pub.first, 0x09)
        XCTAssertEqual(prv.first, 0x59)
        let sig = try scheme.sign(Data("x".utf8), privateKey: prv)
        XCTAssertEqual(sig.first, 0x39)
    }

    // End to end through the provider and key handler.
    func testProviderAndKeyHandlerRoundTrip() throws {
        for type in [KeyType.mlDsa65, .falcon512] {
            let keys = KeyHandler()
            let key = try keys.generateKey("me", type: type)
            let payloads = PayloadHandler()
            let order: JSONValue = .object([("v", .integer(1))])
            let sig = try payloads.sign(order, key: key)
            XCTAssertTrue(payloads.verify(order, signature: sig,
                                          publicKey: key.publicKey, type: type))
        }
    }

    // One BIP-39 phrase backs a post-quantum identity, byte-for-byte portable.
    func testBip39BackedPostQuantumKey() throws {
        for type in [KeyType.mlDsa65, .falcon512] {
            let keys = KeyHandler()
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            let a = try keys.restoreBip39Key("me", phrase: phrase, type: type)
            let b = try keys.restoreBip39Key("me", phrase: phrase, type: type)
            XCTAssertEqual(a.publicKey, b.publicKey, "\(type.wire): phrase-derived key is stable")
        }
    }
}
