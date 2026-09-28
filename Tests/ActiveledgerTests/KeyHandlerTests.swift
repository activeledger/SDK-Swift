import XCTest
@testable import Activeledger

private struct KeyPhraseVector: Codable {
    let type: String
    let phraseName: String
    let phrase: String
    let passphrase: String?
    let scheme: String?
    let publicKeyForm: String?
    let publicKey: String?
    let privateKey: String?
}
private struct KeySeedVector: Codable {
    let type: String
    let seedName: String
    let seed: String
    let valid: Bool
    let publicKeyForm: String?
    let publicKey: String?
    let privateKey: String?
}
private struct KeySeedFile: Codable {
    let seedVectors: [KeySeedVector]
    let phraseVectors: [KeyPhraseVector]
}

final class KeyHandlerTests: XCTestCase {
    private let keys = KeyHandler()
    private let crypto = DefaultCryptoProvider()

    private func file() throws -> KeySeedFile {
        let url = Vectors.directory.appendingPathComponent("seed-vectors.json")
        return try JSONDecoder().decode(KeySeedFile.self, from: Data(contentsOf: url))
    }

    func testGenerateSecp256k1RoundTrips() throws {
        let key = try keys.generateKey("me")
        XCTAssertEqual(key.type, .secp256k1)
        XCTAssertTrue(key.publicKey.hasPrefix("0x"))
        let sig = try crypto.sign("hello", privateKey: key.key.privateKey, type: .secp256k1)
        XCTAssertTrue(crypto.verify("hello", signature: sig, publicKey: key.publicKey, type: .secp256k1))
    }

    func testGenerateFromSeedMatchesSecpSeedVectors() throws {
        for v in try file().seedVectors where v.type == "secp256k1" && v.valid {
            guard let pk = v.publicKey, let sk = v.privateKey else { continue }
            let seed = try Secp256k1.fromHex("0x" + v.seed, "seed")
            let compressed = (v.publicKeyForm ?? "") == "compressed"
            let key = try keys.generateKeyFromSeed("k", seed: seed, type: .secp256k1, compressed: compressed)
            XCTAssertEqual(key.publicKey, pk, "\(v.seedName): public key")
            XCTAssertEqual(key.key.privateKey, sk, "\(v.seedName): private key")
        }
    }

    func testRestoreBip39SecpMatchesPhraseVectors() throws {
        for v in try file().phraseVectors where v.type == "secp256k1" {
            guard let pk = v.publicKey, let sk = v.privateKey else { continue }
            let legacy = v.scheme == "legacy"
            let compressed = (v.publicKeyForm ?? "") == "compressed"
            let key = try keys.restoreBip39Key(
                "k", phrase: v.phrase, type: .secp256k1,
                passphrase: v.passphrase ?? "", compressed: compressed, legacy: legacy)
            XCTAssertEqual(key.publicKey, pk, "\(v.phraseName)/\(v.scheme ?? "v1"): public key")
            XCTAssertEqual(key.key.privateKey, sk, "\(v.phraseName)/\(v.scheme ?? "v1"): private key")
            XCTAssertEqual(key.phrase, v.phrase)
        }
    }

    func testLegacyRejectsPostQuantum() {
        XCTAssertThrowsError(try keys.restoreBip39Key("k", phrase: "x", type: .mlDsa65, legacy: true))
    }

    func testKeyFileRoundTrips() throws {
        let original = Key(name: "id", type: .secp256k1,
                           key: KeyMaterial(publicKey: "0x04aa", privateKey: "0xbb"),
                           identity: "streamid", phrase: nil)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(Key.self, from: data)
        XCTAssertEqual(decoded.name, "id")
        XCTAssertEqual(decoded.type, .secp256k1)
        XCTAssertEqual(decoded.key, original.key)
        XCTAssertEqual(decoded.identity, "streamid")
    }

    func testDecodesJavaScriptKeyFileShape() throws {
        let json = #"""
        {"key":{"pub":{"pkcs8pem":"0x04aa"},"prv":{"pkcs8pem":"0xbb"}},"name":"id","type":"secp256k1"}
        """#
        let key = try JSONDecoder().decode(Key.self, from: Data(json.utf8))
        XCTAssertEqual(key.name, "id")
        XCTAssertEqual(key.type, .secp256k1)
        XCTAssertEqual(key.publicKey, "0x04aa")
        XCTAssertEqual(key.key.privateKey, "0xbb")
    }

    func testExportImportRoundTrips() throws {
        let dir = NSTemporaryDirectory() + "al-keys-\(UUID().uuidString)"
        let key = try keys.generateKey("myid")
        try keys.exportKey(key, to: dir, createDir: true)
        let loaded = try keys.importKey("\(dir)/myid.json")
        XCTAssertEqual(loaded.publicKey, key.publicKey)
        XCTAssertEqual(loaded.key.privateKey, key.key.privateKey)
        XCTAssertEqual(loaded.type, .secp256k1)
        try? FileManager.default.removeItem(atPath: dir)
    }
}
