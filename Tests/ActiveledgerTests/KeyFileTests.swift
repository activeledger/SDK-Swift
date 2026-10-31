import XCTest
@testable import Activeledger

final class KeyFileTests: XCTestCase {
    private let keys = KeyHandler()
    private let abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private func tempDir() -> String {
        NSTemporaryDirectory() + "al-keyfile-\(UUID().uuidString)"
    }

    private func decode(_ json: String) throws -> Key {
        try JSONDecoder().decode(Key.self, from: Data(json.utf8))
    }

    // MARK: key file format

    func testDecodeRequiresType() {
        let json = #"{"key":{"pub":{"pkcs8pem":"0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"},"prv":{"pkcs8pem":"0x0000000000000000000000000000000000000000000000000000000000000001"}},"name":"id"}"#
        XCTAssertThrowsError(try decode(json))
    }

    func testDecodeRejectsUnknownType() {
        let json = #"{"key":{"pub":{"pkcs8pem":"a"},"prv":{"pkcs8pem":"b"}},"name":"id","type":"dsa"}"#
        XCTAssertThrowsError(try decode(json))
    }

    func testDecodeMapsBitcoinAndEthereumToSecp256k1AndReencodesAsSecp256k1() throws {
        for legacy in ["bitcoin", "ethereum"] {
            let key = try decode(
                #"{"key":{"pub":{"pkcs8pem":"0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"},"prv":{"pkcs8pem":"0x0000000000000000000000000000000000000000000000000000000000000001"}},"name":"id","type":"\#(legacy)"}"#)
            XCTAssertEqual(key.type, .secp256k1)
            let out = String(decoding: try JSONEncoder().encode(key), as: UTF8.self)
            XCTAssertTrue(out.contains(#""type":"secp256k1""#), out)
            XCTAssertFalse(out.contains(legacy))
        }
    }

    func testDecodeRejectsMissingKeyHalf() {
        XCTAssertThrowsError(try decode(
            #"{"key":{"pub":{"pkcs8pem":"0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"}},"name":"id","type":"secp256k1"}"#))
    }

    func testEncodedShapeMatchesJavaScriptSDK() throws {
        let key = Key(name: "id", type: .mlDsa65,
                      key: KeyMaterial(publicKey: "PUB", privateKey: "PRV"),
                      identity: "stream", phrase: "some words")
        let obj = try JSONSerialization.jsonObject(with: JSONEncoder().encode(key)) as! [String: Any]
        XCTAssertEqual(Set(obj.keys), ["key", "name", "type", "identity", "phrase"])
        XCTAssertEqual(obj["type"] as? String, "ml-dsa-65")
        let material = obj["key"] as! [String: Any]
        XCTAssertEqual((material["pub"] as? [String: String]), ["pkcs8pem": "PUB"])
        XCTAssertEqual((material["prv"] as? [String: String]), ["pkcs8pem": "PRV"])
    }

    func testOptionalFieldsAreOmittedWhenNil() throws {
        let key = Key(name: "id", type: .secp256k1, key: KeyMaterial(publicKey: "a", privateKey: "b"))
        let obj = try JSONSerialization.jsonObject(with: JSONEncoder().encode(key)) as! [String: Any]
        XCTAssertNil(obj["identity"])
        XCTAssertNil(obj["phrase"])
    }

    func testRoundTripKeepsPhraseAndPostQuantumKeys() throws {
        let key = try keys.restoreBip39Key("pq", phrase: abandon, type: .mlDsa65)
        let back = try JSONDecoder().decode(Key.self, from: JSONEncoder().encode(key))
        XCTAssertEqual(back.type, .mlDsa65)
        XCTAssertEqual(back.phrase, abandon)
        XCTAssertEqual(back.key, key.key)
    }

    // MARK: export / import

    func testExportRefusesMissingDirectoryWithoutCreateDir() {
        let dir = tempDir()
        XCTAssertThrowsError(try keys.exportKey(try keys.generateKey("k"), to: dir))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir))
    }

    func testExportRefusesToOverwriteUnlessAsked() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let first = try keys.generateKey("k")
        let second = try keys.generateKey("k")
        try keys.exportKey(first, to: dir, createDir: true)
        XCTAssertThrowsError(try keys.exportKey(second, to: dir))
        XCTAssertEqual(try keys.importKey("\(dir)/k.json").publicKey, first.publicKey)

        try keys.exportKey(second, to: dir, overwrite: true)
        XCTAssertEqual(try keys.importKey("\(dir)/k.json").publicKey, second.publicKey)
    }

    func testExportHonoursNameOverrideAndTrailingSlash() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let key = try keys.generateKey("k")
        key.identity = "streamid"
        try keys.exportKey(key, to: dir + "/", createDir: true, name: "renamed")
        let loaded = try keys.importKey("\(dir)/renamed.json")
        XCTAssertEqual(loaded.name, "k")
        XCTAssertEqual(loaded.identity, "streamid")
    }

    func testExportRefusesAFileAsLocation() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let key = try keys.generateKey("k")
        try keys.exportKey(key, to: dir, createDir: true)
        XCTAssertThrowsError(try keys.exportKey(key, to: "\(dir)/k.json", overwrite: true))
    }

    func testImportMissingFileAndMalformedFileThrow() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        XCTAssertThrowsError(try keys.importKey("\(dir)/absent.json"))
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try Data("not json".utf8).write(to: URL(fileURLWithPath: "\(dir)/bad.json"))
        XCTAssertThrowsError(try keys.importKey("\(dir)/bad.json"))
    }

    // MARK: BIP-39 / seed handling

    func testRestoreBip39IsDeterministicAndPhraseIsKept() throws {
        let a = try keys.restoreBip39Key("a", phrase: abandon)
        let b = try keys.restoreBip39Key("b", phrase: abandon)
        XCTAssertEqual(a.key, b.key)
        XCTAssertEqual(a.phrase, abandon)
    }

    func testPassphraseChangesTheKey() throws {
        let plain = try keys.restoreBip39Key("a", phrase: abandon)
        let salted = try keys.restoreBip39Key("a", phrase: abandon, passphrase: "TREZOR")
        XCTAssertNotEqual(plain.publicKey, salted.publicKey)
    }

    func testOnePhraseBacksDistinctIdentitiesPerKeyType() throws {
        let secp = try keys.restoreBip39Key("a", phrase: abandon, type: .secp256k1)
        let mldsa = try keys.restoreBip39Key("a", phrase: abandon, type: .mlDsa65)
        XCTAssertEqual(mldsa.type, .mlDsa65)
        XCTAssertNotEqual(secp.publicKey, mldsa.publicKey)
        XCTAssertEqual(Data(base64Encoded: mldsa.publicKey)?.count, 1952)
    }

    func testRestoreRejectsBadChecksumUnlessValidationIsOff() throws {
        let typo = abandon.replacingOccurrences(of: "about", with: "abandon")
        XCTAssertThrowsError(try keys.restoreBip39Key("a", phrase: typo))
        let key = try keys.restoreBip39Key("a", phrase: typo, validate: false)
        XCTAssertNotEqual(key.publicKey, try keys.restoreBip39Key("a", phrase: abandon).publicKey)
    }

    func testRestoreNormalisesWhitespace() throws {
        let spaced = "  " + abandon.replacingOccurrences(of: " ", with: "  ") + "\n"
        XCTAssertEqual(try keys.restoreBip39Key("a", phrase: spaced).key,
                       try keys.restoreBip39Key("a", phrase: abandon).key)
    }

    func testGenerateBip39KeyCarriesARecoverablePhrase() throws {
        let key = try keys.generateBip39Key("g", compressed: true)
        let phrase = try XCTUnwrap(key.phrase)
        XCTAssertEqual(phrase.split(separator: " ").count, 12)
        XCTAssertEqual(try keys.restoreBip39Key("g", phrase: phrase, compressed: true).key, key.key)
        XCTAssertEqual(key.publicKey.count, 2 + 66)
    }

    func testGenerateKeyFromSeedIsDeterministicAndCompressionSelectsLength() throws {
        let seed = [UInt8](repeating: 7, count: 32)
        let a = try keys.generateKeyFromSeed("a", seed: seed)
        let b = try keys.generateKeyFromSeed("b", seed: seed)
        XCTAssertEqual(a.key, b.key)
        XCTAssertEqual(a.publicKey.count, 2 + 130)
        let c = try keys.generateKeyFromSeed("c", seed: seed, compressed: true)
        XCTAssertEqual(c.publicKey.count, 2 + 66)
        XCTAssertEqual(c.key.privateKey, a.key.privateKey)
    }

    func testGenerateKeyFromSeedRefusesWrongLengthsAndInvalidScalars() {
        for type in [KeyType.secp256k1, .mlDsa65] {
            XCTAssertThrowsError(try keys.generateKeyFromSeed("x", seed: [1, 2, 3], type: type))
            XCTAssertThrowsError(try keys.generateKeyFromSeed(
                "x", seed: [UInt8](repeating: 1, count: 48), type: type))
        }
        XCTAssertThrowsError(try keys.generateKeyFromSeed(
            "x", seed: [UInt8](repeating: 0, count: 32)), "zero is not a valid scalar")
        XCTAssertThrowsError(try keys.generateKeyFromSeed(
            "x", seed: [UInt8](repeating: 0xff, count: 32)), ">= curve order must be refused, not reduced")
    }

    func testGenerateKeyRefusesRSA() {
        XCTAssertThrowsError(try keys.generateKey("legacy", type: .rsa))
    }

    // MARK: key pair consistency

    private func fileJSON(type: String, pub: String, prv: String) -> String {
        #"{"key":{"pub":{"pkcs8pem":"\#(pub)"},"prv":{"pkcs8pem":"\#(prv)"}},"name":"id","type":"\#(type)"}"#
    }

    private func assertMismatchRejected(_ type: KeyType, _ a: Key, _ b: Key, _ text: String) {
        let json = fileJSON(type: type.wire, pub: a.key.publicKey, prv: b.key.privateKey)
        XCTAssertThrowsError(try decode(json), text) { error in
            XCTAssertTrue("\(error)".contains("does not belong"), "\(error)")
        }
    }

    func testSecp256k1MismatchedPairIsRejected() throws {
        let a = try keys.generateKey("a")
        let b = try keys.generateKey("b")
        assertMismatchRejected(.secp256k1, a, b, "uncompressed")
        let c = try keys.generateKey("c", compressed: true)
        let d = try keys.generateKey("d", compressed: true)
        assertMismatchRejected(.secp256k1, c, d, "compressed")
    }

    func testSecp256k1PairWithMatchingScalarLoads() throws {
        for compressed in [false, true] {
            let key = try keys.generateKey("k", compressed: compressed)
            let json = fileJSON(type: "secp256k1", pub: key.key.publicKey, prv: key.key.privateKey)
            XCTAssertEqual(try decode(json).publicKey, key.publicKey)
        }
    }

    func testSecp256k1OffCurvePublicKeyIsRejectedOnLoad() throws {
        let key = try keys.generateKey("k")
        var pub = try Secp256k1.fromHex(key.publicKey, "public")
        pub[64] ^= 1
        let json = fileJSON(type: "secp256k1", pub: Secp256k1.toHex(pub), prv: key.key.privateKey)
        XCTAssertThrowsError(try decode(json))
    }

    func testMLDSAMismatchedPairIsRejected() throws {
        let a = try keys.generateKey("a", type: .mlDsa65)
        let b = try keys.generateKey("b", type: .mlDsa65)
        assertMismatchRejected(.mlDsa65, a, b, "ml-dsa-65")
    }

    func testMLDSAPairLoadsAndWrongSizeIsRejected() throws {
        let key = try keys.generateKey("a", type: .mlDsa65)
        let good = fileJSON(type: "ml-dsa-65", pub: key.key.publicKey, prv: key.key.privateKey)
        XCTAssertEqual(try decode(good).key, key.key)
        let short = fileJSON(type: "ml-dsa-65", pub: "AAAA", prv: key.key.privateKey)
        XCTAssertThrowsError(try decode(short))
    }
}
