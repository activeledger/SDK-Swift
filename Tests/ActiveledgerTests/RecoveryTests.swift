import XCTest
@testable import Activeledger

private struct PhraseVector: Codable {
    let type: String
    let phraseName: String
    let phrase: String
    let passphrase: String?
    let bip39Seed: String
    let derivedSeed: String
    let scheme: String?
}
private struct SeedVector: Codable {
    let type: String
    let seedName: String
    let seed: String
    let valid: Bool
    let publicKey: String?
}
private struct SeedFile: Codable {
    let seedVectors: [SeedVector]
    let phraseVectors: [PhraseVector]
}

final class RecoveryTests: XCTestCase {
    private func file() throws -> SeedFile {
        let url = Vectors.directory.appendingPathComponent("seed-vectors.json")
        return try JSONDecoder().decode(SeedFile.self, from: Data(contentsOf: url))
    }

    private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

    func testPhraseVectors() throws {
        let vs = try file().phraseVectors
        XCTAssertFalse(vs.isEmpty)
        for v in vs {
            // The legacy scheme is SHA256(phrase) used directly as the seed -
            // recovery only, no BIP-39 seed step.
            if v.scheme == "legacy" {
                XCTAssertEqual(hex(Recovery.legacySeed(v.phrase)), v.derivedSeed,
                               "\(v.type)/\(v.phraseName): legacy seed")
                continue
            }
            let type = try KeyType.fromWire(v.type)
            let seed = try Recovery.toSeed(v.phrase, passphrase: v.passphrase ?? "")
            XCTAssertEqual(hex(seed), v.bip39Seed, "\(v.type)/\(v.phraseName): BIP-39 seed")
            let derived = try Recovery.deriveSeed(type, bip39Seed: seed)
            XCTAssertEqual(hex(derived), v.derivedSeed, "\(v.type)/\(v.phraseName): derived seed")
        }
    }

    func testSecp256k1SeedVectors() throws {
        for v in try file().seedVectors where v.type == "secp256k1" {
            let seed = try Secp256k1.fromHex("0x" + v.seed, "seed")
            if v.valid {
                XCTAssertTrue(Secp256k1.isValidScalar(seed), "\(v.seedName): valid scalar")
                if let pk = v.publicKey {
                    let compressed = pk.dropFirst(2).count == 66
                    let (pub, _) = try Secp256k1.keyPair(fromScalar: seed, compressed: compressed)
                    XCTAssertEqual(Secp256k1.toHex(pub), pk, "\(v.seedName): derived public key")
                }
            } else {
                XCTAssertFalse(Secp256k1.isValidScalar(seed), "\(v.seedName): invalid scalar rejected")
            }
        }
    }

    func testValidateAcceptsAKnownPhrase() throws {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        XCTAssertEqual(try Recovery.validate(phrase), phrase)
    }

    func testValidateRejectsBadChecksum() {
        let bad = String(repeating: "abandon ", count: 12).trimmingCharacters(in: .whitespaces)
        XCTAssertThrowsError(try Recovery.validate(bad))
    }

    func testValidateRejectsUnknownWord() {
        let bad = "zzzz " + String(repeating: "abandon ", count: 11).trimmingCharacters(in: .whitespaces)
        XCTAssertThrowsError(try Recovery.validate(bad))
    }

    func testGeneratedMnemonicValidates() throws {
        for strength in [128, 160, 192, 224, 256] {
            let m = try Recovery.generateMnemonic(strength: strength)
            XCTAssertNoThrow(try Recovery.validate(m), "generated \(strength)-bit mnemonic validates")
            XCTAssertEqual(m.split(separator: " ").count, 12 + (strength - 128) / 32 * 3)
        }
    }

    func testDeriveSeedRejectsWrongLength() {
        XCTAssertThrowsError(try Recovery.deriveSeed(.mlDsa65, bip39Seed: [UInt8](repeating: 0, count: 32)))
    }
}
