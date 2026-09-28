import XCTest
@testable import Activeledger

private struct PQVector: Codable {
    let type: String
    let messageName: String
    let message: String
    let publicKey: String
    let privateKey: String
    let publicKeyForm: String?
    let signature: String?
    let deterministicSignature: String?
    let highSSignature: String?
}
private struct PQFile: Codable { let vectors: [PQVector] }

final class Secp256k1Tests: XCTestCase {
    private func vectors() throws -> [PQVector] {
        let url = Vectors.directory.appendingPathComponent("pq-vectors.json")
        let file = try JSONDecoder().decode(PQFile.self, from: Data(contentsOf: url))
        return file.vectors.filter { $0.type == "secp256k1" }
    }

    func testVerifiesOpenSSLSignature() throws {
        let vs = try vectors()
        XCTAssertFalse(vs.isEmpty)
        for v in vs {
            let der = [UInt8](Data(base64Encoded: v.signature!)!)
            let pub = try Secp256k1.fromHex(v.publicKey, "public")
            XCTAssertTrue(Secp256k1.verify(Data(v.message.utf8), der: der, publicKey: pub),
                          "\(v.messageName): verify OpenSSL signature")
        }
    }

    func testVerifiesHighSSignature() throws {
        for v in try vectors() {
            let der = [UInt8](Data(base64Encoded: v.highSSignature!)!)
            XCTAssertTrue(Secp256k1.isHighS(der), "\(v.messageName): high-S vector is high-S")
            let pub = try Secp256k1.fromHex(v.publicKey, "public")
            XCTAssertTrue(Secp256k1.verify(Data(v.message.utf8), der: der, publicKey: pub),
                          "\(v.messageName): verify high-S signature")
        }
    }

    func testSignsDeterministicLowS() throws {
        for v in try vectors() {
            let scalar = try Secp256k1.fromHex(v.privateKey, "private")
            let der = try Secp256k1.sign(Data(v.message.utf8), privateScalar: scalar)
            XCTAssertEqual(Data(der).base64EncodedString(), v.deterministicSignature,
                           "\(v.messageName): RFC6979 low-S signature")
            XCTAssertFalse(Secp256k1.isHighS(der), "\(v.messageName): own signature is low-S")
        }
    }

    func testDerivesPublicKey() throws {
        for v in try vectors() {
            let scalar = try Secp256k1.fromHex(v.privateKey, "private")
            let compressed = (v.publicKeyForm ?? "compressed") == "compressed"
            let (pub, priv) = try Secp256k1.keyPair(fromScalar: scalar, compressed: compressed)
            XCTAssertEqual(Secp256k1.toHex(pub), v.publicKey, "\(v.messageName): derived public key")
            XCTAssertEqual(Secp256k1.toHex(priv), v.privateKey, "\(v.messageName): private key preserved")
        }
    }

    func testRejectsTamperedMessage() throws {
        for v in try vectors() {
            let der = [UInt8](Data(base64Encoded: v.signature!)!)
            let pub = try Secp256k1.fromHex(v.publicKey, "public")
            XCTAssertFalse(Secp256k1.verify(Data((v.message + " ").utf8), der: der, publicKey: pub),
                           "\(v.messageName): tampered message rejected")
        }
    }

    func testRejectsScalarZeroAndOrder() {
        XCTAssertFalse(Secp256k1.isValidScalar([UInt8](repeating: 0, count: 32)))
        XCTAssertFalse(Secp256k1.isValidScalar(Secp256k1.order)) // == n
    }
}
