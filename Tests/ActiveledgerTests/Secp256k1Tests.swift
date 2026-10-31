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

    // MARK: public key validation

    private static let gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    private static let gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    private static let p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    private static let zeros = String(repeating: "0", count: 64)

    private func bytes(_ hex: String) throws -> [UInt8] {
        try Secp256k1.fromHex("0x" + hex, "public")
    }

    private func isRejected(_ hex: String) throws -> Bool {
        let key = try bytes(hex)
        var failed = false
        do { _ = try Secp256k1.parsePublicKey(key) } catch { failed = true }
        // verify must refuse it too, whatever the signature.
        let signature = try Secp256k1.sign(Data("m".utf8), privateScalar: [UInt8](repeating: 7, count: 32))
        let verified = Secp256k1.verify(Data("m".utf8), der: signature, publicKey: key)
        return failed && !verified
    }

    func testGeneratorIsAcceptedInBothForms() throws {
        _ = try Secp256k1.parsePublicKey(bytes("04" + Self.gx + Self.gy))
        _ = try Secp256k1.parsePublicKey(bytes("02" + Self.gx))
    }

    func testUncompressedPointNotOnCurveIsRejected() throws {
        let yPlusOne = String(Self.gy.dropLast()) + "9"
        XCTAssertTrue(try isRejected("04" + Self.gx + yPlusOne))
        XCTAssertTrue(try isRejected("04" + Self.gx + Self.gx))
    }

    func testCompressedXWithNoCurvePointIsRejected() throws {
        // x = 5 has no y on secp256k1 (x^3 + 7 = 132 is not a square mod p).
        let five = String(repeating: "0", count: 63) + "5"
        XCTAssertTrue(try isRejected("02" + five))
        XCTAssertTrue(try isRejected("03" + five))
    }

    func testCoordinateAtOrAbovePIsRejected() throws {
        let over = String(repeating: "f", count: 64)
        XCTAssertTrue(try isRejected("04" + Self.p + Self.gy))
        XCTAssertTrue(try isRejected("04" + Self.gx + Self.p))
        XCTAssertTrue(try isRejected("04" + over + over))
        XCTAssertTrue(try isRejected("02" + Self.p))
        XCTAssertTrue(try isRejected("03" + over))
    }

    func testInfinityAndAllZeroEncodingsAreRejected() throws {
        XCTAssertTrue(try isRejected("00"))
        XCTAssertTrue(try isRejected("00" + Self.zeros))
        XCTAssertTrue(try isRejected("04" + Self.zeros + Self.zeros))
        XCTAssertTrue(try isRejected("02" + Self.zeros))
        XCTAssertTrue(try isRejected("03" + Self.zeros))
        XCTAssertTrue(try isRejected(Self.zeros))
    }

    func testWrongPrefixOrLengthIsRejected() throws {
        XCTAssertTrue(try isRejected("06" + Self.gx + Self.gy))
        XCTAssertTrue(try isRejected("07" + Self.gx + Self.gy))
        XCTAssertTrue(try isRejected("05" + Self.gx))
        XCTAssertTrue(try isRejected("04" + Self.gx))
        XCTAssertTrue(try isRejected(""))
    }

    func testRejectionNamesTheProblem() throws {
        let yPlusOne = String(Self.gy.dropLast()) + "9"
        XCTAssertThrowsError(try Secp256k1.parsePublicKey(bytes("04" + Self.gx + yPlusOne))) { error in
            XCTAssertTrue("\(error)".contains("not a point on the curve"), "\(error)")
        }
    }

    func testToHexIsPrefixedLowercase() {
        XCTAssertEqual(Secp256k1.toHex([]), "0x")
        XCTAssertEqual(Secp256k1.toHex([0x00, 0x0f, 0xa0, 0xff]), "0x000fa0ff")
    }
}
