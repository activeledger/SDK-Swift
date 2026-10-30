import XCTest
@testable import Activeledger

final class CryptoProviderBoundaryTests: XCTestCase {
    private let crypto = DefaultCryptoProvider()

    private func secp() throws -> KeyMaterial { try crypto.generate(type: .secp256k1, compressed: false) }

    func testGenerateSecpKeyShapes() throws {
        let u = try crypto.generate(type: .secp256k1, compressed: false)
        XCTAssertTrue(u.publicKey.hasPrefix("0x04"))
        XCTAssertEqual(u.publicKey.count, 2 + 130)
        XCTAssertEqual(u.privateKey.count, 2 + 64)
        let c = try crypto.generate(type: .secp256k1, compressed: true)
        XCTAssertEqual(c.publicKey.count, 2 + 66)
    }

    func testGenerateMLDSAKeySizes() throws {
        let m = try crypto.generate(type: .mlDsa65, compressed: true) // compressed is ignored
        XCTAssertEqual(Data(base64Encoded: m.publicKey)?.count, 1952)
        XCTAssertEqual(Data(base64Encoded: m.privateKey)?.count, 4032)
    }

    func testSecpSignaturesAreDeterministicAndKeyed() throws {
        let k = try secp()
        let s1 = try crypto.sign("msg", privateKey: k.privateKey, type: .secp256k1)
        XCTAssertEqual(s1, try crypto.sign("msg", privateKey: k.privateKey, type: .secp256k1))
        XCTAssertNotEqual(s1, try crypto.sign("msh", privateKey: k.privateKey, type: .secp256k1))
    }

    func testVerifyIsFalseForWrongKeyWrongTypeAndGarbageSignature() throws {
        let k = try secp(), other = try secp()
        let sig = try crypto.sign("msg", privateKey: k.privateKey, type: .secp256k1)
        XCTAssertTrue(crypto.verify("msg", signature: sig, publicKey: k.publicKey, type: .secp256k1))
        XCTAssertFalse(crypto.verify("msg", signature: sig, publicKey: other.publicKey, type: .secp256k1))
        XCTAssertFalse(crypto.verify("msg", signature: "!!not base64!!", publicKey: k.publicKey, type: .secp256k1))
        XCTAssertFalse(crypto.verify("msg", signature: "AAAA", publicKey: k.publicKey, type: .secp256k1))
        XCTAssertFalse(crypto.verify("msg", signature: sig, publicKey: "0xzz", type: .secp256k1))
        XCTAssertFalse(crypto.verify("msg", signature: sig, publicKey: k.publicKey, type: .rsa),
                       "rsa with a non-PEM key never verifies")
        XCTAssertFalse(crypto.verify("msg", signature: sig, publicKey: k.publicKey, type: .mlDsa65),
                       "a secp256k1 key is not a valid ML-DSA key")
    }

    func testSecpSignRejectsMalformedPrivateKeys() {
        for bad in ["", "0x", "0x1234", "nothex", "0x" + String(repeating: "00", count: 32)] {
            XCTAssertThrowsError(try crypto.sign("m", privateKey: bad, type: .secp256k1), "\(bad)")
        }
    }

    func testRSAWithoutPEMIsRefused() {
        XCTAssertThrowsError(try crypto.sign("m", privateKey: "0x01", type: .rsa)) { error in
            guard case ActiveledgerError.invalidArgument = error else {
                return XCTFail("expected invalidArgument, got \(error)")
            }
        }
    }

    // Post-quantum keys are base64 of raw bytes; hex and short keys are rejected before the scheme runs.
    func testMLDSASignRejectsHexAndWrongLengthKeys() {
        XCTAssertThrowsError(try crypto.sign("m", privateKey: "0xabcd", type: .mlDsa65)) { error in
            guard case ActiveledgerError.invalidArgument(let m) = error else {
                return XCTFail("expected invalidArgument, got \(error)")
            }
            XCTAssertTrue(m.contains("hex"))
        }
        XCTAssertThrowsError(try crypto.sign("m", privateKey: "***", type: .mlDsa65))
        XCTAssertThrowsError(try crypto.sign("m", privateKey: Data(count: 10).base64EncodedString(),
                                            type: .mlDsa65))
    }

    func testMLDSARoundTripAndTamperDetection() throws {
        let k = try crypto.generate(type: .mlDsa65, compressed: false)
        let sig = try crypto.sign("payload", privateKey: k.privateKey, type: .mlDsa65)
        XCTAssertEqual(Data(base64Encoded: sig)?.count, 3309)
        XCTAssertTrue(crypto.verify("payload", signature: sig, publicKey: k.publicKey, type: .mlDsa65))
        XCTAssertFalse(crypto.verify("payloaD", signature: sig, publicKey: k.publicKey, type: .mlDsa65))
        var bytes = [UInt8](try XCTUnwrap(Data(base64Encoded: sig)))
        bytes[100] ^= 0x01
        XCTAssertFalse(crypto.verify("payload", signature: Data(bytes).base64EncodedString(),
                                     publicKey: k.publicKey, type: .mlDsa65))
        XCTAssertFalse(crypto.verify("payload", signature: sig, publicKey: "0xabcd", type: .mlDsa65))
        XCTAssertFalse(crypto.verify("payload", signature: sig, publicKey: "###", type: .mlDsa65))
    }

    func testGenerateFromSeedRefusesRSA() {
        XCTAssertThrowsError(try crypto.generateFromSeed([UInt8](repeating: 1, count: 32),
                                                         type: .rsa, compressed: false))
    }

    func testProviderDefaultArgumentsMeanSecp256k1() throws {
        let k = try crypto.generate()
        XCTAssertTrue(k.publicKey.hasPrefix("0x"))
        let sig = try crypto.sign("m", privateKey: k.privateKey)
        XCTAssertTrue(crypto.verify("m", signature: sig, publicKey: k.publicKey))
    }
}
