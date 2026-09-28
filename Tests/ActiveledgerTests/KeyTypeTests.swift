import XCTest
@testable import Activeledger

final class KeyTypeTests: XCTestCase {
    func testWireStrings() {
        XCTAssertEqual(KeyType.secp256k1.wire, "secp256k1")
        XCTAssertEqual(KeyType.mlDsa65.wire, "ml-dsa-65")
        XCTAssertEqual(KeyType.falcon512.wire, "falcon-512")
        XCTAssertEqual(KeyType.rsa.wire, "rsa")
    }

    func testFromWire() throws {
        XCTAssertEqual(try KeyType.fromWire("ml-dsa-65"), .mlDsa65)
        XCTAssertEqual(try KeyType.fromWire("bitcoin"), .secp256k1)
        XCTAssertEqual(try KeyType.fromWire("ethereum"), .secp256k1)
    }

    func testFromWireIsStrict() {
        XCTAssertThrowsError(try KeyType.fromWire("ML-DSA-65"))
        XCTAssertThrowsError(try KeyType.fromWire("nonsense"))
    }

    func testIsPostQuantum() {
        XCTAssertTrue(KeyType.mlDsa65.isPostQuantum)
        XCTAssertTrue(KeyType.falcon512.isPostQuantum)
        XCTAssertFalse(KeyType.secp256k1.isPostQuantum)
        XCTAssertFalse(KeyType.rsa.isPostQuantum)
    }

    func testPreferredPostQuantumDefaultsToMLDSA() {
        // With no Falcon scheme registered (core only), preferred is ML-DSA-65.
        XCTAssertEqual(KeyType.preferredPostQuantum, .mlDsa65)
        XCTAssertFalse(PostQuantum.isAvailable(.falcon512))
    }
}
