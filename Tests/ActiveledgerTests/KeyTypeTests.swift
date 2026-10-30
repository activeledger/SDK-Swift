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

    // Falcon registration is process-global (ActiveledgerFalcon.enable() in
    // PostQuantumTests), so assert the rule rather than one registry state.
    func testPreferredPostQuantumFollowsFalconAvailability() {
        let expected: KeyType = PostQuantum.isAvailable(.falcon512) ? .falcon512 : .mlDsa65
        XCTAssertEqual(KeyType.preferredPostQuantum, expected)
        XCTAssertTrue(PostQuantum.isAvailable(.mlDsa65))
        XCTAssertTrue(KeyType.preferredPostQuantum.isPostQuantum)
    }
}
