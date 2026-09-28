import XCTest
@testable import Activeledger

final class PayloadTests: XCTestCase {
    private let payloads = PayloadHandler()
    private let keys = KeyHandler()

    func testCanonicalIsOrderSensitive() throws {
        let a: JSONValue = .object([("pair", .string("VNR/USDT")), ("side", .string("sell"))])
        let b: JSONValue = .object([("side", .string("sell")), ("pair", .string("VNR/USDT"))])
        XCTAssertNotEqual(try payloads.canonical(a), try payloads.canonical(b))
        XCTAssertEqual(try payloads.canonical(a), #"{"pair":"VNR/USDT","side":"sell"}"#)
    }

    func testCanonicalPassesStringsThrough() throws {
        XCTAssertEqual(try payloads.canonical(.string("already canonical")), "already canonical")
    }

    func testSignAndVerifyRoundTrip() throws {
        let key = try keys.generateKey("trader")
        let order: JSONValue = .object([("pair", .string("VNR/USDT")), ("side", .string("sell"))])
        let sig = try payloads.sign(order, key: key)
        XCTAssertTrue(payloads.verify(order, signature: sig, publicKey: key.publicKey, type: .secp256k1))
        // A different field order does not verify against the same signature.
        let reordered: JSONValue = .object([("side", .string("sell")), ("pair", .string("VNR/USDT"))])
        XCTAssertFalse(payloads.verify(reordered, signature: sig, publicKey: key.publicKey, type: .secp256k1))
    }

    func testVerifyReturnsFalseOnGarbage() {
        let order: JSONValue = .object([("a", .integer(1))])
        XCTAssertFalse(payloads.verify(order, signature: "!!notbase64!!", publicKey: "0x04", type: .secp256k1))
    }
}
