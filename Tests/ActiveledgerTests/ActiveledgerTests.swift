import XCTest
@testable import Activeledger

final class ActiveledgerTests: XCTestCase {
    func testVersionIsSet() {
        XCTAssertFalse(Activeledger.version.isEmpty)
    }

    func testInitFromUrlWiresHandlers() throws {
        let ledger = try Activeledger("http://localhost:5260")
        XCTAssertEqual(ledger.connection.baseURL.absoluteString, "http://localhost:5260")
    }

    func testInitFromComponents() throws {
        let ledger = try Activeledger("https", "example.com", 443)
        XCTAssertEqual(ledger.connection.baseURL.absoluteString, "https://example.com:443")
    }

    func testInitRejectsNonHttpUrl() {
        XCTAssertThrowsError(try Activeledger("ftp://localhost:5260"))
    }

    func testGenerateKeyShorthandMatchesHandler() throws {
        let ledger = try Activeledger("http://localhost:5260")
        let key = try ledger.generateKey("me")
        XCTAssertEqual(key.name, "me")
        XCTAssertEqual(key.type, .secp256k1)
        // The shorthand and the handler produce equivalent keys (both valid,
        // signable via the same payload handler).
        let order: JSONValue = .object([("hello", .string("world"))])
        let sig = try ledger.payloads.sign(order, key: key)
        XCTAssertTrue(ledger.payloads.verify(order, signature: sig,
                                             publicKey: key.publicKey, type: .secp256k1))
    }
}
