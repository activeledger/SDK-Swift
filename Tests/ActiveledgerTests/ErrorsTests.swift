import XCTest
@testable import Activeledger

final class ErrorsTests: XCTestCase {
    func testDescriptions() {
        XCTAssertEqual(ActiveledgerError.invalidArgument("bad").description,
                       "ActiveledgerError.invalidArgument: bad")
        XCTAssertEqual(ActiveledgerError.keyTypeUnavailable("nope").description,
                       "ActiveledgerError.keyTypeUnavailable: nope")
        XCTAssertEqual(ActiveledgerError.http(statusCode: 502, body: "gateway").description,
                       "ActiveledgerError.http: HTTP 502: gateway")
        XCTAssertEqual(ActiveledgerError.onboard(message: "none").description,
                       "ActiveledgerError.onboard: none")
        XCTAssertEqual(ActiveledgerError.ledger("oops").description,
                       "ActiveledgerError.ledger: oops")
    }

    func testEquatableDistinguishesCasesAndPayloads() {
        XCTAssertEqual(ActiveledgerError.http(statusCode: 500, body: "x"),
                       ActiveledgerError.http(statusCode: 500, body: "x"))
        XCTAssertNotEqual(ActiveledgerError.http(statusCode: 500, body: "x"),
                          ActiveledgerError.http(statusCode: 501, body: "x"))
        XCTAssertNotEqual(ActiveledgerError.ledger("a"), ActiveledgerError.invalidArgument("a"))
    }

    // Both the registry and the provider surface the same typed error, not a crash.
    func testUnregisteredKeyTypeThrowsKeyTypeUnavailable() {
        for type in [KeyType.secp256k1, .rsa] {
            XCTAssertThrowsError(try PostQuantum.scheme(for: type)) { error in
                guard case ActiveledgerError.keyTypeUnavailable(let m) = error else {
                    return XCTFail("expected keyTypeUnavailable, got \(error)")
                }
                XCTAssertTrue(m.contains(type.wire))
                XCTAssertFalse(m.contains("ActiveledgerFalcon"), "Falcon hint only for falcon-512")
            }
        }
    }
}
