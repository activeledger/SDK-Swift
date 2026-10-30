import XCTest
@testable import Activeledger

// URL validation only; nothing here touches the network.
final class ConnectionTests: XCTestCase {
    func testAcceptsHttpAndHttps() throws {
        XCTAssertEqual(try Connection(url: "http://node:5260").baseURL.absoluteString, "http://node:5260")
        XCTAssertEqual(try Connection(url: "https://node").baseURL.absoluteString, "https://node")
    }

    func testRejectsOtherSchemesAndGarbage() {
        for bad in ["ftp://node:5260", "ws://node", "node:5260", "localhost", "", "file:///tmp/x"] {
            XCTAssertThrowsError(try Connection(url: bad), "\(bad) must be refused") { error in
                guard case ActiveledgerError.invalidArgument = error else {
                    return XCTFail("expected invalidArgument for \(bad), got \(error)")
                }
            }
        }
    }

    func testComponentInitBuildsTheURL() throws {
        let c = try Connection("http", "10.0.0.1", 5260)
        XCTAssertEqual(c.baseURL.absoluteString, "http://10.0.0.1:5260")
        XCTAssertThrowsError(try Connection("gopher", "10.0.0.1", 70))
    }
}
