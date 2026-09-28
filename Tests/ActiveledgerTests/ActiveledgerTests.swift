import XCTest
@testable import Activeledger

final class ActiveledgerTests: XCTestCase {
    func testVersionIsSet() {
        XCTAssertFalse(Activeledger.version.isEmpty)
    }
}
