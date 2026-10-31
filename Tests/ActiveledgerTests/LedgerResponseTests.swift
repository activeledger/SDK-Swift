import XCTest
@testable import Activeledger

final class LedgerResponseTests: XCTestCase {
    private func response(_ json: String) throws -> LedgerResponse {
        let obj = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
        return LedgerResponse(raw: obj)
    }

    func testParsesACommittedOnboardResponse() throws {
        let r = try response(#"""
        {"$umid":"abc123",
         "$summary":{"total":3,"vote":3,"commit":3,"errors":[]},
         "$streams":{"new":[{"id":"stream1","name":"me"}],"updated":[{"id":"stream2"}]},
         "$responses":["hello", 7]}
        """#)
        XCTAssertEqual(r.umid, "abc123")
        XCTAssertEqual(r.total, 3)
        XCTAssertEqual(r.vote, 3)
        XCTAssertEqual(r.commit, 3)
        XCTAssertTrue(r.errors.isEmpty)
        XCTAssertTrue(r.committed)
        XCTAssertEqual(r.created, [StreamRef(id: "stream1", name: "me")])
        XCTAssertEqual(r.updated, [StreamRef(id: "stream2", name: nil)])
        XCTAssertEqual(r.streams.created, r.created)
        XCTAssertEqual(r.streams.updated, r.updated)
        XCTAssertEqual(r.responses.count, 2)
        XCTAssertEqual(r.responses.first as? String, "hello")
    }

    // A rejected transaction is HTTP 200; only the summary says so.
    func testErrorsMeanNotCommittedEvenWithCommitVotes() throws {
        let r = try response(#"""
        {"$summary":{"total":3,"vote":3,"commit":3,"errors":["Signature Incorrect", 1220]}}
        """#)
        XCTAssertEqual(r.errors, ["Signature Incorrect", "1220"])
        XCTAssertFalse(r.committed)
    }

    // The rule does not look at the commit count, only at the errors.
    func testCommitCountIsNotRequired() throws {
        let r = try response(#"{"$summary":{"total":3,"vote":3,"commit":0,"errors":[]}}"#)
        XCTAssertEqual(r.commit, 0)
        XCTAssertTrue(r.committed)
    }

    func testEmptyObjectIsNotCommitted() throws {
        let r = try response("{}")
        XCTAssertFalse(r.committed)
        XCTAssertEqual(r.errors.count, 1)
        XCTAssertTrue(r.errors[0].contains("$summary"), "\(r.errors)")
    }

    func testObjectWithoutSummaryIsNotCommitted() throws {
        let r = try response(#"{"$umid":"u","$streams":{"new":[{"id":"s"}]}}"#)
        XCTAssertFalse(r.committed)
        XCTAssertFalse(r.errors.isEmpty)
    }

    func testNonObjectSummaryIsNotCommitted() throws {
        for json in [#"{"$summary":"ok"}"#, #"{"$summary":[]}"#, #"{"$summary":null}"#] {
            let r = try response(json)
            XCTAssertFalse(r.committed, json)
            XCTAssertFalse(r.errors.isEmpty, json)
        }
    }

    func testSummaryWithoutErrorsKeyIsCommitted() throws {
        XCTAssertTrue(try response(#"{"$summary":{}}"#).committed)
        XCTAssertTrue(try response(#"{"$summary":{"errors":null}}"#).committed)
    }

    func testNonListErrorsIsNotCommitted() throws {
        let r = try response(#"{"$summary":{"errors":"boom"}}"#)
        XCTAssertFalse(r.committed)
        XCTAssertFalse(r.errors.isEmpty)
    }

    func testMissingCommitWithNoErrorsCountsAsCommitted() throws {
        let r = try response(#"{"$summary":{"total":1}}"#)
        XCTAssertNil(r.commit)
        XCTAssertTrue(r.committed)
    }

    func testEmptyResponseYieldsEmptyAccessors() throws {
        let r = try response("{}")
        XCTAssertNil(r.umid)
        XCTAssertNil(r.total)
        XCTAssertNil(r.vote)
        XCTAssertNil(r.commit)
        XCTAssertTrue(r.created.isEmpty)
        XCTAssertTrue(r.updated.isEmpty)
        XCTAssertTrue(r.responses.isEmpty)
    }

    func testStreamRefsWithoutAnIdAreDropped() throws {
        let r = try response(#"""
        {"$streams":{"new":[{"name":"orphan"},{"id":"keep"},"junk",{"id":5}]}}
        """#)
        XCTAssertEqual(r.created, [StreamRef(id: "keep", name: nil)])
    }

    func testWrongTypedSectionsAreIgnored() throws {
        let r = try response(#"""
        {"$umid":5,"$summary":"bad","$streams":[],"$responses":{}}
        """#)
        XCTAssertNil(r.umid)
        XCTAssertNil(r.commit)
        XCTAssertFalse(r.committed)
        XCTAssertTrue(r.created.isEmpty)
        XCTAssertTrue(r.responses.isEmpty)
    }
}
