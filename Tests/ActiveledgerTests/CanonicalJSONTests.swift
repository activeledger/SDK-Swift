import XCTest
@testable import Activeledger

final class CanonicalJSONTests: XCTestCase {

    // MARK: number formatting, against the cross-language vectors

    private struct NumberCase: Codable {
        let name: String
        let value: Double
        let expected: String
    }
    private struct NumberFile: Codable { let vectors: [NumberCase] }

    func testNumberVectors() throws {
        let url = Vectors.directory.appendingPathComponent("number-vectors.json")
        let file = try JSONDecoder().decode(NumberFile.self, from: Data(contentsOf: url))
        XCTAssertFalse(file.vectors.isEmpty)
        for c in file.vectors {
            let got = try jsNumber(c.value)
            XCTAssertEqual(got, c.expected, "number vector '\(c.name)' (value \(c.value))")
        }
    }

    func testJSNumberRefusesNonFinite() {
        XCTAssertThrowsError(try jsNumber(.nan))
        XCTAssertThrowsError(try jsNumber(.infinity))
        XCTAssertThrowsError(try jsNumber(-.infinity))
    }

    // MARK: integers

    func testIntegerFormatting() throws {
        XCTAssertEqual(try jsInteger(0), "0")
        XCTAssertEqual(try jsInteger(1), "1")
        XCTAssertEqual(try jsInteger(-1), "-1")
        XCTAssertEqual(try jsInteger(9_007_199_254_740_991), "9007199254740991")
    }

    func testIntegerBeyondSafeIsRefused() {
        // 2^53 + 1 is not exactly representable as a JS number.
        XCTAssertThrowsError(try jsInteger(9_007_199_254_740_993))
    }

    // MARK: structure and escaping

    func testObjectPreservesOrder() throws {
        let v: JSONValue = .object([
            ("b", .integer(1)),
            ("a", .integer(2)),
        ])
        XCTAssertEqual(try canonicalJSON(v), #"{"b":1,"a":2}"#)
    }

    func testNestedAndTypes() throws {
        let v: JSONValue = .object([
            ("greeting", .string("hello")),
            ("n", .number(1.5)),
            ("flag", .bool(true)),
            ("nothing", .null),
            ("list", .array([.integer(1), .integer(2)])),
        ])
        XCTAssertEqual(
            try canonicalJSON(v),
            #"{"greeting":"hello","n":1.5,"flag":true,"nothing":null,"list":[1,2]}"#)
    }

    func testStringEscaping() throws {
        XCTAssertEqual(try canonicalJSON(.string("a\"b\\c")), #""a\"b\\c""#)
        XCTAssertEqual(try canonicalJSON(.string("line\ntab\t")), #""line\ntab\t""#)
        // control char below 0x20 that has no short form -> \u00XX
        XCTAssertEqual(try canonicalJSON(.string("\u{01}")), #""\u0001""#)
        // non-ASCII passes through as raw UTF-8 (byte-compatible with JS)
        XCTAssertEqual(try canonicalJSON(.string("é")), "\"é\"")
        // astral character (emoji) passes through, not escaped
        XCTAssertEqual(try canonicalJSON(.string("😀")), "\"😀\"")
    }

    func testBytesAreUTF8() throws {
        let bytes = try canonicalJSONBytes(.object([("k", .string("v"))]))
        XCTAssertEqual(bytes, Data(#"{"k":"v"}"#.utf8))
    }
}
