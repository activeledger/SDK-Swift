import XCTest
@testable import Activeledger

// Error paths and edge inputs found by a coverage sweep: strict DER decoding,
// the canonical JSON nesting limit and control-character escapes, seed and
// mnemonic arguments, the ML-DSA private key length, and the Activeledger
// facade's onboard and send over a loopback socket.
final class EdgeInputTests: XCTestCase {

    // MARK: DER

    private func assertDERRefused(_ bytes: [UInt8], _ why: String,
                                  file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try DER.decodeSignature(bytes), why, file: file, line: line)
    }

    func testDERDecodesTheSmallestSignature() throws {
        let (r, s) = try DER.decodeSignature([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        XCTAssertEqual(r, [1])
        XCTAssertEqual(s, [2])
    }

    func testDERRefusesMalformedSignatures() {
        assertDERRefused([], "empty")
        assertDERRefused([0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], "not a SEQUENCE")
        assertDERRefused([0x30], "no length")
        assertDERRefused([0x30, 0x80], "indefinite length")
        assertDERRefused([0x30, 0x83, 0x00, 0x00, 0x06], "three-byte length")
        assertDERRefused([0x30, 0x81], "long form with no length byte")
        assertDERRefused([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00], "trailing byte")
        assertDERRefused([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], "sequence longer than its bytes")
        assertDERRefused([0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x02], "r is not an INTEGER")
        assertDERRefused([0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x02], "s is not an INTEGER")
        assertDERRefused([0x30, 0x04, 0x02, 0x00, 0x02, 0x00], "zero-length INTEGER")
        assertDERRefused([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x02], "negative r")
        assertDERRefused([0x30, 0x06, 0x02, 0x05, 0x01, 0x02, 0x01, 0x02], "INTEGER longer than the sequence")
        assertDERRefused([0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03], "third component")
        assertDERRefused([0x30, 0x03, 0x02, 0x01, 0x01], "only one component")
    }

    func testDERLongFormLengthsRoundTrip() throws {
        // 200-byte magnitudes: each INTEGER needs a 0x81 length (r also a sign
        // byte), and the sequence needs a 0x82 length.
        let r = [UInt8](repeating: 0xfe, count: 200)
        let s = [UInt8](repeating: 0x7f, count: 200)
        let der = DER.encodeSignature(r: r, s: s)
        XCTAssertEqual(Array(der.prefix(4)), [0x30, 0x82, 0x01, 0x97])
        let decoded = try DER.decodeSignature(der)
        XCTAssertEqual(decoded.r, r)
        XCTAssertEqual(decoded.s, s)

        // A 144-byte body is the 0x81 form.
        let mid = DER.encodeSignature(r: [UInt8](repeating: 0x11, count: 70),
                                      s: [UInt8](repeating: 0x22, count: 70))
        XCTAssertEqual(Array(mid.prefix(2)), [0x30, 0x81])
        XCTAssertEqual(try DER.decodeSignature(mid).s, [UInt8](repeating: 0x22, count: 70))
    }

    // MARK: canonical JSON

    func testNestingBeyondTheLimitIsRefusedNotOverflowed() throws {
        var deep = JSONValue.integer(1)
        for _ in 0..<600 { deep = .array([deep]) }
        XCTAssertThrowsError(try canonicalJSON(deep))

        var fine = JSONValue.integer(1)
        for _ in 0..<100 { fine = .array([fine]) }
        XCTAssertNoThrow(try canonicalJSON(fine))
    }

    func testControlCharactersWithoutAShortEscapeUseLowercaseUnicodeEscapes() throws {
        XCTAssertEqual(try canonicalJSON(.string("\u{01}")), #""\u0001""#)
        XCTAssertEqual(try canonicalJSON(.string("\u{1f}")), #""\u001f""#)
        XCTAssertEqual(try canonicalJSON(.string("a\u{0b}b")), #""a\u000bb""#)
        // DEL and U+2028 pass through as JSON.stringify leaves them.
        XCTAssertEqual(try canonicalJSON(.string("\u{7f}\u{2028}")), "\"\u{7f}\u{2028}\"")
    }

    func testObjectKeysKeepInsertionOrderAndAreEscaped() throws {
        let value = JSONValue.object([("b", .integer(1)), ("a\"x", .null)])
        XCTAssertEqual(try canonicalJSON(value), #"{"b":1,"a\"x":null}"#)
    }

    // MARK: seeds and mnemonics

    func testSeedSizeIsRefusedForKeyTypesThatCannotBeDerived() throws {
        XCTAssertThrowsError(try Recovery.seedSize(.rsa))
        XCTAssertEqual(try Recovery.seedSize(.secp256k1), 32)
        XCTAssertEqual(try Recovery.seedSize(.falcon512), 48)
    }

    func testMnemonicStrengthMustBeABIP39EntropySize() throws {
        for bad in [0, 96, 127, 129, 255, 288] {
            XCTAssertThrowsError(try Recovery.generateMnemonic(strength: bad), "strength \(bad)")
        }
        XCTAssertEqual(try Recovery.generateMnemonic(strength: 256).split(separator: " ").count, 24)
    }

    func testPhraseOfTheWrongWordCountIsRefused() throws {
        let twelve = try Recovery.generateMnemonic()
        let words = twelve.split(separator: " ").map(String.init)
        XCTAssertNoThrow(try Recovery.validate(twelve))
        for count in [0, 1, 11, 13, 14, 25] {
            let phrase = (0..<count).map { words[$0 % words.count] }.joined(separator: " ")
            XCTAssertThrowsError(try Recovery.validate(phrase), "\(count) words")
        }
    }

    // MARK: ML-DSA

    func testMLDSAPrivateKeyOfTheWrongLengthIsRefusedBySign() throws {
        let scheme = MLDSA65Scheme()
        let pair = try scheme.generateKeyPair(seed: nil)
        let message = Data("hello".utf8)
        let signature = try scheme.sign(message, privateKey: pair.privateKey)
        XCTAssertTrue(scheme.verify(signature, message: message, publicKey: pair.publicKey))

        XCTAssertThrowsError(try scheme.sign(message, privateKey: pair.privateKey.dropLast()))
        XCTAssertThrowsError(try scheme.sign(message, privateKey: Data()))
        XCTAssertThrowsError(try scheme.generateKeyPair(seed: Data(count: 31)))
    }

    // MARK: Activeledger facade

    func testFacadeOnboardSetsTheIdentityAndSendPostsTheTransaction() async throws {
        let committed = """
            {"$umid":"u1","$summary":{"total":1,"vote":1,"commit":1,"errors":[]},\
            "$streams":{"new":[{"id":"stream-abc","name":"me"}],"updated":[]}}
            """
        let server = try LoopbackServer { _ in .init(committed) }
        defer { server.stop() }
        let ledger = try Activeledger(server.url)

        let key = try ledger.generateKey("me")
        let onboarded = try await ledger.onboard(key)
        XCTAssertTrue(onboarded.committed)
        XCTAssertEqual(key.identity, "stream-abc")

        let tx = try ledger.transactions.buildOnboardKeyTx(key)
        let sent = try await ledger.send(tx)
        XCTAssertEqual(sent.umid, "u1")
        XCTAssertEqual(server.requests.count, 2)
        XCTAssertEqual(server.requests[1].bodyString, try canonicalJSON(tx.toJSONValue()))
    }

    func testFacadeRefusesANonHTTPURL() {
        XCTAssertThrowsError(try Activeledger("ftp://node:5260"))
    }
}
