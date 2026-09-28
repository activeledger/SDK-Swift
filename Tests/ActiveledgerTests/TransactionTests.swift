import XCTest
@testable import Activeledger

final class TransactionTests: XCTestCase {
    private let keys = KeyHandler()
    private let handler = TransactionHandler()
    private let crypto = DefaultCryptoProvider()

    func testBuildOnboardKeyTxShapeAndSignature() throws {
        let key = try keys.generateKey("me")
        let tx = try handler.buildOnboardKeyTx(key)

        // $tx is signed in exactly this field order.
        let expected = try canonicalJSON(.object([
            ("$contract", .string("onboard")),
            ("$i", .object([("me", .object([
                ("publicKey", .string(key.publicKey)),
                ("type", .string("secp256k1")),
            ]))])),
            ("$namespace", .string("default")),
        ]))
        XCTAssertEqual(tx.signedString, expected)
        XCTAssertEqual(tx.selfsign, true)

        // Self-signed: the signature is keyed by the $i label, not an identity.
        XCTAssertEqual(tx.sigs.count, 1)
        XCTAssertEqual(tx.sigs.first?.0, "me")
        let sig = try XCTUnwrap(tx.sigs.first?.1)
        XCTAssertTrue(crypto.verify(tx.signedString, signature: sig, publicKey: key.publicKey,
                                    type: .secp256k1))

        // Envelope carries $selfsign, $sigs and $tx.
        let env = try canonicalJSON(tx.toJSONValue())
        XCTAssertTrue(env.contains("\"$selfsign\":true"))
        XCTAssertTrue(env.contains("\"$sigs\""))
        XCTAssertTrue(env.contains("\"$tx\""))
    }

    func testLabelledTransactionRequiresIdentity() throws {
        let key = try keys.generateKey("me") // no identity
        XCTAssertThrowsError(try handler.labelledTransaction(
            key: key, namespace: "ns", contract: "c", inputLabel: "in", stream: "s"))
    }

    func testLabelledTransactionInputOrdering() throws {
        let key = try keys.generateKey("me")
        key.identity = "streamid"
        let tx = try handler.labelledTransaction(
            key: key, namespace: "ns", contract: "c", inputLabel: "in", stream: "streamid",
            inputData: .object([("amount", .integer(10))]), selfsign: true)
        // inputData first, then $stream, then publicKey/type (selfsign).
        let s = tx.signedString
        let iAmount = try XCTUnwrap(s.range(of: "\"amount\""))
        let iStream = try XCTUnwrap(s.range(of: "\"$stream\""))
        let iType = try XCTUnwrap(s.range(of: "\"type\""))
        XCTAssertTrue(iAmount.lowerBound < iStream.lowerBound)
        XCTAssertTrue(iStream.lowerBound < iType.lowerBound)
        XCTAssertEqual(tx.sigs.first?.0, "in") // keyed by label when selfsign
    }

    func testSignTransactionKeyedByIdentityWhenNotSelfSign() throws {
        let key = try keys.generateKey("me")
        key.identity = "id123"
        let tx = Transaction(tx: .object([("$contract", .string("c"))]))
        try handler.signTransaction(tx, key: key)
        XCTAssertEqual(tx.sigs.first?.0, "id123")
        XCTAssertTrue(crypto.verify(tx.signedString, signature: tx.sigs.first!.1,
                                    publicKey: key.publicKey, type: .secp256k1))
    }
}
