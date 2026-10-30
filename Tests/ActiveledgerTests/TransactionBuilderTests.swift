import XCTest
@testable import Activeledger

final class TransactionBuilderTests: XCTestCase {
    private let keys = KeyHandler()
    private let handler = TransactionHandler()
    private let crypto = DefaultCryptoProvider()

    private func onboarded(_ type: KeyType = .secp256k1) throws -> Key {
        let key = try keys.generateKey("me", type: type)
        key.identity = "streamid"
        return key
    }

    func testLabelledTransactionExactSignedStringWithAllOptions() throws {
        let key = try onboarded()
        let tx = try handler.labelledTransaction(
            key: key, namespace: "ns", contract: "c", inputLabel: "in", stream: "streamid",
            inputData: .object([("amount", .integer(10))]), entry: "transfer",
            outputs: .object([("out", .string("x"))]), readonly: .object([("ro", .string("y"))]))
        let expected = #"{"$contract":"c","$i":{"in":{"amount":10,"$stream":"streamid"}},"#
            + #""$namespace":"ns","$entry":"transfer","$o":{"out":"x"},"$r":{"ro":"y"}}"#
        XCTAssertEqual(tx.signedString, expected)
        XCTAssertNil(tx.selfsign)
        // Not self-signed: keyed by identity, and the input carries no key material.
        XCTAssertEqual(tx.sigs.map(\.0), ["streamid"])
        XCTAssertFalse(tx.signedString.contains(key.publicKey))
    }

    func testLabelledTransactionSelfsignAddsKeyMaterialAndSignsVerifiably() throws {
        let key = try onboarded()
        let tx = try handler.labelledTransaction(
            key: key, namespace: "ns", contract: "c", inputLabel: "in", stream: "streamid",
            selfsign: true)
        let expected = #"{"$contract":"c","$i":{"in":{"$stream":"streamid","publicKey":""#
            + key.publicKey + #"","type":"secp256k1"}},"$namespace":"ns"}"#
        XCTAssertEqual(tx.signedString, expected)
        XCTAssertEqual(tx.selfsign, true)
        XCTAssertTrue(crypto.verify(expected, signature: try XCTUnwrap(tx.sigs.first?.1),
                                    publicKey: key.publicKey, type: .secp256k1))
    }

    func testLabelledTransactionRejectsNonObjectInputData() throws {
        let key = try onboarded()
        for bad: JSONValue in [.string("x"), .array([]), .null, .integer(1)] {
            XCTAssertThrowsError(try handler.labelledTransaction(
                key: key, namespace: "ns", contract: "c", inputLabel: "in", stream: "s",
                inputData: bad)) { error in
                guard case ActiveledgerError.invalidArgument = error else {
                    return XCTFail("expected invalidArgument, got \(error)")
                }
            }
        }
    }

    func testLabelledTransactionSignsWithPostQuantumKey() throws {
        let key = try onboarded(.mlDsa65)
        let tx = try handler.labelledTransaction(
            key: key, namespace: "ns", contract: "c", inputLabel: "in", stream: "streamid")
        let sig = try XCTUnwrap(tx.sigs.first?.1)
        XCTAssertEqual(Data(base64Encoded: sig)?.count, 3309)
        XCTAssertTrue(crypto.verify(tx.signedString, signature: sig, publicKey: key.publicKey,
                                    type: .mlDsa65))
        XCTAssertFalse(crypto.verify(tx.signedString + " ", signature: sig,
                                     publicKey: key.publicKey, type: .mlDsa65))
    }

    func testSignTransactionFallsBackToKeyNameWithoutIdentity() throws {
        let key = try keys.generateKey("fallback")
        let tx = Transaction(tx: .object([("$contract", .string("c"))]))
        try handler.signTransaction(tx, key: key)
        XCTAssertEqual(tx.sigs.map(\.0), ["fallback"])
    }

    func testSelfSignLabelWinsOverIdentity() throws {
        let key = try onboarded()
        let tx = Transaction(tx: .object([("$contract", .string("c"))]))
        try handler.signTransaction(tx, key: key, selfSignLabel: "label")
        XCTAssertEqual(tx.sigs.map(\.0), ["label"])
    }

    // Editing $tx after signing invalidates the signature; signing again replaces it.
    func testResigningAfterEditReplacesTheSignature() throws {
        let key = try onboarded()
        let tx = Transaction(tx: .object([("$contract", .string("a"))]))
        try handler.signTransaction(tx, key: key)
        let first = try XCTUnwrap(tx.sigs.first?.1)

        tx.tx = .object([("$contract", .string("b"))])
        XCTAssertFalse(crypto.verify(tx.signedString, signature: first, publicKey: key.publicKey,
                                     type: .secp256k1))
        try handler.signTransaction(tx, key: key)
        XCTAssertEqual(tx.sigs.count, 1)
        XCTAssertNotEqual(tx.sigs[0].1, first)
        XCTAssertTrue(crypto.verify(tx.signedString, signature: tx.sigs[0].1,
                                    publicKey: key.publicKey, type: .secp256k1))
    }

    func testSetSignatureReplacesInPlaceAndPreservesOrder() {
        let tx = Transaction(tx: .object([]))
        tx.setSignature("s1", for: "a")
        tx.setSignature("s2", for: "b")
        tx.setSignature("s3", for: "a")
        XCTAssertEqual(tx.sigs.map(\.0), ["a", "b"])
        XCTAssertEqual(tx.sigs.map(\.1), ["s3", "s2"])
    }

    func testEnvelopeFieldOrder() throws {
        let plain = Transaction(tx: .object([("$contract", .string("c"))]), sigs: [("id", "sig")])
        XCTAssertEqual(try canonicalJSON(plain.toJSONValue()),
                       #"{"$sigs":{"id":"sig"},"$tx":{"$contract":"c"}}"#)
        let selfSigned = Transaction(tx: .object([]), sigs: [("k", "s")], selfsign: true)
        XCTAssertEqual(try canonicalJSON(selfSigned.toJSONValue()),
                       #"{"$selfsign":true,"$sigs":{"k":"s"},"$tx":{}}"#)
    }

    func testSignedStringIsOrderSensitive() {
        let a = Transaction(tx: .object([("x", .integer(1)), ("y", .integer(2))]))
        let b = Transaction(tx: .object([("y", .integer(2)), ("x", .integer(1))]))
        XCTAssertEqual(a.signedString, #"{"x":1,"y":2}"#)
        XCTAssertEqual(b.signedString, #"{"y":2,"x":1}"#)
    }

    func testSignStringMatchesProviderSignature() throws {
        let key = try onboarded()
        let sig = try handler.signString("hello", key: key)
        XCTAssertEqual(sig, try crypto.sign("hello", privateKey: key.key.privateKey, type: .secp256k1))
    }

    func testOnboardTxForPostQuantumKeyCarriesItsWireType() throws {
        let key = try keys.generateKey("pq", type: .mlDsa65)
        let tx = try handler.buildOnboardKeyTx(key, contract: "custom", namespace: "space")
        XCTAssertTrue(tx.signedString.hasPrefix(#"{"$contract":"custom","$i":{"pq":{"publicKey":""#))
        XCTAssertTrue(tx.signedString.hasSuffix(#"","type":"ml-dsa-65"}},"$namespace":"space"}"#))
        XCTAssertEqual(tx.sigs.map(\.0), ["pq"])
        XCTAssertTrue(crypto.verify(tx.signedString, signature: tx.sigs[0].1,
                                    publicKey: key.publicKey, type: .mlDsa65))
    }
}
