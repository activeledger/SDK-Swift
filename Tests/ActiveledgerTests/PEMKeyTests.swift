import XCTest
@testable import Activeledger

// RSA and PEM-encoded secp256k1 keys (legacy identities). The expectations come
// from OpenSSL (see PEMFixtures.swift), not from the SDK. RSA PKCS#1 v1.5
// signatures are deterministic, so the SDK's must equal OpenSSL's byte for byte.
final class PEMKeyTests: XCTestCase {
    private let crypto = DefaultCryptoProvider()
    private let msg = PEMFixtures.message

    // MARK: RSA

    func testRSASignatureMatchesOpenSSLForPKCS8AndPKCS1Keys() throws {
        for pem in [PEMFixtures.rsaPKCS8Private, PEMFixtures.rsaPKCS1Private] {
            XCTAssertEqual(try crypto.sign(msg, privateKey: pem, type: .rsa), PEMFixtures.rsaSignature)
        }
    }

    func testRSAVerifiesOpenSSLSignature() {
        XCTAssertTrue(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                    publicKey: PEMFixtures.rsaPublic, type: .rsa))
    }

    func testRSAVerifyFailsForAlteredMessageSignatureOrKey() {
        XCTAssertFalse(crypto.verify(msg + "!", signature: PEMFixtures.rsaSignature,
                                     publicKey: PEMFixtures.rsaPublic, type: .rsa))
        var tampered = PEMFixtures.rsaSignature
        tampered.replaceSubrange(tampered.startIndex...tampered.startIndex,
                                 with: tampered.first == "A" ? "B" : "A")
        XCTAssertFalse(crypto.verify(msg, signature: tampered,
                                     publicKey: PEMFixtures.rsaPublic, type: .rsa))
        XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                     publicKey: PEMFixtures.ecPublic, type: .rsa))
    }

    func testRSAVerifyIsFalseForMalformedInput() {
        XCTAssertFalse(crypto.verify(msg, signature: "not base64!!", publicKey: PEMFixtures.rsaPublic, type: .rsa))
        XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                     publicKey: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
                                     type: .rsa))
        XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                     publicKey: "0x04aa", type: .rsa))
    }

    func testPEMDecidesTheAlgorithmNotTheDeclaredType() throws {
        // A legacy identity's type string is not always accurate; the PEM wins.
        XCTAssertEqual(try crypto.sign(msg, privateKey: PEMFixtures.rsaPKCS8Private, type: .secp256k1),
                       PEMFixtures.rsaSignature)
        XCTAssertTrue(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                    publicKey: PEMFixtures.rsaPublic, type: .secp256k1))
    }

    func testRSASignRejectsGarbagePEM() {
        XCTAssertThrowsError(try crypto.sign(
            msg, privateKey: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", type: .rsa))
    }

    func testRSAKeyPairSignsAndVerifiesATransaction() throws {
        let key = Key(name: "legacy", type: .rsa,
                      key: KeyMaterial(publicKey: PEMFixtures.rsaPublic, privateKey: PEMFixtures.rsaPKCS8Private),
                      identity: "stream-rsa")
        let tx = try TransactionHandler().labelledTransaction(
            key: key, namespace: "default", contract: "c", inputLabel: "in", stream: "stream-rsa")

        let sig = try XCTUnwrap(tx.sigs.first)
        XCTAssertEqual(sig.0, "stream-rsa")
        XCTAssertEqual(Data(base64Encoded: sig.1)?.count, 256) // RSA-2048
        XCTAssertTrue(crypto.verify(tx.signedString, signature: sig.1, publicKey: key.publicKey, type: .rsa))
        XCTAssertFalse(crypto.verify(tx.signedString + " ", signature: sig.1, publicKey: key.publicKey, type: .rsa))
    }

    func testRSAKeyFileRoundTripKeepsPEMIntact() throws {
        let key = Key(name: "legacy", type: .rsa,
                      key: KeyMaterial(publicKey: PEMFixtures.rsaPublic, privateKey: PEMFixtures.rsaPKCS8Private),
                      identity: "s")
        let back = try JSONDecoder().decode(Key.self, from: JSONEncoder().encode(key))
        XCTAssertEqual(back.type, .rsa)
        XCTAssertEqual(back.key, key.key)
        XCTAssertEqual(try crypto.sign(msg, privateKey: back.key.privateKey, type: back.type),
                       PEMFixtures.rsaSignature)
    }

    // MARK: PEM-encoded secp256k1

    func testECPEMVerifiesOpenSSLSignatureAsPEMAndAsHex() {
        XCTAssertTrue(crypto.verify(msg, signature: PEMFixtures.ecSignature,
                                    publicKey: PEMFixtures.ecPublic, type: .secp256k1))
        XCTAssertTrue(crypto.verify(msg, signature: PEMFixtures.ecSignature,
                                    publicKey: PEMFixtures.ecPublicHex, type: .secp256k1))
    }

    func testECPEMVerifyFailsForAlteredMessageOrOtherKey() throws {
        XCTAssertFalse(crypto.verify(msg + "!", signature: PEMFixtures.ecSignature,
                                     publicKey: PEMFixtures.ecPublic, type: .secp256k1))
        let other = try KeyHandler().generateKey("other")
        XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.ecSignature,
                                     publicKey: other.publicKey, type: .secp256k1))
    }

    func testECPEMSignatureIsDeterministicLowSAndVerifiesWithTheHexKey() throws {
        let a = try crypto.sign(msg, privateKey: PEMFixtures.ecPrivate, type: .secp256k1)
        let b = try crypto.sign(msg, privateKey: PEMFixtures.ecPrivate, type: .secp256k1)
        XCTAssertEqual(a, b)
        XCTAssertFalse(Secp256k1.isHighS([UInt8](try XCTUnwrap(Data(base64Encoded: a)))))
        XCTAssertTrue(crypto.verify(msg, signature: a, publicKey: PEMFixtures.ecPublicHex, type: .secp256k1))
        XCTAssertTrue(crypto.verify(msg, signature: a, publicKey: PEMFixtures.ecPublic, type: .secp256k1))
        XCTAssertFalse(crypto.verify(msg + "!", signature: a, publicKey: PEMFixtures.ecPublic, type: .secp256k1))
    }

    func testECPEMAndHexPrivateKeysSignIdentically() throws {
        // The scalar inside the PEM, as hex, must give the same RFC 6979 signature.
        let pem = try crypto.sign(msg, privateKey: PEMFixtures.ecPrivate, type: .secp256k1)
        let scalar = try pemScalarHex(PEMFixtures.ecPrivate)
        XCTAssertEqual(try crypto.sign(msg, privateKey: scalar, type: .secp256k1), pem)
    }

    /// The 32-byte private scalar from a SEC1 "EC PRIVATE KEY" PEM: the OCTET
    /// STRING that follows the `02 01 01 04 20` header.
    private func pemScalarHex(_ pem: String) throws -> String {
        let b64 = pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
        let der = [UInt8](try XCTUnwrap(Data(base64Encoded: b64)))
        let header: [UInt8] = [0x02, 0x01, 0x01, 0x04, 0x20]
        let at = try XCTUnwrap((0..<der.count - header.count).first { Array(der[$0..<$0 + 5]) == header })
        return "0x" + der[(at + 5)..<(at + 37)].map { String(format: "%02x", $0) }.joined()
    }
}
