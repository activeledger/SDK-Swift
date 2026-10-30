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
        // PEM-framed but undecodable: swift-crypto aborts (Signal 6) on this, so
        // PEMGuard must refuse it before it gets there.
        XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                     publicKey: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
                                     type: .rsa))
        XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                     publicKey: "0x04aa", type: .rsa))
    }

    func testMalformedPEMPublicKeysVerifyFalseWithoutReachingSwiftCrypto() {
        for (name, pem) in malformedPEMs(label: "PUBLIC KEY", valid: PEMFixtures.rsaPublic) {
            XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature, publicKey: pem, type: .rsa), name)
            XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature, publicKey: pem, type: .secp256k1), name)
        }
    }

    func testMalformedPEMPrivateKeysThrowOnSign() {
        for (name, pem) in malformedPEMs(label: "PRIVATE KEY", valid: PEMFixtures.rsaPKCS8Private) {
            XCTAssertThrowsError(try crypto.sign(msg, privateKey: pem, type: .rsa), name)
            XCTAssertThrowsError(try crypto.sign(msg, privateKey: pem, type: .secp256k1), name)
        }
        for (name, pem) in malformedPEMs(label: "RSA PRIVATE KEY", valid: PEMFixtures.rsaPKCS1Private) {
            XCTAssertThrowsError(try crypto.sign(msg, privateKey: pem, type: .rsa), name)
        }
        for (name, pem) in malformedPEMs(label: "EC PRIVATE KEY", valid: PEMFixtures.ecPrivate) {
            XCTAssertThrowsError(try crypto.sign(msg, privateKey: pem, type: .secp256k1), name)
        }
    }

    func testWellFormedButDegenerateRSAKeysAreRefusedNotFatal() throws {
        // Valid DER, nonsense key: modulus 3, exponent 3.
        let rsaPublic = der(0x30, der(0x02, [3]) + der(0x02, [3]))
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        let spki = der(0x30, der(0x30, rsaOID + [0x05, 0x00]) + der(0x03, [0x00] + rsaPublic))
        XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                     publicKey: pem("PUBLIC KEY", spki), type: .rsa))
        XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature,
                                     publicKey: pem("RSA PUBLIC KEY", rsaPublic), type: .rsa))
        let ints = [UInt8](repeating: 0, count: 0) + der(0x02, [0]) + (0..<8).flatMap { _ in der(0x02, [3]) }
        XCTAssertThrowsError(try crypto.sign(msg, privateKey: pem("RSA PRIVATE KEY", der(0x30, ints)), type: .rsa))
    }

    // A structurally valid 2048-bit-modulus key to mutate one thing at a time.
    private let modulus: [UInt8] = [0x00, 0xC0] + [UInt8](repeating: 0x55, count: 254) + [0x01]
    private let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

    private func rsaPublicDER(n: [UInt8]? = nil, e: [UInt8] = [0x01, 0x00, 0x01]) -> [UInt8] {
        der(0x30, der(0x02, n ?? modulus) + der(0x02, e))
    }

    private func spki(params: [UInt8] = [0x05, 0x00], key: [UInt8]? = nil, tail: [UInt8] = []) -> [UInt8] {
        der(0x30, der(0x30, rsaOID + params) + der(0x03, [0x00] + (key ?? rsaPublicDER())) + tail)
    }

    func testGuardAcceptsTheBaselineAndRejectsEachSingleMutation() {
        func algorithm(_ bytes: [UInt8]) -> PEMGuard.Algorithm? {
            PEMGuard.algorithm(of: pem("PUBLIC KEY", bytes))
        }
        XCTAssertEqual(algorithm(spki()), .rsa)
        XCTAssertEqual(algorithm(spki(params: [])), .rsa) // absent parameters are allowed

        XCTAssertNil(algorithm(spki(params: [0x05, 0x01, 0x00])), "NULL with content")
        XCTAssertNil(algorithm(spki(params: [0x04, 0x00])), "non-NULL parameters")
        XCTAssertNil(algorithm(spki(params: [0x05, 0x00, 0x05, 0x00])), "extra parameters")
        XCTAssertNil(algorithm(spki(params: [0x02, 0x01, 0x00])), "INTEGER parameters")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(n: [0x00]))), "zero modulus")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(n: [0x03]))), "tiny modulus")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(n: [0x00, 0xC0] + [UInt8](repeating: 0x55, count: 254) + [0x00]))),
                     "even modulus")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(n: [0x00, 0x80] + [UInt8](repeating: 0x55, count: 2100) + [0x01]))),
                     "oversized modulus")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(n: [0xC0] + [UInt8](repeating: 0x55, count: 255)))),
                     "negative modulus")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(e: [0x00]))), "zero exponent")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(e: [0x01]))), "exponent 1")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(e: [0x80, 0x01]))), "negative exponent")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER(e: [0x00, 0x00, 0x01]))), "non-minimal exponent")
        XCTAssertNil(algorithm(spki(key: rsaPublicDER() + [0x00])), "trailing byte inside the key")
        XCTAssertNil(algorithm(spki(tail: [0x00])), "trailing byte in the SPKI")
        XCTAssertNil(algorithm(spki() + [0x00]), "trailing byte after the SPKI")
        XCTAssertNil(algorithm(spki(key: [0x30, 0x80, 0x02, 0x01, 0x03, 0x00, 0x00])), "indefinite length")
        XCTAssertNil(algorithm(spki(key: [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF])), "oversized length")
        XCTAssertNil(algorithm(spki(key: [0x30, 0x81, 0x05] + [UInt8](rsaPublicDER().prefix(5)))), "non-minimal length")
        XCTAssertNil(algorithm(spki(key: Array(rsaPublicDER().dropLast(3)))), "truncated INTEGER")
    }

    func testGuardChecksPKCS8AndPKCS1PrivateKeyStructure() {
        func privateDER(version: [UInt8] = [0], n: [UInt8]? = nil, d: [UInt8] = [0x07]) -> [UInt8] {
            der(0x30, der(0x02, version) + der(0x02, n ?? modulus) + der(0x02, [0x01, 0x00, 0x01]) + der(0x02, d)
                + (0..<5).flatMap { _ in der(0x02, [0x07]) })
        }
        func pkcs8(params: [UInt8] = [0x05, 0x00], key: [UInt8]) -> [UInt8] {
            der(0x30, der(0x02, [0]) + der(0x30, rsaOID + params) + der(0x04, key))
        }
        XCTAssertEqual(PEMGuard.algorithm(of: pem("RSA PRIVATE KEY", privateDER())), .rsa)
        XCTAssertEqual(PEMGuard.algorithm(of: pem("PRIVATE KEY", pkcs8(key: privateDER()))), .rsa)

        XCTAssertNil(PEMGuard.algorithm(of: pem("RSA PRIVATE KEY", privateDER(version: [1]))))
        XCTAssertNil(PEMGuard.algorithm(of: pem("RSA PRIVATE KEY", privateDER(n: [0x00]))), "zero modulus")
        XCTAssertNil(PEMGuard.algorithm(of: pem("RSA PRIVATE KEY", privateDER(d: [0x00]))), "zero private exponent")
        XCTAssertNil(PEMGuard.algorithm(of: pem("RSA PRIVATE KEY", privateDER() + [0x00])), "trailing byte")
        XCTAssertNil(PEMGuard.algorithm(of: pem("PRIVATE KEY", pkcs8(params: [0x04, 0x00], key: privateDER()))))
        XCTAssertNil(PEMGuard.algorithm(of: pem("PRIVATE KEY", pkcs8(params: [0x05, 0x00, 0x05, 0x00], key: privateDER()))))
        XCTAssertNil(PEMGuard.algorithm(of: pem("PRIVATE KEY", pkcs8(key: privateDER() + [0x00]))), "trailing inside OCTET STRING")
        XCTAssertNil(PEMGuard.algorithm(of: pem("PRIVATE KEY", pkcs8(key: [0x30, 0x00]))), "empty key SEQUENCE")
    }

    func testGuardRejectsWhatTwoParsersCouldReadDifferently() {
        let b64 = Data(spki()).base64EncodedString()
        let framed = "-----BEGIN PUBLIC KEY-----\n\(b64)\n-----END PUBLIC KEY-----"
        XCTAssertEqual(PEMGuard.algorithm(of: framed), .rsa)
        XCTAssertEqual(PEMGuard.algorithm(of: framed.replacingOccurrences(of: "\n", with: "\r\n")), .rsa)

        for (name, bad) in [
            ("NEL newline", "-----BEGIN PUBLIC KEY-----\u{85}\(b64)\u{85}-----END PUBLIC KEY-----"),
            ("line separator", "-----BEGIN PUBLIC KEY-----\u{2028}\(b64)\u{2028}-----END PUBLIC KEY-----"),
            ("no-break space in the body", framed.replacingOccurrences(of: "A", with: "\u{A0}")),
            ("zero-width space", "-----BEGIN PUBLIC KEY-----\n\u{200B}\(b64)\n-----END PUBLIC KEY-----"),
            ("NUL", "-----BEGIN PUBLIC KEY-----\n\(b64)\u{0}\n-----END PUBLIC KEY-----"),
            ("tab", "-----BEGIN PUBLIC KEY-----\n\(b64)\t\n-----END PUBLIC KEY-----"),
            ("garbage before", "junk\n" + framed),
            ("garbage after", framed + "\njunk"),
            ("second block", framed + "\n" + framed),
        ] {
            XCTAssertNil(PEMGuard.algorithm(of: bad), name)
            XCTAssertFalse(crypto.verify(msg, signature: PEMFixtures.rsaSignature, publicKey: bad, type: .rsa), name)
        }
    }

    func testCanonicalPEMIsWhatSwiftCryptoGets() throws {
        // Differently armoured copies of one key verify identically.
        let body = PEMFixtures.rsaPublic.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
        let oneLine = "-----BEGIN PUBLIC KEY-----\r\n\(body)\r\n-----END PUBLIC KEY-----\r\n"
        XCTAssertTrue(crypto.verify(msg, signature: PEMFixtures.rsaSignature, publicKey: oneLine, type: .rsa))
        let key = try XCTUnwrap(PEMGuard.validate(oneLine))
        XCTAssertEqual(key.canonicalPEM, PEMGuard.validate(PEMFixtures.rsaPublic)?.canonicalPEM)
    }

    func testWellFormedPEMFixturesAreRecognised() {
        XCTAssertEqual(PEMGuard.algorithm(of: PEMFixtures.rsaPublic), .rsa)
        XCTAssertEqual(PEMGuard.algorithm(of: PEMFixtures.rsaPKCS8Private), .rsa)
        XCTAssertEqual(PEMGuard.algorithm(of: PEMFixtures.rsaPKCS1Private), .rsa)
        XCTAssertEqual(PEMGuard.algorithm(of: PEMFixtures.ecPublic), .other)
        XCTAssertEqual(PEMGuard.algorithm(of: PEMFixtures.ecPrivate), .other)
    }

    // MARK: PEM builders

    private func der(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        let n = content.count
        let length: [UInt8] = n < 0x80 ? [UInt8(n)] : n < 0x100 ? [0x81, UInt8(n)]
            : [0x82, UInt8(n >> 8), UInt8(n & 0xFF)]
        return [tag] + length + content
    }

    private func pem(_ label: String, _ bytes: [UInt8]) -> String {
        "-----BEGIN \(label)-----\n\(Data(bytes).base64EncodedString())\n-----END \(label)-----"
    }

    /// `valid` damaged in the ways a hostile or corrupt key file can be.
    private func malformedPEMs(label: String, valid: String) -> [(String, String)] {
        let body = valid.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
        let bytes = [UInt8](Data(base64Encoded: body)!)
        var wrongTag = bytes; wrongTag[0] = 0x31
        var huge = bytes; huge.replaceSubrange(1..<min(4, huge.count), with: [0x84, 0xFF, 0xFF, 0xFF, 0xFF])
        var overLong = bytes; overLong[1] = 0x82; overLong[2] = 0xFF; overLong[3] = 0xFF
        return [
            ("undecodable body", "-----BEGIN \(label)-----\nAAAA\n-----END \(label)-----"),
            ("empty body", "-----BEGIN \(label)-----\n-----END \(label)-----"),
            ("not base64", "-----BEGIN \(label)-----\n!!!!not base64!!!!\n-----END \(label)-----"),
            ("truncated DER", pem(label, Array(bytes.prefix(bytes.count / 2)))),
            ("one byte short", pem(label, Array(bytes.dropLast()))),
            ("wrong tag", pem(label, wrongTag)),
            ("trailing garbage", pem(label, bytes + [0xDE, 0xAD, 0xBE, 0xEF])),
            ("huge length field", pem(label, huge)),
            ("length beyond the data", pem(label, overLong)),
            ("wrong label", pem("CERTIFICATE", bytes)),
            ("mismatched END", "-----BEGIN \(label)-----\n\(body)\n-----END OTHER-----"),
            ("no END", "-----BEGIN \(label)-----\n\(body)"),
        ]
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
