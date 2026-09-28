import XCTest
@testable import Activeledger

private struct ProviderVector: Codable {
    let type: String
    let messageName: String
    let message: String
    let publicKey: String
    let privateKey: String
    let signature: String?
    let deterministicSignature: String?
}
private struct ProviderFile: Codable { let vectors: [ProviderVector] }

final class CryptoProviderTests: XCTestCase {
    private let crypto = DefaultCryptoProvider()

    private func secpVectors() throws -> [ProviderVector] {
        let url = Vectors.directory.appendingPathComponent("pq-vectors.json")
        return try JSONDecoder().decode(ProviderFile.self, from: Data(contentsOf: url))
            .vectors.filter { $0.type == "secp256k1" }
    }

    func testSignsSecp256k1DeterministicallyThroughProvider() throws {
        for v in try secpVectors() {
            let sig = try crypto.sign(v.message, privateKey: v.privateKey, type: .secp256k1)
            XCTAssertEqual(sig, v.deterministicSignature, "\(v.messageName): provider sign")
        }
    }

    func testVerifiesThroughProvider() throws {
        for v in try secpVectors() {
            XCTAssertTrue(
                crypto.verify(v.message, signature: v.signature!, publicKey: v.publicKey, type: .secp256k1),
                "\(v.messageName): provider verify")
            XCTAssertFalse(
                crypto.verify(v.message + " ", signature: v.signature!, publicKey: v.publicKey, type: .secp256k1),
                "\(v.messageName): provider rejects tampered message")
        }
    }

    func testGenerateRefusesUnsupportedType() {
        XCTAssertThrowsError(try crypto.generate(type: .rsa, compressed: false))
    }

    func testPostQuantumSignWithoutSchemeThrows() {
        // No ML-DSA scheme is registered in the core-only test target.
        XCTAssertThrowsError(try crypto.sign("hi", privateKey: "AAAA", type: .mlDsa65))
    }
}
