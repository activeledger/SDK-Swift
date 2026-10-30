import Foundation

/// Checks a PEM key is structurally sound DER before it reaches swift-crypto.
///
/// swift-crypto's RSA initialisers can abort the whole process (Signal 6, in
/// BoringSSL's `EVP_PKEY_free`) on their error path for input that is framed
/// as PEM but is not a decodable key, and `try?` cannot catch an abort. So
/// nothing is handed to `_RSA` until the base64 body and the ASN.1 structure
/// of the key have been proven well formed here. Anything this rejects is an
/// ordinary error to the caller.
enum PEMGuard {
    enum Algorithm {
        case rsa
        /// Not RSA; left to the secp256k1 PEM parser.
        case other
    }

    /// The algorithm of the one well-formed PEM key in `pem`, or nil when it
    /// is not a recognisable, well-formed key.
    static func algorithm(of pem: String) -> Algorithm? {
        guard let (label, der) = decode(pem) else { return nil }
        switch label {
        case "PUBLIC KEY": return publicKey(der)
        case "PRIVATE KEY": return privateKey(der)
        case "RSA PUBLIC KEY": return rsaPublicKey(der) ? .rsa : nil
        case "RSA PRIVATE KEY": return rsaPrivateKey(der) ? .rsa : nil
        case "EC PRIVATE KEY": return ecPrivateKey(der) ? .other : nil
        default: return nil
        }
    }

    // MARK: PEM framing

    private static func decode(_ pem: String) -> (String, [UInt8])? {
        let lines = pem.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let begin = "-----BEGIN ", end = "-----END ", dashes = "-----"
        guard lines.count >= 3, let first = lines.first, let last = lines.last,
              first.hasPrefix(begin), first.hasSuffix(dashes),
              last.hasPrefix(end), last.hasSuffix(dashes) else { return nil }
        let label = String(first.dropFirst(begin.count).dropLast(dashes.count))
        guard label == String(last.dropFirst(end.count).dropLast(dashes.count)) else { return nil }
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        let body = lines.dropFirst().dropLast().joined()
        guard !body.isEmpty, body.allSatisfy({ allowed.contains($0) }),
              let data = Data(base64Encoded: body) else { return nil }
        return (label, [UInt8](data))
    }

    // MARK: DER

    private static let sequence: UInt8 = 0x30, integer: UInt8 = 0x02, bitString: UInt8 = 0x03
    private static let octetString: UInt8 = 0x04, oid: UInt8 = 0x06
    /// rsaEncryption, 1.2.840.113549.1.1.1
    private static let rsaOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

    /// One DER element: tag, content, and the bytes after it. Lengths must be
    /// definite, minimally encoded and inside the input.
    private static func element(_ b: ArraySlice<UInt8>) -> (tag: UInt8, content: ArraySlice<UInt8>,
                                                            rest: ArraySlice<UInt8>)? {
        var i = b.startIndex
        guard b.count >= 2 else { return nil }
        let tag = b[i]; i += 1
        guard tag & 0x1F != 0x1F else { return nil } // multi-byte tags: not in a key
        var length = Int(b[i]); i += 1
        if length & 0x80 != 0 {
            let n = length & 0x7F
            guard (1...4).contains(n), b.endIndex - i >= n, b[i] != 0 else { return nil }
            length = 0
            for _ in 0..<n { length = length << 8 | Int(b[i]); i += 1 }
            guard length >= 0x80 else { return nil }
        }
        guard length <= b.endIndex - i else { return nil }
        return (tag, b[i..<i + length], b[(i + length)...])
    }

    /// All the elements of `b`, with nothing left over.
    private static func children(_ b: ArraySlice<UInt8>) -> [(tag: UInt8, content: ArraySlice<UInt8>)]? {
        var out: [(tag: UInt8, content: ArraySlice<UInt8>)] = []
        var rest = b
        while !rest.isEmpty {
            guard let e = element(rest) else { return nil }
            out.append((e.tag, e.content))
            rest = e.rest
        }
        return out
    }

    /// The children of the single SEQUENCE that makes up all of `der`.
    private static func sequenceChildren(_ der: [UInt8]) -> [(tag: UInt8, content: ArraySlice<UInt8>)]? {
        guard let e = element(der[...]), e.tag == sequence, e.rest.isEmpty else { return nil }
        return children(e.content)
    }

    /// A positive INTEGER in minimal form.
    private static func isPositiveInteger(_ c: (tag: UInt8, content: ArraySlice<UInt8>)) -> Bool {
        guard c.tag == integer, let first = c.content.first, first & 0x80 == 0 else { return false }
        return c.content.count == 1 || first != 0 || c.content[c.content.startIndex + 1] & 0x80 != 0
    }

    /// AlgorithmIdentifier: the OID and any parameters (which must be well formed).
    private static func algorithmOID(_ c: (tag: UInt8, content: ArraySlice<UInt8>)) -> [UInt8]? {
        guard c.tag == sequence, let parts = children(c.content), let id = parts.first, id.tag == oid,
              !id.content.isEmpty, parts.count <= 2 else { return nil }
        return [UInt8](id.content)
    }

    // MARK: key structures

    /// SubjectPublicKeyInfo.
    private static func publicKey(_ der: [UInt8]) -> Algorithm? {
        guard let c = sequenceChildren(der), c.count == 2, let id = algorithmOID(c[0]),
              c[1].tag == bitString, c[1].content.first == 0 else { return nil }
        if id == rsaOID { return rsaPublicKey(Array(c[1].content.dropFirst())) ? .rsa : nil }
        return .other
    }

    /// PKCS#8 PrivateKeyInfo.
    private static func privateKey(_ der: [UInt8]) -> Algorithm? {
        guard let c = sequenceChildren(der), c.count >= 3, c[0].tag == integer, c[0].content.count == 1,
              let id = algorithmOID(c[1]), c[2].tag == octetString else { return nil }
        if id == rsaOID { return rsaPrivateKey(Array(c[2].content)) ? .rsa : nil }
        return .other
    }

    /// PKCS#1 RSAPublicKey: modulus and exponent.
    private static func rsaPublicKey(_ der: [UInt8]) -> Bool {
        guard let c = sequenceChildren(der), c.count == 2 else { return false }
        return c.allSatisfy(isPositiveInteger)
    }

    /// PKCS#1 RSAPrivateKey: version 0 and eight positive integers.
    private static func rsaPrivateKey(_ der: [UInt8]) -> Bool {
        guard let c = sequenceChildren(der), c.count == 9, c[0].tag == integer,
              Array(c[0].content) == [0] else { return false }
        return c.dropFirst().allSatisfy(isPositiveInteger)
    }

    /// SEC1 ECPrivateKey: version, private key, then optional tagged items.
    private static func ecPrivateKey(_ der: [UInt8]) -> Bool {
        guard let c = sequenceChildren(der), c.count >= 2, c[0].tag == integer,
              c[1].tag == octetString else { return false }
        return true
    }
}
