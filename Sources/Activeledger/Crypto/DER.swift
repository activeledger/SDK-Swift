import Foundation

/// Just enough DER to read and write an ECDSA signature: SEQUENCE { INTEGER
/// r, INTEGER s }. Values are handled as big-endian magnitude byte arrays,
/// so no big-integer type is needed. Strict: trailing bytes are refused.
enum DER {
    /// Encode SEQUENCE { INTEGER r, INTEGER s } from big-endian magnitudes.
    static func encodeSignature(r: [UInt8], s: [UInt8]) -> [UInt8] {
        let body = integer(r) + integer(s)
        return [0x30] + length(body.count) + body
    }

    /// Decode SEQUENCE { INTEGER r, INTEGER s }, returning big-endian
    /// magnitudes (leading zero sign byte stripped).
    static func decodeSignature(_ bytes: [UInt8]) throws -> (r: [UInt8], s: [UInt8]) {
        var i = 0
        guard i < bytes.count, bytes[i] == 0x30 else {
            throw ActiveledgerError.invalidArgument("ECDSA signature is not a DER SEQUENCE")
        }
        i += 1
        let (seqLen, seqHeader) = try readLength(bytes, i)
        i += seqHeader
        guard i + seqLen == bytes.count else {
            throw ActiveledgerError.invalidArgument("DER: trailing bytes after signature")
        }
        let r = try readInteger(bytes, &i)
        let s = try readInteger(bytes, &i)
        guard i == bytes.count else {
            throw ActiveledgerError.invalidArgument("DER signature has extra components")
        }
        return (r, s)
    }

    // MARK: internals

    /// TLV for a non-negative INTEGER from a big-endian magnitude.
    static func integer(_ magnitude: [UInt8]) -> [UInt8] {
        var m = magnitude
        while m.count > 1 && m.first == 0 { m.removeFirst() }
        if m.isEmpty { m = [0] }
        // DER INTEGERs are signed: prepend 0x00 if the top bit is set.
        if m[0] & 0x80 != 0 { m.insert(0, at: 0) }
        return [0x02] + length(m.count) + m
    }

    private static func length(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        if n < 0x100 { return [0x81, UInt8(n)] }
        return [0x82, UInt8(n >> 8), UInt8(n & 0xff)]
    }

    private static func readLength(_ bytes: [UInt8], _ i: Int) throws -> (value: Int, header: Int) {
        guard i < bytes.count else { throw ActiveledgerError.invalidArgument("DER: truncated length") }
        let first = bytes[i]
        if first < 0x80 { return (Int(first), 1) }
        let count = Int(first & 0x7f)
        guard count >= 1 && count <= 2, i + count < bytes.count else {
            throw ActiveledgerError.invalidArgument("DER: unsupported length encoding")
        }
        var value = 0
        for j in 0..<count { value = (value << 8) | Int(bytes[i + 1 + j]) }
        return (value, 1 + count)
    }

    private static func readInteger(_ bytes: [UInt8], _ i: inout Int) throws -> [UInt8] {
        guard i < bytes.count, bytes[i] == 0x02 else {
            throw ActiveledgerError.invalidArgument("DER: expected INTEGER")
        }
        i += 1
        let (len, header) = try readLength(bytes, i)
        i += header
        guard len > 0, i + len <= bytes.count else {
            throw ActiveledgerError.invalidArgument("DER: bad INTEGER length")
        }
        var content = Array(bytes[i..<(i + len)])
        i += len
        guard content[0] & 0x80 == 0 else {
            throw ActiveledgerError.invalidArgument("DER: negative INTEGER")
        }
        while content.count > 1 && content.first == 0 { content.removeFirst() }
        return content
    }
}
