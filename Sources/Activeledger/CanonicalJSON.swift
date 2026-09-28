import Foundation

/// A JSON value in the exact shape Activeledger signs.
///
/// Object member order is preserved (an array of pairs, not a dictionary),
/// because `JSON.stringify` preserves insertion order and the signature
/// covers those exact bytes.
public indirect enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    /// An integer that must be representable exactly as a JavaScript number.
    case integer(Int64)
    /// A double, formatted per ECMA-262 Number::toString.
    case number(Double)
    case string(String)
    case array([JSONValue])
    /// An object; members are kept in the given order.
    case object([(String, JSONValue)])

    public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null): return true
        case let (.bool(a), .bool(b)): return a == b
        case let (.integer(a), .integer(b)): return a == b
        case let (.number(a), .number(b)): return a == b
        case let (.string(a), .string(b)): return a == b
        case let (.array(a), .array(b)): return a == b
        case let (.object(a), .object(b)):
            return a.count == b.count
                && zip(a, b).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        default: return false
        }
    }
}

extension JSONValue: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral,
    ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral,
    ExpressibleByStringLiteral, ExpressibleByArrayLiteral,
    ExpressibleByDictionaryLiteral {
    public init(nilLiteral: ()) { self = .null }
    public init(booleanLiteral v: Bool) { self = .bool(v) }
    public init(integerLiteral v: Int64) { self = .integer(v) }
    public init(floatLiteral v: Double) { self = .number(v) }
    public init(stringLiteral v: String) { self = .string(v) }
    public init(arrayLiteral xs: JSONValue...) { self = .array(xs) }
    public init(dictionaryLiteral xs: (String, JSONValue)...) { self = .object(xs) }
}

private let maxDepth = 512

/// Serialise `value` exactly as JavaScript's `JSON.stringify` would.
///
/// Activeledger signs the exact bytes of `JSON.stringify($tx)` encoded UTF-8 -
/// no hash prefix, no length prefix, no key sorting - and the ledger verifies
/// by re-stringifying the `$tx` it parsed. A signature over bytes that differ
/// by one escape is invalid, reported as 1220 "Signature Incorrect".
public func canonicalJSON(_ value: JSONValue) throws -> String {
    var out = ""
    try write(value, into: &out, depth: 0)
    return out
}

/// The UTF-8 bytes of ``canonicalJSON(_:)`` - what actually gets signed.
public func canonicalJSONBytes(_ value: JSONValue) throws -> Data {
    Data(try canonicalJSON(value).utf8)
}

private func write(_ value: JSONValue, into out: inout String, depth: Int) throws {
    if depth > maxDepth {
        throw ActiveledgerError.invalidArgument(
            "JSON nesting is deeper than \(maxDepth) - is there a cycle?")
    }
    switch value {
    case .null:
        out += "null"
    case .bool(let b):
        out += b ? "true" : "false"
    case .string(let s):
        writeString(s, into: &out)
    case .integer(let i):
        out += try jsInteger(i)
    case .number(let d):
        out += try jsNumber(d)
    case .object(let members):
        out += "{"
        var first = true
        for (key, val) in members {
            if !first { out += "," }
            first = false
            writeString(key, into: &out)
            out += ":"
            try write(val, into: &out, depth: depth + 1)
        }
        out += "}"
    case .array(let items):
        out += "["
        var first = true
        for item in items {
            if !first { out += "," }
            first = false
            try write(item, into: &out, depth: depth + 1)
        }
        out += "]"
    }
}

/// An integer as JavaScript would print it after parsing it into a double.
func jsInteger(_ value: Int64) throws -> String {
    let asDouble = Double(value)
    guard let back = Int64(exactly: asDouble.rounded()), back == value else {
        throw ActiveledgerError.invalidArgument(
            "\(value) cannot be represented exactly as a JavaScript number - "
                + "the ledger would store a different value. Send it as a string.")
    }
    return try jsNumber(asDouble)
}

/// Format a double exactly as JavaScript's `Number.prototype.toString`
/// (and therefore `JSON.stringify`) would. Implements ECMA-262
/// Number::toString. Checked against `number-vectors.json`.
func jsNumber(_ value: Double) throws -> String {
    if value.isNaN || value.isInfinite {
        throw ActiveledgerError.invalidArgument(
            "\(value) cannot be serialised - JSON.stringify emits null, which "
                + "would sign bytes you did not intend")
    }
    if value == 0 { return "0" } // covers -0.0
    if value < 0 { return "-" + (try jsNumber(-value)) }

    let (digits, n) = shortestDecimal(value)
    let k = digits.count

    if k <= n && n <= 21 {
        return digits + String(repeating: "0", count: n - k)
    }
    if 0 < n && n <= 21 {
        let idx = digits.index(digits.startIndex, offsetBy: n)
        return String(digits[..<idx]) + "." + String(digits[idx...])
    }
    if -6 < n && n <= 0 {
        return "0." + String(repeating: "0", count: -n) + digits
    }
    let e = n - 1
    let head: String
    if k == 1 {
        head = digits
    } else {
        let second = digits.index(after: digits.startIndex)
        head = String(digits[..<second]) + "." + String(digits[second...])
    }
    return head + "e" + (e >= 0 ? "+" : "-") + String(abs(e))
}

/// Decompose a positive, finite, non-zero double into its shortest
/// round-tripping significant digits and a decimal exponent `n`, such that
/// `value == 0.<digits> * 10^n` with `digits` having no leading or trailing
/// zeros. Swift's default `Double` description is shortest round-tripping;
/// this parses it into that canonical form regardless of the form Swift chose.
func shortestDecimal(_ value: Double) -> (digits: String, n: Int) {
    var s = String(value)
    var exp = 0
    if let e = s.firstIndex(where: { $0 == "e" || $0 == "E" }) {
        exp = Int(s[s.index(after: e)...]) ?? 0
        s = String(s[..<e])
    }
    var intPart = s
    var fracPart = ""
    if let dot = s.firstIndex(of: ".") {
        intPart = String(s[..<dot])
        fracPart = String(s[s.index(after: dot)...])
    }
    var d = Array(intPart + fracPart)
    // value == d(as integer) * 10^(exp - fracPart.count)
    // In "0.<digits> * 10^n" form: n = intPart.count + exp, then adjust for
    // stripped leading zeros.
    var n = intPart.count + exp
    var lead = 0
    while lead < d.count - 1 && d[lead] == "0" { lead += 1; n -= 1 }
    d.removeFirst(lead)
    while d.count > 1 && d.last == "0" { d.removeLast() }
    let digits = String(d)
    if digits == "0" { return ("0", 1) }
    return (digits, n)
}

/// JSON string escaping, matching `JSON.stringify` exactly: escapes `"`, `\`,
/// the control characters below 0x20 (short forms where JS has them), and
/// lone UTF-16 surrogates. Everything else passes through as raw UTF-8.
private func writeString(_ value: String, into out: inout String) {
    out += "\""
    let units = Array(value.utf16)
    var i = 0
    while i < units.count {
        let c = units[i]
        switch c {
        case 0x22: out += "\\\""
        case 0x5c: out += "\\\\"
        case 0x0a: out += "\\n"
        case 0x0d: out += "\\r"
        case 0x09: out += "\\t"
        case 0x08: out += "\\b"
        case 0x0c: out += "\\f"
        default:
            if c < 0x20 {
                out += "\\u" + hex4(c)
            } else if c >= 0xd800 && c <= 0xdbff {
                // High surrogate: only well-formed followed by a low one.
                // Recombine the pair into its scalar so the emitted UTF-8
                // matches JavaScript passing the character through.
                if i + 1 < units.count && units[i + 1] >= 0xdc00 && units[i + 1] <= 0xdfff {
                    let hi = UInt32(c)
                    let lo = UInt32(units[i + 1])
                    let scalar = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                    out.unicodeScalars.append(Unicode.Scalar(scalar)!)
                    i += 1
                } else {
                    out += "\\u" + hex4(c)
                }
            } else if c >= 0xdc00 && c <= 0xdfff {
                out += "\\u" + hex4(c)
            } else {
                if let scalar = Unicode.Scalar(c) {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        i += 1
    }
    out += "\""
}

private func hex4(_ c: UInt16) -> String {
    let s = String(c, radix: 16)
    return String(repeating: "0", count: max(0, 4 - s.count)) + s
}
