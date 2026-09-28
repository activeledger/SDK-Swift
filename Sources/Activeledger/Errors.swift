import Foundation

/// Errors this SDK raises about the ledger or its data, as opposed to
/// programming errors (which are `precondition`/`fatalError` or thrown
/// `ActiveledgerError.invalidArgument`).
public enum ActiveledgerError: Error, CustomStringConvertible, Equatable {
    /// A value handed to the SDK was malformed (wrong length, wrong type
    /// string, a number JavaScript cannot represent, and so on).
    case invalidArgument(String)

    /// A key type was requested whose implementation is not present in this
    /// process - Falcon-512 without the `ActiveledgerFalcon` add-on.
    case keyTypeUnavailable(String)

    /// The node answered with a non-2xx HTTP status.
    ///
    /// A transaction the ledger *rejects* is still HTTP 200; that case is
    /// reported through `LedgerResponse.errors`, not by this error.
    case http(statusCode: Int, body: String)

    /// Onboarding did not produce an identity.
    case onboard(message: String)

    /// A general ledger/data error.
    case ledger(String)

    public var description: String {
        switch self {
        case .invalidArgument(let m): return "ActiveledgerError.invalidArgument: \(m)"
        case .keyTypeUnavailable(let m): return "ActiveledgerError.keyTypeUnavailable: \(m)"
        case .http(let code, let body): return "ActiveledgerError.http: HTTP \(code): \(body)"
        case .onboard(let m): return "ActiveledgerError.onboard: \(m)"
        case .ledger(let m): return "ActiveledgerError.ledger: \(m)"
        }
    }
}
