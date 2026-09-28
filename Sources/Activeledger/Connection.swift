import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A connection to one Activeledger node.
public struct Connection {
    /// The node's base URL.
    public let baseURL: URL
    private let session: URLSession

    /// A connection to `protocol://address:port`.
    public init(_ scheme: String, _ address: String, _ port: Int,
                session: URLSession = .shared) throws {
        try self.init(url: "\(scheme)://\(address):\(port)", session: session)
    }

    /// A connection to the node at `url`.
    public init(url: String, session: URLSession = .shared) throws {
        guard let u = URL(string: url), let s = u.scheme, s == "http" || s == "https" else {
            throw ActiveledgerError.invalidArgument("url must start with http:// or https://: \(url)")
        }
        self.baseURL = u
        self.session = session
    }

    /// Send a transaction and return the ledger's response. The body is
    /// serialised with `canonicalJSON`, so the `$tx` the node receives is
    /// byte-identical to the one that was signed.
    ///
    /// **A rejected transaction is HTTP 200.** Check `LedgerResponse.committed`,
    /// not only that this did not throw. Throws `ActiveledgerError.http` for a
    /// non-2xx status.
    public func sendTransaction(_ tx: Transaction) async throws -> LedgerResponse {
        try await send(canonicalJSON(tx.toJSONValue()))
    }

    /// Send an already-built envelope value.
    public func sendEnvelope(_ envelope: JSONValue) async throws -> LedgerResponse {
        try await send(canonicalJSON(envelope))
    }

    private func send(_ body: String) async throws -> LedgerResponse {
        var request = URLRequest(url: baseURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        // Send the body with uploadTask rather than setting request.httpBody and
        // calling data(for:). On Linux (swift-corelibs-foundation) a POST whose
        // body is set that way fails with "Failure writing output to
        // destination"; uploadTask delivers the body correctly on every
        // platform, macOS and iOS included.
        let (data, response) = try await Connection.upload(Data(body.utf8), for: request,
                                                           using: session)
        let text = String(decoding: data, as: UTF8.self)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw ActiveledgerError.http(statusCode: http.statusCode, body: text)
        }
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ActiveledgerError.ledger("Unexpected ledger response: \(text)")
        }
        return LedgerResponse(raw: obj)
    }

    /// POST `body` via `uploadTask`, bridged to async. The completion-handler
    /// upload API is the one path that reliably sends a request body on both
    /// Apple platforms and Linux.
    private static func upload(_ body: Data, for request: URLRequest,
                              using session: URLSession) async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            let task = session.uploadTask(with: request, from: body) { data, response, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, let response {
                    continuation.resume(returning: (data, response))
                } else {
                    continuation.resume(throwing: ActiveledgerError.ledger(
                        "No response received from the node"))
                }
            }
            task.resume()
        }
    }
}

/// The ledger's reply to a submitted transaction.
public struct LedgerResponse {
    /// The decoded JSON, for anything the typed accessors do not cover.
    public let raw: [String: Any]
    public init(raw: [String: Any]) { self.raw = raw }

    /// The transaction's unique id.
    public var umid: String? { raw["$umid"] as? String }

    private var summaryDict: [String: Any] { raw["$summary"] as? [String: Any] ?? [:] }
    private var streamsDict: [String: Any] { raw["$streams"] as? [String: Any] ?? [:] }

    /// Consensus totals.
    public var total: Int? { (summaryDict["total"] as? NSNumber)?.intValue }
    public var vote: Int? { (summaryDict["vote"] as? NSNumber)?.intValue }
    public var commit: Int? { (summaryDict["commit"] as? NSNumber)?.intValue }

    /// Values a contract returned with `returnToRemote`.
    public var responses: [Any] { raw["$responses"] as? [Any] ?? [] }

    /// Errors the network reported. Non-empty means the transaction did NOT
    /// commit, even though the HTTP status was 200.
    public var errors: [String] {
        guard let list = summaryDict["errors"] as? [Any] else { return [] }
        return list.map { ($0 as? String) ?? String(describing: $0) }
    }

    /// Streams created (`$streams.new`); the first after onboarding is the new
    /// identity.
    public var created: [StreamRef] { LedgerResponse.refs(streamsDict["new"]) }
    /// Streams updated (`$streams.updated`).
    public var updated: [StreamRef] { LedgerResponse.refs(streamsDict["updated"]) }

    /// Convenience: created + updated under one accessor.
    public var streams: (created: [StreamRef], updated: [StreamRef]) { (created, updated) }

    /// Whether the transaction committed.
    public var committed: Bool { errors.isEmpty && (commit == nil || commit! > 0) }

    private static func refs(_ value: Any?) -> [StreamRef] {
        guard let list = value as? [Any] else { return [] }
        return list.compactMap { item in
            guard let m = item as? [String: Any], let id = m["id"] as? String else { return nil }
            return StreamRef(id: id, name: m["name"] as? String)
        }
    }
}

/// A stream id and its name.
public struct StreamRef: Equatable {
    public let id: String
    public let name: String?
    public init(id: String, name: String?) { self.id = id; self.name = name }
}
