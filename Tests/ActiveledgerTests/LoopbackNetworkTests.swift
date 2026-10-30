import XCTest
@testable import Activeledger

// Exercises Connection and KeyHandler.onboardKey over a real socket to an
// in-process server on 127.0.0.1. No external network.
final class LoopbackNetworkTests: XCTestCase {
    private let keys = KeyHandler()
    private let crypto = DefaultCryptoProvider()

    private static let committed = """
        {"$umid":"u1","$summary":{"total":1,"vote":1,"commit":1,"errors":[]},\
        "$streams":{"new":[{"id":"stream-abc","name":"me"}],"updated":[]}}
        """
    private static let rejected = """
        {"$umid":"u2","$summary":{"total":1,"vote":0,"commit":0,"errors":["1220 Signature Incorrect"]},\
        "$streams":{"new":[],"updated":[]}}
        """

    private func serve(_ reply: String, status: Int = 200) throws -> LoopbackServer {
        try LoopbackServer { _ in .init(reply, status: status) }
    }

    private func sampleTx() -> Transaction {
        Transaction(tx: .object([("$contract", .string("c")), ("$namespace", .string("n"))]),
                    sigs: [("id", "c2ln")])
    }

    /// The text of `$tx` exactly as sent: it is the last member of the envelope.
    private func sentTx(_ body: String) throws -> String {
        let marker = "\"$tx\":"
        let range = try XCTUnwrap(body.range(of: marker), body)
        XCTAssertTrue(body.hasSuffix("}"))
        return String(body[range.upperBound...].dropLast())
    }

    // MARK: Connection.sendTransaction

    func testSendTransactionPostsTheCanonicalEnvelope() async throws {
        let server = try serve(Self.committed)
        defer { server.stop() }
        let tx = sampleTx()

        let response = try await Connection(url: server.url).sendTransaction(tx)

        let req = try XCTUnwrap(server.requests.first)
        XCTAssertEqual(server.requests.count, 1)
        XCTAssertEqual(req.method, "POST")
        XCTAssertEqual(req.path, "/")
        XCTAssertEqual(req.headers["content-type"], "application/json")
        XCTAssertEqual(req.bodyString, try canonicalJSON(tx.toJSONValue()))
        XCTAssertEqual(try sentTx(req.bodyString), tx.signedString)

        XCTAssertTrue(response.committed)
        XCTAssertEqual(response.umid, "u1")
        XCTAssertEqual(response.commit, 1)
        XCTAssertEqual(response.created, [StreamRef(id: "stream-abc", name: "me")])
    }

    func testBaseURLPathIsPostedTo() async throws {
        let server = try serve(Self.committed)
        defer { server.stop() }
        _ = try await Connection(url: server.url + "/a/b").sendTransaction(sampleTx())
        XCTAssertEqual(server.requests.first?.path, "/a/b")
    }

    func testSendEnvelopeSendsTheGivenValue() async throws {
        let server = try serve(Self.committed)
        defer { server.stop() }
        let envelope = JSONValue.object([("$tx", .object([("x", .integer(1))])), ("extra", .bool(true))])
        _ = try await Connection(url: server.url).sendEnvelope(envelope)
        XCTAssertEqual(server.requests.first?.bodyString, try canonicalJSON(envelope))
    }

    func testRejectedTransactionIsHTTP200AndNotCommitted() async throws {
        let server = try serve(Self.rejected)
        defer { server.stop() }

        let response = try await Connection(url: server.url).sendTransaction(sampleTx())

        XCTAssertFalse(response.committed)
        XCTAssertEqual(response.errors, ["1220 Signature Incorrect"])
        XCTAssertEqual(response.commit, 0)
        XCTAssertTrue(response.created.isEmpty)
    }

    // MARK: non-2xx and malformed replies

    func testRefusedPortFailsFastRatherThanWaitingForTheRequestTimeout() async throws {
        // A port that was just listening and no longer is: nothing will accept.
        let server = try serve(Self.committed)
        let url = server.url
        server.stop()
        let connection = try Connection(url: url)

        let start = Date()
        do {
            _ = try await connection.sendEnvelope(.object([("$tx", .string("x"))]))
            XCTFail("a refused connection must throw")
        } catch {}
        XCTAssertLessThan(Date().timeIntervalSince(start), 10) // 30 s before the connect timeout
    }

    func testNon2xxThrowsHTTPErrorWithStatusAndBody() async throws {
        for (status, body) in [(500, "boom"), (404, #"{"error":"nope"}"#), (503, "")] {
            let server = try serve(body, status: status)
            defer { server.stop() }
            do {
                _ = try await Connection(url: server.url).sendTransaction(sampleTx())
                XCTFail("HTTP \(status) must throw")
            } catch {
                XCTAssertEqual(error as? ActiveledgerError, .http(statusCode: status, body: body))
            }
        }
    }

    func testNon2xxIsNotMistakenForALedgerReply() async throws {
        // A 500 whose body is a valid committed reply must still be an error.
        let server = try serve(Self.committed, status: 500)
        defer { server.stop() }
        do {
            _ = try await Connection(url: server.url).sendTransaction(sampleTx())
            XCTFail("expected a throw")
        } catch {
            XCTAssertEqual(error as? ActiveledgerError, .http(statusCode: 500, body: Self.committed))
        }
    }

    func testNonObjectJSONReplyIsALedgerError() async throws {
        let server = try serve("[1,2]")
        defer { server.stop() }
        do {
            _ = try await Connection(url: server.url).sendTransaction(sampleTx())
            XCTFail("expected a throw")
        } catch {
            XCTAssertEqual(error as? ActiveledgerError, .ledger("Unexpected ledger response: [1,2]"))
        }
    }

    func testUnparseableReplyThrowsRatherThanReturning() async throws {
        let server = try serve("<html>not json</html>")
        defer { server.stop() }
        do {
            _ = try await Connection(url: server.url).sendTransaction(sampleTx())
            XCTFail("expected a throw")
        } catch {
            XCTAssertNil(error as? ActiveledgerError, "expected the JSON parser's error, got \(error)")
        }
    }

    // MARK: KeyHandler.onboardKey

    func testOnboardKeySendsSelfSignedTxAndSetsIdentity() async throws {
        let server = try serve(Self.committed)
        defer { server.stop() }
        let key = try keys.generateKey("me")
        XCTAssertNil(key.identity)

        let response = try await keys.onboardKey(key, connection: Connection(url: server.url))

        XCTAssertEqual(key.identity, "stream-abc")
        XCTAssertEqual(response.umid, "u1")

        let body = try XCTUnwrap(server.requests.first).bodyString
        let sent = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: Any])
        XCTAssertEqual(sent["$selfsign"] as? Bool, true)
        let tx = try XCTUnwrap(sent["$tx"] as? [String: Any])
        XCTAssertEqual(tx["$contract"] as? String, "onboard")
        XCTAssertEqual(tx["$namespace"] as? String, "default")
        let input = try XCTUnwrap((tx["$i"] as? [String: Any])?["me"] as? [String: Any])
        XCTAssertEqual(input["publicKey"] as? String, key.publicKey)
        XCTAssertEqual(input["type"] as? String, "secp256k1")

        // Self-signed: keyed by the label, and the signature is over the $tx
        // text as it went over the wire.
        let sigs = try XCTUnwrap(sent["$sigs"] as? [String: String])
        XCTAssertEqual(Array(sigs.keys), ["me"])
        XCTAssertTrue(crypto.verify(try sentTx(body), signature: sigs["me"]!,
                                    publicKey: key.publicKey, type: .secp256k1))
    }

    func testOnboardKeyHonoursContractAndNamespace() async throws {
        let server = try serve(Self.committed)
        defer { server.stop() }
        _ = try await keys.onboardKey(try keys.generateKey("me"), connection: Connection(url: server.url),
                                      contract: "custom", namespace: "ns")
        let tx = try sentTx(try XCTUnwrap(server.requests.first).bodyString)
        XCTAssertTrue(tx.hasPrefix(#"{"$contract":"custom","$i":"#), tx)
        XCTAssertTrue(tx.hasSuffix(#""$namespace":"ns"}"#), tx)
    }

    func testOnboardKeyMLDSA65OverTheWire() async throws {
        let server = try serve(Self.committed)
        defer { server.stop() }
        let key = try keys.generateKey("pq", type: .mlDsa65)

        try await keys.onboardKey(key, connection: Connection(url: server.url))

        let body = try XCTUnwrap(server.requests.first).bodyString
        XCTAssertTrue(body.contains(#""type":"ml-dsa-65""#), body)
        let sent = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: Any])
        let sig = try XCTUnwrap((sent["$sigs"] as? [String: String])?["pq"])
        XCTAssertEqual(Data(base64Encoded: sig)?.count, 3309)
        XCTAssertTrue(crypto.verify(try sentTx(body), signature: sig, publicKey: key.publicKey,
                                    type: .mlDsa65))
        XCTAssertFalse(crypto.verify(try sentTx(body) + " ", signature: sig, publicKey: key.publicKey,
                                     type: .mlDsa65))
    }

    // A key file written with the legacy "bitcoin"/"ethereum" type strings must
    // reach the node as "secp256k1": the legacy strings are never emitted.
    func testLegacyWireTypeIsSentAsSecp256k1() async throws {
        for legacy in ["bitcoin", "ethereum"] {
            let server = try serve(Self.committed)
            defer { server.stop() }
            let source = try keys.generateKey("legacy")
            let file = try JSONSerialization.data(withJSONObject: [
                "name": "legacy", "type": legacy,
                "key": ["pub": ["pkcs8pem": source.key.publicKey], "prv": ["pkcs8pem": source.key.privateKey]],
            ])
            let key = try JSONDecoder().decode(Key.self, from: file)

            try await keys.onboardKey(key, connection: Connection(url: server.url))

            let body = try XCTUnwrap(server.requests.first).bodyString
            XCTAssertTrue(body.contains(#""type":"secp256k1""#), body)
            XCTAssertFalse(body.contains(legacy), body)
            XCTAssertEqual(key.identity, "stream-abc")
        }
    }

    func testOnboardKeyRejectedByLedgerThrowsOnboardWithDetail() async throws {
        let server = try serve(Self.rejected)
        defer { server.stop() }
        let key = try keys.generateKey("me")
        do {
            try await keys.onboardKey(key, connection: Connection(url: server.url))
            XCTFail("expected a throw")
        } catch {
            XCTAssertEqual(error as? ActiveledgerError, .onboard(
                message: "Onboarding \"me\" created no identity: 1220 Signature Incorrect"))
        }
        XCTAssertNil(key.identity)
    }

    func testOnboardKeyWithNoCreatedStreamThrowsWithoutDetail() async throws {
        let server = try serve(
            #"{"$umid":"u","$summary":{"total":1,"vote":1,"commit":1},"$streams":{"new":[]}}"#)
        defer { server.stop() }
        let key = try keys.generateKey("me")
        do {
            try await keys.onboardKey(key, connection: Connection(url: server.url))
            XCTFail("expected a throw")
        } catch {
            XCTAssertEqual(error as? ActiveledgerError,
                           .onboard(message: "Onboarding \"me\" created no identity"))
        }
        XCTAssertNil(key.identity)
    }

    func testOnboardKeyPropagatesHTTPFailureAndKeepsExistingIdentity() async throws {
        let server = try serve("down", status: 500)
        defer { server.stop() }
        let key = try keys.generateKey("me")
        key.identity = "previous"
        do {
            try await keys.onboardKey(key, connection: Connection(url: server.url))
            XCTFail("expected a throw")
        } catch {
            XCTAssertEqual(error as? ActiveledgerError, .http(statusCode: 500, body: "down"))
        }
        XCTAssertEqual(key.identity, "previous")
    }

    func testOnboardedKeyCanThenSignAndSendAnIdentityKeyedTransaction() async throws {
        let server = try serve(Self.committed)
        defer { server.stop() }
        let key = try keys.generateKey("me")
        let conn = try Connection(url: server.url)
        try await keys.onboardKey(key, connection: conn)

        let handler = TransactionHandler()
        let tx = try handler.labelledTransaction(
            key: key, namespace: "default", contract: "demo", inputLabel: "in", stream: key.identity!)
        _ = try await handler.sendTransaction(tx, connection: conn)

        XCTAssertEqual(server.requests.count, 2)
        let second = server.requests[1].bodyString
        XCTAssertFalse(second.contains("$selfsign"), second)
        let sent = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(second.utf8)) as? [String: Any])
        // Keyed by the identity the first reply created, not the key name.
        let sigs = try XCTUnwrap(sent["$sigs"] as? [String: String])
        XCTAssertEqual(Array(sigs.keys), ["stream-abc"])
    }
}
