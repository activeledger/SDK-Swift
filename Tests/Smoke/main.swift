// Smoke test: a consumer package that depends on Activeledger by path and uses
// only its public API. Runs against LoopbackServer (copied in by smoke.sh).
import Foundation
import Activeledger

var failures = 0
func check(_ condition: @autoclosure () -> Bool, _ what: String) {
    if condition() { print("ok   \(what)") } else { print("FAIL \(what)"); failures += 1 }
}

let committed = """
    {"$umid":"u1","$summary":{"total":1,"vote":1,"commit":1,"errors":[]},\
    "$streams":{"new":[{"id":"smoke-stream","name":"k"}],"updated":[]}}
    """
let rejected = """
    {"$umid":"u2","$summary":{"total":1,"vote":0,"commit":0,"errors":["1220 Signature Incorrect"]},\
    "$streams":{"new":[],"updated":[]}}
    """

// A contract called "reject" is answered with a rejection (still HTTP 200).
let server = try LoopbackServer { request in
    .init(request.bodyString.contains("\"$contract\":\"reject\"") ? rejected : committed)
}
defer { server.stop() }

let connection = try Connection(url: server.url)
let keys = KeyHandler()
let handler = TransactionHandler()
let crypto = DefaultCryptoProvider()

for type in [KeyType.secp256k1, .mlDsa65] {
    let key = try keys.generateKey("smoke-\(type.wire)", type: type)
    try await keys.onboardKey(key, connection: connection)
    check(key.identity == "smoke-stream", "\(type.wire): onboarded, identity set")

    let tx = try handler.labelledTransaction(
        key: key, namespace: "default", contract: "demo", inputLabel: "in", stream: key.identity!,
        inputData: .object([("value", .integer(42))]))
    let signature = tx.sigs.first?.1 ?? ""
    check(tx.sigs.first?.0 == "smoke-stream", "\(type.wire): signature keyed by identity")
    check(crypto.verify(tx.signedString, signature: signature, publicKey: key.publicKey, type: type),
          "\(type.wire): signature verifies")
    check(!crypto.verify(tx.signedString + " ", signature: signature, publicKey: key.publicKey, type: type),
          "\(type.wire): altered payload does not verify")

    let committedReply = try await connection.sendTransaction(tx)
    check(committedReply.committed && committedReply.umid == "u1", "\(type.wire): committed reply")

    let bad = try handler.labelledTransaction(
        key: key, namespace: "default", contract: "reject", inputLabel: "in", stream: key.identity!)
    let rejectedReply = try await connection.sendTransaction(bad)
    check(!rejectedReply.committed && rejectedReply.errors == ["1220 Signature Incorrect"],
          "\(type.wire): rejected HTTP 200 reply is not committed")
}

// 2 key types x (onboard + committed + rejected)
check(server.requests.count == 6, "server saw 6 requests (got \(server.requests.count))")
check(server.requests.allSatisfy { $0.method == "POST" }, "all requests were POST")

if failures > 0 { print("SMOKE FAILED: \(failures) check(s)"); exit(1) }
print("SMOKE OK")
