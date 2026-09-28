import Foundation
import Activeledger
import ActiveledgerFalcon

/// A tiny, runnable end-to-end example: connect, generate a key, onboard it,
/// and send a transaction signed by the new identity.
///
///     swift run Example                                   # secp256k1, default node
///     swift run Example http://127.0.0.1:5510             # a node the test network prints
///     swift run Example http://127.0.0.1:5510 falcon-512  # a post-quantum identity
///
/// It cannot start a ledger for you: run one first, e.g. from an `activeledger`
/// checkout, `npm run test:network:serve`, then pass a URL it prints.
@main
struct Example {
    static func main() async {
        ActiveledgerFalcon.enable()   // register Falcon-512 (ML-DSA is built in)

        let args = CommandLine.arguments
        let url = args.count > 1 ? args[1]
            : ProcessInfo.processInfo.environment["AL_NODE"] ?? "http://127.0.0.1:5260"

        let type: KeyType
        if args.count > 2 {
            guard let parsed = try? KeyType.fromWire(args[2]) else {
                fail("unknown key type '\(args[2])' - use secp256k1, ml-dsa-65 or falcon-512")
            }
            type = parsed
        } else {
            type = .secp256k1
        }

        print("Activeledger SDK for Swift - example")
        print("  node:     \(url)")
        print("  key type: \(type.wire)\n")

        do {
            let ledger = try Activeledger(url)

            print("1. Generating a \(type.wire) key ...")
            let key = try ledger.generateKey("example", type: type)
            print("   public key: \(shorten(key.publicKey))")

            print("2. Onboarding - creating the identity on the ledger ...")
            let onboard = try await ledger.onboard(key)
            guard onboard.committed, let identity = key.identity else {
                fail("onboard was not committed: \(describe(onboard.errors))")
            }
            print("   identity (stream id): \(identity)")

            print("3. Sending a transaction signed by the new identity ...")
            let tx = try ledger.transactions.labelledTransaction(
                key: key, namespace: "default", contract: "namespace",
                inputLabel: identity, stream: identity,
                inputData: .object([("namespace", .string("example\(epoch())"))]))
            let response = try await ledger.send(tx)
            guard response.committed else {
                fail("transaction not committed: \(describe(response.errors))")
            }
            print("   committed  (umid: \(response.umid ?? "n/a"))\n")

            print("Done. secp256k1, ML-DSA-65 and Falcon-512 all work the same way -")
            print("re-run with a type argument, e.g.:  swift run Example \(url) falcon-512")
        } catch {
            connectionHint(url, error)
        }
    }

    // MARK: helpers

    private static func epoch() -> Int { Int(Date().timeIntervalSince1970) }

    private static func shorten(_ s: String) -> String {
        s.count <= 24 ? s : "\(s.prefix(12))...\(s.suffix(8)) (\(s.count) chars)"
    }

    private static func describe(_ errors: [String]) -> String {
        errors.isEmpty ? "(no error detail)" : errors.joined(separator: "; ")
    }

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("error: \(message)\n".utf8))
        exit(1)
    }

    private static func connectionHint(_ url: String, _ error: Error) -> Never {
        fail("""
            could not reach a node at \(url): \(error)

            Start a local Activeledger network first - from an activeledger checkout:
                npm run test:network:serve
            then re-run against a URL it prints, for example:
                swift run Example http://127.0.0.1:5510
            """)
    }
}
