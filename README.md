<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23-dark.png">
  <img src="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23.png" alt="Activeledger" width="300"/>
</picture>

[![licence](https://img.shields.io/badge/licence-MIT-blue)](https://github.com/activeledger/SDK-Swift/blob/main/LICENSE)

# Activeledger SDK for Swift

Swift and iOS SDK for [Activeledger](https://github.com/activeledger/activeledger),
with post-quantum identity support.

A port of the [JavaScript SDK](https://github.com/activeledger/SDK-JS): the
same handlers (`KeyHandler`, `TransactionHandler`, `PayloadHandler`,
`Connection`), the same key file format, and byte-for-byte the same
signatures, checked against the JavaScript SDK's cross-language vectors.

Requires Swift 5.9+ and a platform with `swift-crypto` (macOS, iOS, Linux).

---

## Install

Swift Package Manager - add the dependency to `Package.swift`:

```swift
.package(url: "https://github.com/activeledger/SDK-Swift.git", from: "1.0.0")
```

and the product to your target:

```swift
.product(name: "Activeledger", package: "SDK-Swift")
```

For Falcon-512 as well, add the add-on product (it brings the native Falcon
code):

```swift
.product(name: "ActiveledgerFalcon", package: "SDK-Swift")
```

In Xcode: **File → Add Package Dependencies…** and paste the repository URL.

## Quick start

```swift
import Activeledger

let ledger = try Activeledger("http://localhost:5260")

let key = try ledger.generateKey("identity")
try await ledger.onboard(key)
print(key.identity!)   // the new identity's stream id
```

The `Activeledger` value wires up the four handlers - `keys`, `transactions`,
`payloads` and `connection` - and exposes shorthands for the common calls.
Anything the shorthands do not cover is a handler call away.

---

## Key types

| Key type | Wire string | Public | Private | Signature | Encoding |
|---|---|---|---|---|---|
| secp256k1 | `secp256k1` | 33 or 65 | 32 | ~70-72, variable DER | `0x` hex |
| ML-DSA-65 | `ml-dsa-65` | 1952 | 4032 | 3309 | base64 |
| Falcon-512 | `falcon-512` | 897 | 1281 | 649-662, variable | base64 |
| RSA (legacy) | `rsa` | PEM | PEM | 256 for 2048-bit | PEM |

Use **secp256k1** unless the identity must outlive a cryptographically
relevant quantum computer: roughly **22x smaller** per transaction than
ML-DSA-65, and every byte is stored on the ledger permanently and replicated
to every node. Between the post-quantum schemes, **Falcon-512** signatures are
about a fifth the size of ML-DSA-65's; ML-DSA-65 is the finalised standard.

```swift
let keys = KeyHandler()

let ec = try keys.generateKey("me")                        // secp256k1, uncompressed
let ec33 = try keys.generateKey("me", compressed: true)    // 33-byte public key

ec.key.publicKey    // "0x04a1b2..." - give this to the ledger
ec.key.privateKey   // keep this
```

- **secp256k1 keys are `0x`-prefixed hex; post-quantum keys are base64** of
  the raw algorithm bytes. The prefix is required, not tolerated.
- **secp256k1 signing is RFC 6979 deterministic and low-S**, so its signatures
  are byte-identical to `@noble/curves` for the same key and message.
  **Verification accepts high-S**, because the ledger verifies through
  OpenSSL and produces high-S freely.
- **RSA** keys (a network's contract deployer, say) sign and verify from PEM.
  They cannot be generated. secp256k1 keys exported as PEM by older SDKs work
  too.
- `KeyType.fromWire` parses `bitcoin` and `ethereum` as secp256k1, because
  the ledger routes them to identical verification. They are never emitted.

### Post-quantum

Both schemes are backed by the vendored [PQClean](https://github.com/PQClean/PQClean)
`clean` implementations — the same code liboqs wraps — so keys and signatures
are byte-identical to the JavaScript and Dart SDKs, checked against the
cross-language vectors. **ML-DSA-65 is built into the core** and always
available. **Falcon-512 is the `ActiveledgerFalcon` add-on**, because it
carries native code; enable it once at startup:

```swift
import Activeledger
import ActiveledgerFalcon

ActiveledgerFalcon.enable()   // once, at startup
let key = try keys.generateKey("me", type: .preferredPostQuantum)  // Falcon-512
```

`KeyType.preferredPostQuantum` resolves to Falcon-512 once the add-on is
enabled and ML-DSA-65 otherwise, so the same code runs either way. Key
generation is deterministic from the derived seed (ML-DSA reads a 32-byte ξ,
Falcon a 48-byte seed expanded with SHAKE-256), which is what makes one
recovery phrase reproduce the same post-quantum identity in every SDK.
**Requires Activeledger 4.7.0+** on the network side.

---

## Seeds and recovery phrases

```swift
let keys = KeyHandler()

let key = try keys.generateBip39Key("me")
print(key.phrase!)                                        // 12 words - store them

let same = try keys.restoreBip39Key("me", phrase: key.phrase!)
let withPass = try keys.restoreBip39Key("me", phrase: phrase, passphrase: "extra words")

let fromSeed = try keys.generateKeyFromSeed("me", seed: seed32)
```

The same seed gives the same identity in **every** Activeledger SDK, which
makes a seed the portable private-key format. One phrase can back a
secp256k1, an ml-dsa-65 and a falcon-512 identity at once, each derived
independently:

| Type | Seed from the BIP-39 seed `S` |
|---|---|
| `secp256k1` | `HMAC-SHA512("Bitcoin seed", S)[0..32]` |
| `ml-dsa-65` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)` |
| `falcon-512` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)` |

`Recovery` exposes each step - `validate`, `toSeed`, `deriveSeed`,
`deriveBip32MasterKey`, `generateMnemonic` - so you can see which one differs
when a recovered identity is not the expected one.

- A seed of the wrong length is **refused, not padded**: a padded seed is a
  different identity, not a malformed one.
- For secp256k1 the seed **is** the private scalar, so a seed of zero or at or
  above the curve order is refused rather than reduced mod *n*.
- Phrases are validated, wordlist **and** checksum. A mistyped phrase that is
  not checked derives a valid key for an identity nobody owns. Pass
  `validate: false` only to derive from a string that is not a mnemonic.
- `legacy: true` recovers a phrase made by the old `@activeledger/sdk-bip39`
  package (SHA256 of the phrase). Recovery only, never for new keys.

---

## Transactions

```swift
let transactions = TransactionHandler()

let tx = try transactions.labelledTransaction(
    key: key,                         // must be onboarded
    namespace: "mynamespace",
    contract: "mycontract",
    inputLabel: "input",
    stream: key.identity!,
    inputData: .object([("message", .string("hello"))]),
    outputs: .object([("target-stream", .object([("amount", .integer(10))]))]),
    entry: "update")                  // optional $entry

let response = try await ledger.send(tx)
if !response.committed { throw ActiveledgerError.ledger(response.errors.joined(separator: "; ")) }

response.created     // streams created
response.responses   // returnToRemote values
```

For any other shape - several inputs, several signers - build the `$tx`
yourself and sign it once per key. The `$tx` body is an ordered `JSONValue`,
because the ledger does not sort keys and signatures cover the exact bytes:

```swift
let tx = Transaction(tx: .object([
    ("$namespace", .string("ns")),
    ("$contract", .string("c")),
    ("$i", .object([(alice.identity!, .object([])), (bob.identity!, .object([]))])),
]))
try transactions.signTransaction(tx, key: alice)
try transactions.signTransaction(tx, key: bob)
```

`$sigs` is keyed by identity, or by the `$i` label for a self-signed
transaction, which is what the ledger looks up.

### Reading state

There is no separate read API: a node's storage service listens only on the
node's own host. Name the streams in `readonly` (`$r`) and have the contract
return values with `returnToRemote`; they arrive in `response.responses`.

---

## Signing payloads

```swift
let payloads = PayloadHandler()

let order: JSONValue = .object([("pair", .string("VNR/USDT")), ("side", .string("sell"))])
let signature = try payloads.sign(order, key: key)
payloads.verify(order, signature: signature, publicKey: key.publicKey, type: .secp256k1)   // Bool
```

`payloads.canonical(order)` is the exact string signed. It is key-order
sensitive, so persist it alongside the signature and verify that.

## Key files

```swift
try keys.exportKey(key, to: "keys", createDir: true)     // keys/<name>.json
let loaded = try keys.importKey("keys/identity.json")
```

The format is the JavaScript SDK's, so key files move between the two.

## Signing elsewhere

Every handler takes a `CryptoProvider`. Implement one to sign in the Secure
Enclave or an HSM, or register a custom `PostQuantumScheme` with
`PostQuantum.register`.

---

## Things that will bite you

**Always send the key type.** The ledger defaults a missing `type` to `rsa`.
This SDK always sends it; if you hand-build an envelope, do the same.

**A rejected transaction is HTTP 200.** Check `response.committed`, never the
status code.

**Errors are unhelpful by design.** A wrong type string, a wrong-length key or
signed bytes differing by one escape all come back as **1220 "Signature
Incorrect"**. This SDK validates key lengths and type strings up front so
these fail locally with a message naming the problem.

**Signatures cover `$tx` only**, not the envelope. `tx.signedString` is exactly
what was signed, which is the fastest way to diagnose a 1220.

## Canonical JSON

Signatures cover the exact bytes of JavaScript's `JSON.stringify($tx)`. Swift's
`JSONEncoder` differs from it - key order, number formatting (`1.0` versus
`1`, `1e20` versus `100000000000000000000`) - so `canonicalJSON` reproduces
`JSON.stringify` exactly, using the ordered `JSONValue` type. It is checked
against the cross-language number vectors, and it refuses `NaN`, infinities and
integers a JavaScript number cannot hold, rather than signing something you
did not write.

---

## Testing

```bash
swift test
```

The unit tests run against the cross-language vectors under `vectors/`, the
same fixtures the JavaScript and Dart SDKs use.

## Licence

MIT
