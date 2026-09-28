import Foundation
import Activeledger

/// The Falcon-512 add-on.
///
/// Falcon-512 signatures are about a fifth the size of ML-DSA-65's, which
/// matters because every signature byte is stored on the ledger permanently.
/// It is an add-on because it carries native code (the vendored PQClean
/// Falcon implementation); ML-DSA-65 is always available in the core.
///
/// Call ``enable()`` once at startup, before generating or using a Falcon key.
/// After that, `KeyType.preferredPostQuantum` resolves to Falcon-512.
///
/// ```swift
/// import Activeledger
/// import ActiveledgerFalcon
///
/// ActiveledgerFalcon.enable()   // once, at startup
/// let key = try ledger.generateKey("me", type: .preferredPostQuantum)
/// ```
public enum ActiveledgerFalcon {
    /// Register Falcon-512 with the shared ``PostQuantum`` registry. Idempotent.
    public static func enable() {
        PostQuantum.register(Falcon512Scheme(), for: .falcon512)
    }
}
