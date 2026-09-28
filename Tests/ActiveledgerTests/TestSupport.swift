import Foundation

/// Locates the repo-root `vectors/` directory from a test source path, so the
/// cross-language vectors can be loaded without bundling them as a package
/// resource. Layout: <root>/Tests/ActiveledgerTests/<thisFile>.
enum Vectors {
    static var directory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // ActiveledgerTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo root
            .appendingPathComponent("vectors")
    }

    static func load(_ name: String) throws -> [String: Any] {
        let url = directory.appendingPathComponent(name)
        let data = try Data(contentsOf: url)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }
}
