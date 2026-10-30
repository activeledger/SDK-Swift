import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A minimal HTTP/1.1 server on 127.0.0.1 for tests that need a real socket.
/// On Linux the SDK talks through AsyncHTTPClient, so URLProtocol stubbing is
/// not possible; this answers real requests instead and never leaves the host.
///
/// Self-contained (Foundation and the C socket API only) so the smoke test can
/// copy this one file into its consumer package.
///
/// One connection is served at a time, in order. Every request is recorded.
/// `stop()` closes the listener and joins the thread; callers must call it
/// (`defer { server.stop() }`), because the serving thread keeps the server alive.
final class LoopbackServer {
    struct Request {
        let method: String
        let path: String
        let headers: [String: String] // lower-cased names
        let body: Data
        var bodyString: String { String(decoding: body, as: UTF8.self) }
    }

    struct Reply {
        var body: String
        var status: Int
        init(_ body: String, status: Int = 200) { self.body = body; self.status = status }
    }

    /// `http://127.0.0.1:<port>`
    let url: String
    let port: Int

    private let handler: (Request) -> Reply
    private let listener: Int32
    private let lock = NSLock()
    private var recorded: [Request] = []
    private let finished = DispatchSemaphore(value: 0)
    private var stopped = false

    /// Binds an ephemeral port and starts serving. `handler` runs on the
    /// server thread.
    init(handler: @escaping (Request) -> Reply) throws {
        self.handler = handler
        #if canImport(Glibc)
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #else
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #endif
        guard fd >= 0 else { throw LoopbackError.socket("socket() failed, errno \(errno)") }

        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(fd, 8) == 0 else {
            close(fd)
            throw LoopbackError.socket("bind/listen failed, errno \(errno)")
        }

        var local = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        self.port = Int(UInt16(bigEndian: local.sin_port))
        self.url = "http://127.0.0.1:\(port)"
        self.listener = fd

        // Holds self strongly until the thread exits, so callers must stop().
        let thread = Thread { self.serve(fd) }
        thread.start()
    }

    /// Requests received so far, oldest first.
    var requests: [Request] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }

    /// Close the listener and wait for the server thread to exit. Idempotent.
    func stop() {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        lock.unlock()
        // shutdown() wakes a thread blocked in accept(); close() alone may not.
        shutdown(listener, Int32(SHUT_RDWR))
        finished.wait()
        close(listener)
    }

    // MARK: serving

    private func serve(_ fd: Int32) {
        defer { finished.signal() }
        while true {
            let conn = accept(fd, nil, nil)
            lock.lock(); let done = stopped; lock.unlock()
            if conn < 0 || done {
                if conn >= 0 { close(conn) }
                return
            }
            handle(conn)
            close(conn)
        }
    }

    private func handle(_ conn: Int32) {
        guard let request = readRequest(conn) else { return }
        lock.lock(); recorded.append(request); lock.unlock()
        let reply = handler(request)
        let payload = Data(reply.body.utf8)
        let head = "HTTP/1.1 \(reply.status) \(LoopbackServer.reason(reply.status))\r\n"
            + "Content-Type: application/json\r\nContent-Length: \(payload.count)\r\n"
            + "Connection: close\r\n\r\n"
        writeAll(conn, Data(head.utf8) + payload)
    }

    private func readRequest(_ conn: Int32) -> Request? {
        var buffer = Data()
        let terminator = Data("\r\n\r\n".utf8)
        var headEnd: Range<Data.Index>?
        while headEnd == nil {
            guard let chunk = readChunk(conn) else { return nil }
            buffer.append(chunk)
            headEnd = buffer.range(of: terminator)
        }
        let head = String(decoding: buffer[buffer.startIndex..<headEnd!.lowerBound], as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        let start = lines.removeFirst().split(separator: " ")
        guard start.count >= 2 else { return nil }
        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            headers[line[..<colon].lowercased()] =
                line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        let length = Int(headers["content-length"] ?? "0") ?? 0
        var body = Data(buffer[headEnd!.upperBound...])
        while body.count < length {
            guard let chunk = readChunk(conn) else { return nil }
            body.append(chunk)
        }
        return Request(method: String(start[0]), path: String(start[1]), headers: headers,
                       body: Data(body.prefix(length)))
    }

    private func readChunk(_ conn: Int32) -> Data? {
        var bytes = [UInt8](repeating: 0, count: 16 * 1024)
        let n = recv(conn, &bytes, bytes.count, 0)
        return n > 0 ? Data(bytes[0..<n]) : nil
    }

    private func writeAll(_ conn: Int32, _ data: Data) {
        var sent = 0
        let bytes = [UInt8](data)
        while sent < bytes.count {
            let n = bytes[sent...].withUnsafeBytes {
                send(conn, $0.baseAddress, $0.count, LoopbackServer.noSigPipe)
            }
            if n <= 0 { return }
            sent += n
        }
    }

    #if canImport(Glibc)
    private static let noSigPipe = Int32(MSG_NOSIGNAL)
    #else
    private static let noSigPipe: Int32 = 0
    #endif

    private static func reason(_ status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 400: return "Bad Request"
        case 404: return "Not Found"
        case 500: return "Internal Server Error"
        case 503: return "Service Unavailable"
        default: return "Status"
        }
    }
}

enum LoopbackError: Error { case socket(String) }
