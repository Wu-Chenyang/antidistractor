/// ControlServer.swift
/// Local HTTP server exposing antidistractor blocking functions as a REST API.
///
/// Listens on localhost:PORT (default 18964) so the host multi-platform app
/// can call blocking operations over HTTP — same pattern as the macOS Unix socket
/// control server, but using HTTP for cross-language compatibility.
///
/// All endpoints accept and return JSON. Authentication is by shared secret
/// (configured at startup) to prevent other local processes from calling the API.
///
/// Endpoints:
///   POST /block          { "domains": [...], "bundle_ids": [...], "category_ids": [...] }
///   POST /unblock        { "domains": [...], "bundle_ids": [...] }
///   POST /clear          {}
///   POST /authorize      {}   — triggers FamilyControls auth prompt
///   GET  /status         → { "ok": true, "authorized": bool, "blocking": bool, "blocklist": {...} }
///
/// Uses only Foundation (URLSession + CFSocket) — no third-party dependencies.

import Foundation
import AntidistractorCore

// MARK: - Request / Response types

struct ControlRequest: Codable {
    var domains: [String]?
    var bundleIDs: [String]?
    var categoryIDs: [Int]?

    enum CodingKeys: String, CodingKey {
        case domains
        case bundleIDs = "bundle_ids"
        case categoryIDs = "category_ids"
    }
}

struct ControlResponse: Codable {
    var ok: Bool
    var error: String?
    var authorized: Bool?
    var blocking: Bool?
    var blocklist: BlocklistPayload?
}

struct BlocklistPayload: Codable {
    var domains: [String]
    var bundleIDs: [String]
    var categoryIDs: [Int]

    enum CodingKeys: String, CodingKey {
        case domains
        case bundleIDs = "bundle_ids"
        case categoryIDs = "category_ids"
    }
}

// MARK: - ControlServer

public final class ControlServer: @unchecked Sendable {

    // MARK: - Configuration

    public static let defaultPort: UInt16 = 18964

    /// Shared secret — set this to a random value at app launch and share it
    /// with the host app via a secure channel (e.g. Keychain, QR code, or
    /// a one-time pairing flow). Requests without this header are rejected.
    public var sharedSecret: String = ""

    private let port: UInt16
    private var serverSocket: CFSocket?
    private var runLoopSource: CFRunLoopSource?
    private let queue = DispatchQueue(label: "com.antidistractor.server", qos: .utility)

    // MARK: - Init

    public init(port: UInt16 = defaultPort) {
        self.port = port
    }

    // MARK: - Lifecycle

    /// Start the HTTP server. Call once at app launch.
    public func start() throws {
        var context = CFSocketContext(
            version: 0,
            info: Unmanaged.passRetained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        serverSocket = CFSocketCreate(
            kCFAllocatorDefault,
            PF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
            CFSocketCallBackType.acceptCallBack.rawValue,
            acceptCallback,
            &context
        )

        guard let socket = serverSocket else {
            throw ServerError.socketCreationFailed
        }

        // Allow address reuse
        var yes: Int32 = 1
        setsockopt(CFSocketGetNative(socket), SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = INADDR_LOOPBACK.bigEndian  // localhost only
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)

        let addrData = withUnsafeBytes(of: &addr) { Data($0) } as CFData
        let err = CFSocketSetAddress(socket, addrData)
        guard err == .success else {
            throw ServerError.bindFailed(port: port)
        }

        runLoopSource = CFSocketCreateRunLoopSource(kCFAllocatorDefault, socket, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), runLoopSource, .defaultMode)

        print("[antidistractor-server] Listening on localhost:\(port)")
    }

    /// Stop the server.
    public func stop() {
        if let source = runLoopSource {
            CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .defaultMode)
        }
        if let socket = serverSocket {
            CFSocketInvalidate(socket)
        }
        serverSocket = nil
        runLoopSource = nil
    }

    // MARK: - Request handling

    func handleConnection(nativeSocket: CFSocketNativeHandle) {
        queue.async { [weak self] in
            guard let self else { return }
            defer { close(nativeSocket) }

            // Read raw HTTP request
            var buffer = [UInt8](repeating: 0, count: 8192)
            let bytesRead = read(nativeSocket, &buffer, buffer.count - 1)
            guard bytesRead > 0 else { return }

            let raw = String(bytes: buffer[..<bytesRead], encoding: .utf8) ?? ""
            self.processRequest(raw, socket: nativeSocket)
        }
    }

    private func processRequest(_ raw: String, socket: CFSocketNativeHandle) {
        // Parse HTTP request line
        let lines = raw.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return }
        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return }
        let method = parts[0]
        let path = parts[1]

        // Extract headers
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard !line.isEmpty else { break }
            let headerParts = line.components(separatedBy: ": ")
            if headerParts.count >= 2 {
                headers[headerParts[0].lowercased()] = headerParts[1...].joined(separator: ": ")
            }
        }

        // Authenticate (skip if no secret configured)
        if !sharedSecret.isEmpty {
            let token = headers["x-antidistractor-secret"] ?? ""
            guard token == sharedSecret else {
                sendResponse(socket: socket, status: 401, body: ControlResponse(ok: false, error: "unauthorized"))
                return
            }
        }

        // Extract body
        let bodyStart = raw.range(of: "\r\n\r\n").map { raw.index($0.upperBound, offsetBy: 0) }
        let bodyString = bodyStart.map { String(raw[$0...]) } ?? ""
        let bodyData = bodyString.data(using: .utf8) ?? Data()

        // Route
        let response: ControlResponse
        switch (method, path) {
        case ("POST", "/block"):
            response = handleBlock(body: bodyData)
        case ("POST", "/unblock"):
            response = handleUnblock(body: bodyData)
        case ("POST", "/clear"):
            response = handleClear()
        case ("POST", "/authorize"):
            response = handleAuthorize()
        case ("GET", "/status"):
            response = handleStatus()
        default:
            response = ControlResponse(ok: false, error: "unknown endpoint: \(method) \(path)")
        }

        sendResponse(socket: socket, status: response.ok ? 200 : 400, body: response)
    }

    // MARK: - Handlers

    private func handleBlock(body: Data) -> ControlResponse {
        guard let req = try? JSONDecoder().decode(ControlRequest.self, from: body) else {
            return ControlResponse(ok: false, error: "invalid JSON body")
        }

        DispatchQueue.main.sync {
            if let domains = req.domains, !domains.isEmpty {
                BlockingManager.shared.addDomains(domains)
            }
            if let ids = req.bundleIDs, !ids.isEmpty {
                BlockingManager.shared.addBundleIDs(ids)
            }
            if let cats = req.categoryIDs, !cats.isEmpty {
                BlockingManager.shared.addCategories(cats)
            }
        }

        return ControlResponse(ok: true)
    }

    private func handleUnblock(body: Data) -> ControlResponse {
        guard let req = try? JSONDecoder().decode(ControlRequest.self, from: body) else {
            return ControlResponse(ok: false, error: "invalid JSON body")
        }

        DispatchQueue.main.sync {
            if let domains = req.domains { BlockingManager.shared.removeDomains(domains) }
            if let ids = req.bundleIDs   { BlockingManager.shared.removeBundleIDs(ids) }
        }

        return ControlResponse(ok: true)
    }

    private func handleClear() -> ControlResponse {
        DispatchQueue.main.sync {
            BlockingManager.shared.clearBlocklist()
        }
        return ControlResponse(ok: true)
    }

    private func handleAuthorize() -> ControlResponse {
        // Authorization must happen on main actor — schedule and return immediately.
        // The caller should poll /status to check when authorized.
        Task { @MainActor in
            await BlockingManager.shared.requestAuthorization()
        }
        return ControlResponse(ok: true, error: nil)
    }

    private func handleStatus() -> ControlResponse {
        var authorized = false
        var blocking = false
        var list = Blocklist()

        DispatchQueue.main.sync {
            BlockingManager.shared.checkAuthorizationStatus()
            authorized = BlockingManager.shared.isAuthorized
            blocking = BlockingManager.shared.isBlocking
            list = BlocklistStore.shared.load()
        }

        return ControlResponse(
            ok: true,
            authorized: authorized,
            blocking: blocking,
            blocklist: BlocklistPayload(
                domains: Array(list.domains).sorted(),
                bundleIDs: Array(list.bundleIDs).sorted(),
                categoryIDs: Array(list.categoryIDs).sorted()
            )
        )
    }

    // MARK: - HTTP response

    private func sendResponse(socket: CFSocketNativeHandle, status: Int, body: ControlResponse) {
        guard let data = try? JSONEncoder().encode(body) else { return }
        let bodyStr = String(data: data, encoding: .utf8) ?? "{}"
        let response = """
        HTTP/1.1 \(status) \(status == 200 ? "OK" : "Error")\r\n\
        Content-Type: application/json\r\n\
        Content-Length: \(bodyStr.utf8.count)\r\n\
        Connection: close\r\n\
        \r\n\
        \(bodyStr)
        """
        _ = response.withCString { ptr in
            write(socket, ptr, strlen(ptr))
        }
    }

    // MARK: - Errors

    enum ServerError: Error {
        case socketCreationFailed
        case bindFailed(port: UInt16)
    }
}

// MARK: - CFSocket accept callback

private let acceptCallback: CFSocketCallBack = { socket, type, address, data, info in
    guard let info,
          type == .acceptCallBack,
          let data else { return }

    let server = Unmanaged<ControlServer>.fromOpaque(info).takeUnretainedValue()
    let nativeHandle = data.load(as: CFSocketNativeHandle.self)
    server.handleConnection(nativeSocket: nativeHandle)
}
