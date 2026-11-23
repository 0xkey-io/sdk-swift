import Foundation

/// A recorded request as seen on the wire.
public struct RecordedRequest: Sendable {
    public let url: URL
    public let method: String
    public let headers: [String: String]
    public let body: Data

    public var path: String { url.path }
    public var bodyString: String { String(decoding: body, as: UTF8.self) }
    public func header(_ name: String) -> String? {
        headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
    public var json: [String: Any] {
        (try? JSONSerialization.jsonObject(with: body) as? [String: Any]) ?? [:]
    }
}

public struct MockResponse: Sendable {
    public let status: Int
    public let body: Data
    public let headers: [String: String]

    public init(status: Int = 200, body: Data, headers: [String: String] = ["Content-Type": "application/json"]) {
        self.status = status
        self.body = body
        self.headers = headers
    }

    public static func json(_ object: Any, status: Int = 200) -> MockResponse {
        MockResponse(status: status, body: try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }

    public static func text(_ text: String, status: Int) -> MockResponse {
        MockResponse(status: status, body: Data(text.utf8), headers: ["Content-Type": "text/plain; charset=utf-8"])
    }
}

/// Offline HTTP server stub. Each test registers its own unique host (see `MockServer`),
/// so tests can run in parallel. Requests to unregistered hosts fail with
/// `URLError(.cannotConnectToHost)`; the protocol never forwards to the network.
public final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    public typealias Handler = @Sendable (RecordedRequest) throws -> MockResponse

    nonisolated(unsafe) private static var handlers: [String: Handler] = [:]
    private static let lock = NSLock()

    static func register(host: String, handler: @escaping Handler) {
        lock.withLock { handlers[host] = handler }
    }

    static func unregister(host: String) {
        lock.withLock { handlers[host] = nil }
    }

    static func handler(for host: String) -> Handler? {
        lock.withLock { handlers[host] }
    }

    public override class func canInit(with request: URLRequest) -> Bool { true }
    public override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    public override func startLoading() {
        guard let url = request.url, let host = url.host, let handler = Self.handler(for: host) else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
            return
        }
        let recorded = RecordedRequest(
            url: url, method: request.httpMethod ?? "GET",
            headers: request.allHTTPHeaderFields ?? [:], body: Self.readBody(request))
        do {
            let r = try handler(recorded)
            let response = HTTPURLResponse(url: url, statusCode: r.status, httpVersion: "HTTP/1.1", headerFields: r.headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: r.body)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    public override func stopLoading() {}

    static func readBody(_ request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buffer, maxLength: buffer.count)
            if n <= 0 { break }
            data.append(buffer, count: n)
        }
        return data
    }

    /// A URLSession that only talks to `MockURLProtocol`.
    public static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        config.urlCache = nil
        return URLSession(configuration: config)
    }
}

/// A route table bound to unique hosts for one test. Records every request.
public final class MockServer: @unchecked Sendable {
    public typealias Route = @Sendable (RecordedRequest, Int) throws -> MockResponse

    public let apiHost: String
    public let authProxyHost: String
    public let session: URLSession
    private let lock = NSLock()
    private var routes: [String: Route] = [:]
    private var hits: [String: Int] = [:]
    private var _requests: [RecordedRequest] = []

    /// - Parameter apiHost: host of the API routes; default a unique `*.mock.invalid` name. Give a
    ///   fixed one (e.g. a loopback name) only in a single test.
    public init(apiHost: String? = nil) {
        let id = UUID().uuidString.lowercased()
        self.apiHost = apiHost ?? "api-\(id).mock.invalid"
        authProxyHost = "authproxy-\(id).mock.invalid"
        session = MockURLProtocol.session()
        let handler: MockURLProtocol.Handler = { [unowned self] req in try self.handle(req) }
        MockURLProtocol.register(host: self.apiHost, handler: handler)
        MockURLProtocol.register(host: authProxyHost, handler: handler)
    }

    deinit {
        MockURLProtocol.unregister(host: apiHost)
        MockURLProtocol.unregister(host: authProxyHost)
    }

    public var apiURL: URL { URL(string: "https://\(apiHost)")! }
    public var authProxyURL: URL { URL(string: "https://\(authProxyHost)")! }

    /// Registers a route for `path`; the closure gets the request and its 0-based hit index.
    public func on(_ path: String, _ route: @escaping Route) {
        lock.withLock { routes[path] = route }
    }

    public func on(_ path: String, respond: MockResponse) {
        on(path) { _, _ in respond }
    }

    public var requests: [RecordedRequest] { lock.withLock { _requests } }

    public func requests(to path: String) -> [RecordedRequest] { requests.filter { $0.path == path } }

    func handle(_ req: RecordedRequest) throws -> MockResponse {
        let (route, n): (Route?, Int) = lock.withLock {
            _requests.append(req)
            let n = hits[req.path, default: 0]
            hits[req.path] = n + 1
            return (routes[req.path], n)
        }
        guard let route else {
            return .json(["code": 5, "message": "no mock route for \(req.path)", "details": []], status: 404)
        }
        return try route(req, n)
    }
}
