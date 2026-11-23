import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Which URLs the SDK sends requests to.
///
/// Session JWTs, stamps, OTP codes and verification tokens travel in these requests, so plain
/// `http` is refused unless you opt in. Even then only loopback hosts are accepted, for a server
/// running on the development machine.
///
/// This check is independent of App Transport Security and runs first: it refuses an insecure URL
/// even when the app's `Info.plist` relaxes ATS (`NSAllowsArbitraryLoads`). A loopback `http` URL
/// that this policy lets through must still pass ATS; Apple's ATS rules exempt IP addresses and
/// unqualified host names such as `localhost`.
public enum ZeroXKeyTransportSecurity: Sendable, Equatable {
    /// `https` only (default).
    case requireHTTPS
    /// `https`, plus plain `http` to a loopback host: `localhost`, `127.0.0.0/8` in dotted-decimal
    /// form, or `::1`. An `http` URL with a user name or password is refused (`http://localhost@host`
    /// connects to `host`). Never ship this in a release build.
    case dangerouslyAllowInsecureLoopback

    /// Whether a request may be sent to `url`.
    public func allows(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(), let host = url.host, !host.isEmpty else { return false }
        switch scheme {
        case "https":
            return true
        case "http":
            return self == .dangerouslyAllowInsecureLoopback && url.user == nil && url.password == nil
                && Self.isLoopbackHost(host)
        default:
            return false
        }
    }

    /// Throws ``ZeroXKeyHttpError/insecureURL(_:)`` unless ``allows(_:)``.
    public func validate(_ url: URL) throws {
        guard allows(url) else { throw ZeroXKeyHttpError.insecureURL(Self.redacted(url)) }
    }

    /// `localhost`, a dotted-decimal IPv4 address in `127.0.0.0/8`, or the IPv6 loopback address
    /// (without zone ID). Case-insensitive; IPv6 with or without brackets.
    public static func isLoopbackHost(_ host: String) -> Bool {
        var h = host.lowercased()
        if h.hasPrefix("["), h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        if h == "localhost" { return true }
        let octets = h.split(separator: ".", omittingEmptySubsequences: false)
        if octets.count == 4, octets.allSatisfy({ (1...3).contains($0.count) && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) }) {
            return octets[0] == "127" && octets.allSatisfy { Int($0).map { $0 <= 255 } ?? false }
        }
        var address = in6_addr()
        guard h.contains(":"), !h.contains("%"), inet_pton(AF_INET6, h, &address) == 1 else { return false }
        return withUnsafeBytes(of: &address) { Array($0) } == [UInt8](repeating: 0, count: 15) + [1]
    }

    /// `url` without user name and password, for error messages.
    static func redacted(_ url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return "<invalid URL>" }
        components.user = nil
        components.password = nil
        return components.string ?? "<invalid URL>"
    }
}
