#if canImport(Network)
import Foundation
import Network
import XCTest
@testable import OpenPlanCore

final class PlanLoopbackTests: XCTestCase {
    func testLocalCallbackRejectsInvalidStateAndAcceptsValidState() async throws {
        let server = PlanLoopback()
        let state = String(repeating: "q", count: 40)
        let redirect = try await server.start(state: state)
        defer { server.cancel() }
        XCTAssertEqual(redirect.host, "127.0.0.1")
        XCTAssertEqual(redirect.path, "/auth/callback")

        let bad = URL(string: "\(redirect.absoluteString)?code=test&state=incorrect&client_id=oaiapp_test")!
        let (_, badResponse) = try await URLSession.shared.data(from: bad)
        XCTAssertEqual((badResponse as? HTTPURLResponse)?.statusCode, 400)

        // Same-state requests with a missing code or duplicate parameters
        // must NOT consume the one-use callback listener.
        let malformed = URL(string: "\(redirect.absoluteString)?state=\(state)&client_id=oaiapp_test")!
        let (_, malformedResponse) = try await URLSession.shared.data(from: malformed)
        XCTAssertEqual((malformedResponse as? HTTPURLResponse)?.statusCode, 400)

        let duplicate = URL(string: "\(redirect.absoluteString)?state=\(state)&state=\(state)&code=test&client_id=oaiapp_test")!
        let (_, duplicateResponse) = try await URLSession.shared.data(from: duplicate)
        XCTAssertEqual((duplicateResponse as? HTTPURLResponse)?.statusCode, 400)

        let good = URL(string: "\(redirect.absoluteString)?code=test&state=\(state)&client_id=oaiapp_test")!
        let (_, goodResponse) = try await URLSession.shared.data(from: good)
        XCTAssertEqual((goodResponse as? HTTPURLResponse)?.statusCode, 200)
        let received = try await server.wait()
        XCTAssertEqual(received.absoluteString, good.absoluteString)
    }
}
#endif
