import XCTest
@testable import OpenPlanCore

final class PlanSSETests: XCTestCase {
    func testIncrementalTextUntilCompleted() throws {
        var decoder = PlanEventDecoder()
        XCTAssertNil(try decoder.acceptLine("event: response.output_text.delta"))
        XCTAssertNil(try decoder.acceptLine("data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}"))
        XCTAssertEqual(try decoder.acceptLine(""), "Hello")
        XCTAssertNil(try decoder.acceptLine("data: {\"type\":\"response.output_text.delta\",\"delta\":\" world\"}"))
        XCTAssertEqual(try decoder.acceptLine(""), " world")
        XCTAssertNil(try decoder.acceptLine("data: {\"type\":\"response.completed\"}"))
        XCTAssertNil(try decoder.acceptLine(""))
        XCTAssertEqual(try decoder.endOfStream(), "Hello world")
    }

    func testInterruptedStreamIsFailure() throws {
        var decoder = PlanEventDecoder()
        XCTAssertNil(try decoder.acceptLine("data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}"))
        XCTAssertEqual(try decoder.acceptLine(""), "partial")
        XCTAssertThrowsError(try decoder.endOfStream()) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.missingCompletion))
        }
    }

    func testRateLimitMidStreamDoesNotSucceed() throws {
        var decoder = PlanEventDecoder()
        XCTAssertNil(try decoder.acceptLine("data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\"}}}"))
        XCTAssertThrowsError(try decoder.acceptLine("")) { error in
            XCTAssertEqual(error as? PlanError, .usageUnavailable)
        }
    }

    func testIncompleteAndFailed() throws {
        var decoder = PlanEventDecoder()
        XCTAssertNil(try decoder.acceptLine("data: {\"type\":\"response.incomplete\"}"))
        XCTAssertThrowsError(try decoder.acceptLine("")) { error in
            XCTAssertEqual(error as? PlanError, .incompleteResponse)
        }
    }

    func testOversizedEventRejected() {
        var decoder = PlanEventDecoder()
        XCTAssertThrowsError(try decoder.acceptLine("data: \(String(repeating: "x", count: 1_000_001))"))
    }
}
