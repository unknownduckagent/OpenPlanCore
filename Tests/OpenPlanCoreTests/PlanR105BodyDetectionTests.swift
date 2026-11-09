import XCTest
@testable import OpenPlanCore

final class PlanR105BodyDetectionTests: XCTestCase {
    func testSSEWorksWithoutSSEContentType() throws {
        // Client must sniff this SSE content even when Content-Type is "other".
        var d = PlanWireDecoder()
        XCTAssertNil(try d.acceptLine("event: response.output_text.delta"))
        XCTAssertNil(try d.acceptLine("data: {\"type\":\"response.output_text.delta\",\"delta\":\"Jupiter\"}"))
        XCTAssertEqual(try d.acceptLine(""), "Jupiter")
        XCTAssertNil(try d.acceptLine("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}"))
        XCTAssertNil(try d.acceptLine(""))
        XCTAssertEqual(try d.endOfStream(), "Jupiter")
        XCTAssertEqual(d.detectedFormat, "sse")
    }

    func testCompletedJSONCanBeReadSafely() throws {
        var d = PlanWireDecoder()
        XCTAssertNil(try d.acceptLine("{\"object\":\"response\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"Jupiter\"}]}]}"))
        XCTAssertEqual(try d.endOfStream(), "Jupiter")
        XCTAssertEqual(d.detectedFormat, "json")
    }

    func testJSONIncompleteIsNotSuccess() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine("{\"object\":\"response\",\"status\":\"incomplete\",\"output\":[]}")
        XCTAssertThrowsError(try d.endOfStream()) { error in
            XCTAssertEqual(error as? PlanError, .incompleteResponse)
        }
    }

    func testErrorJSONDoesNotBecomeSuccessfulOutput() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine("{\"error\":{\"code\":\"permission_denied\"}}")
        XCTAssertThrowsError(try d.endOfStream()) { error in
            XCTAssertEqual(error as? PlanError, .responseRejected(200, "permission_denied"))
        }
    }

    func testHTMLIsRejectedWithoutExposingBody() throws {
        var d = PlanWireDecoder()
        XCTAssertThrowsError(try d.acceptLine("<!doctype html><script>secret</script>")) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.unexpectedContentType))
        }
        XCTAssertEqual(d.detectedFormat, "html")
    }

    func testEmptyBodyNeverSucceeds() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine("")
        XCTAssertThrowsError(try d.endOfStream())
    }

    func testNoTerminalSSEStillFails() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine("data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}")
        _ = try d.acceptLine("")
        XCTAssertThrowsError(try d.endOfStream()) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.missingCompletion))
        }
    }
}
