import XCTest
@testable import OpenPlanCore

final class PlanR106FrameTests: XCTestCase {
    private func push(_ d: inout PlanWireDecoder, _ event: [String]) throws {
        for line in event { _ = try d.acceptLine(line) }
    }

    func testControlAndHeartbeatBeforeCompletedResponse() throws {
        var d = PlanWireDecoder()
        try push(&d, [": gateway alive", "", "event: heartbeat", "data: up", "", "data:", ""])
        try push(&d, ["event: response.output_text.delta", #"data: {"type":"response.output_text.delta","delta":"Jupiter"}"#, ""])
        try push(&d, [#"data: {"type":"response.completed"}"#, ""])
        XCTAssertEqual(try d.endOfStream(), "Jupiter")
    }

    func testBOMOnFirstEventLine() throws {
        var d = PlanWireDecoder()
        try push(&d, ["\u{FEFF}event: response.output_text.done", #"data: {"type":"response.output_text.done","text":"Jupiter"}"#, ""])
        try push(&d, [#"data: {"type":"response.completed"}"#, ""])
        XCTAssertEqual(try d.endOfStream(), "Jupiter")
    }

    func testDoneBeforeCompletedNeverSucceeds() throws {
        var d = PlanWireDecoder()
        XCTAssertNil(try d.acceptLine("data: [DONE]"))
        XCTAssertThrowsError(try d.acceptLine("")) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.missingCompletion))
        }
        XCTAssertEqual(d.lastFrameClass, "done_without_completion")
    }

    func testInvalidJSONIsFingerprintOnly() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine("data: Private user email: hidden@example.com")
        XCTAssertThrowsError(try d.acceptLine("")) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.malformedEvent))
        }
        XCTAssertEqual(d.lastFrameClass, "invalid_json_other")
        XCTAssertFalse(d.lastFrameClass.contains("@"))
        XCTAssertFalse(d.lastFrameClass.contains("Private"))
    }

    func testJSONScalarCannotBecomeSuccess() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine(#"data: "secret""#)
        XCTAssertThrowsError(try d.acceptLine(""))
        XCTAssertEqual(d.lastFrameClass, "json_not_object")
    }

    func testErrorEnvelopeWithoutTypeFailsWithSafeCode() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine(#"data: {"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"secret"}}"#)
        XCTAssertThrowsError(try d.acceptLine("")) { error in
            XCTAssertEqual(error as? PlanError, .responseRejected(200, "subscription_sharing_usage_limit_exceeded"))
        }
        XCTAssertEqual(d.lastFrameClass, "provider_error")
    }

    func testMalformedResponseEventStillFails() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine("event: response.created")
        _ = try d.acceptLine("data: {invalid")
        XCTAssertThrowsError(try d.acceptLine(""))
        XCTAssertEqual(d.lastFrameClass, "invalid_json_partial_object")
    }

    func testDoNotTreatDoneMarkerAfterPartialTextAsCompletion() throws {
        var d = PlanWireDecoder()
        try push(&d, [#"data: {"type":"response.output_text.delta","delta":"Hi"}"#, ""])
        _ = try d.acceptLine("data: [DONE]")
        XCTAssertThrowsError(try d.acceptLine(""))
    }
}
