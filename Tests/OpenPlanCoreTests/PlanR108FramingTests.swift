import XCTest
@testable import OpenPlanCore

final class PlanR108FramingTests: XCTestCase {
    private func decode(_ lines: [String]) throws -> String {
        var decoder = PlanWireDecoder()
        for line in lines { _ = try decoder.acceptLine(line) }
        return try decoder.endOfStream()
    }

    func testGatewayCombinedTwoJSONObjectsInOneDataLine() throws {
        let events = #"{"type":"response.output_text.delta","delta":"Jupiter"}{"type":"response.completed"}"#
        XCTAssertEqual(try decode(["data: " + events, ""]), "Jupiter")
    }

    func testCoalescedTwoDataLinesWithNoBlankSeparator() throws {
        XCTAssertEqual(try decode([
            #"data: {"type":"response.output_text.delta","delta":"Ju"}"#,
            #"data: {"type":"response.output_text.delta","delta":"piter"}"#,
            "", #"data: {"type":"response.completed"}"#, ""
        ]), "Jupiter")
    }

    func testCoalescedMissingCompletionStillFails() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine(#"data: {"type":"response.output_text.delta","delta":"A"}{"type":"response.output_text.delta","delta":"B"}"#)
        _ = try d.acceptLine("")
        XCTAssertThrowsError(try d.endOfStream()) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.missingCompletion))
        }
    }

    func testCoalescedExplicitProviderFailureCannotPass() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine(#"data: {"type":"response.output_text.delta","delta":"A"}{"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}}"#)
        XCTAssertThrowsError(try d.acceptLine(""))
    }

    func testInvalidObjectStillRejectedAndNoSecretDiagnostic() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine(#"data: {"type":"response.created","secret":"do not leak","n":broken}"#)
        XCTAssertThrowsError(try d.acceptLine(""))
        XCTAssertEqual(d.lastFrameClass, "invalid_json_object")
        XCTAssertFalse(d.lastFrameClass.contains("secret"))
        XCTAssertFalse(d.lastFrameClass.contains("leak"))
    }

    func testMalformedJsonControlByteClassifiedWithoutContent() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine("data: {\"type\":\"response.created\",\"text\":\"private\u{0001}data\"}")
        XCTAssertThrowsError(try d.acceptLine(""))
        XCTAssertEqual(d.lastFrameClass, "invalid_json_object_control_in_string")
    }

    func testBracesInsideStringsDoNotBreakObjectSplitter() throws {
        let event1 = #"{"type":"response.output_text.delta","delta":"J{\"x\"}"}"#
        let event2 = #"{"type":"response.completed"}"#
        XCTAssertEqual(try decode(["data: " + event1 + event2, ""]), #"J{"x"}"#)
    }

    func testRejectsMalformedConcatenatedSecondObject() throws {
        var d = PlanWireDecoder()
        _ = try d.acceptLine(#"data: {"type":"response.output_text.delta","delta":"OK"}{"type":"response.completed",bad}"#)
        XCTAssertThrowsError(try d.acceptLine(""))
        XCTAssertEqual(d.lastFrameClass, "invalid_json_object_multiple_objects")
    }

    func testNormalMultiLineJSONEventStillDecodes() throws {
        XCTAssertEqual(try decode([
            #"data: {"type":"response.output_text.delta", "delta": "Ju", "sequence_number": 1}"#,
            "", #"data: {"type":"response.output_text.delta", "delta": "piter"}"#, "",
            #"data: {"type":"response.completed"}"#, ""
        ]), "Jupiter")
    }
}
