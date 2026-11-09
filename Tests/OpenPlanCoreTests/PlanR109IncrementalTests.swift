import XCTest
@testable import OpenPlanCore

final class PlanR109IncrementalTests: XCTestCase {
    private func finish(_ lines: [String]) throws -> String {
        var decoder = PlanWireDecoder()
        for line in lines { _ = try decoder.acceptLine(line) }
        return try decoder.endOfStream()
    }

    func testShortStreamWithoutBlankSeparators() throws {
        XCTAssertEqual(try finish([
            #"event: response.created"#,
            #"data: {"type":"response.created"}"#,
            #"event: response.output_text.delta"#,
            #"data: {"type":"response.output_text.delta","delta":"Ju"}"#,
            #"event: response.output_text.delta"#,
            #"data: {"type":"response.output_text.delta","delta":"piter"}"#,
            #"event: response.completed"#,
            #"data: {"type":"response.completed"}"#
        ]), "Jupiter")
    }

    func testLargeStreamWithoutAnyBlankSeparators() throws {
        var decoder = PlanWireDecoder()
        var seen = ""
        for n in 0..<250 {
            let line = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\",\"sequence_number\":\(n)}"
            if let fragment = try decoder.acceptLine(line) { seen += fragment }
        }
        if let fragment = try decoder.acceptLine(#"data: {"type":"response.completed"}"#) { seen += fragment }
        XCTAssertEqual(seen, String(repeating: "x", count: 250))
        XCTAssertEqual(try decoder.endOfStream(), seen)
    }

    func testSplitJSONAcrossDataLines() throws {
        XCTAssertEqual(try finish([
            #"data: {"type":"response.output_text.delta", "#,
            #"data: "delta":"Jupiter"}"#,
            #"data: {"type":"response.completed"}"#
        ]), "Jupiter")
    }

    func testCoalescedTypedEventsOnOneLine() throws {
        XCTAssertEqual(try finish([
            #"data: {"type":"response.output_text.delta","delta":"Ju"}{"type":"response.output_text.delta","delta":"piter"}{"type":"response.completed"}"#,
        ]), "Jupiter")
    }

    func testLargeCombinedEventDataIsBoundedAndValidated() throws {
        var objects = (0..<80).map { n in
            "{\"type\":\"response.output_text.delta\",\"delta\":\"x\",\"sequence_number\":\(n)}"
        }
        objects.append(#"{"type":"response.completed"}"#)
        XCTAssertEqual(try finish(["data: " + objects.joined()]), String(repeating: "x", count: 80))
    }

    func testMissingCompletionRemainsFailure() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine(#"data: {"type":"response.output_text.delta","delta":"private"}"#)
        XCTAssertThrowsError(try decoder.endOfStream()) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.missingCompletion))
        }
    }

    func testInvalidPayloadRejected() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine(#"data: {"type":"response.output_text.delta","delta":"abc","secret":not_json}"#)
        XCTAssertThrowsError(try decoder.acceptLine(""))
        XCTAssertFalse(decoder.lastFrameClass.contains("abc"))
    }

    func testErrorCannotBeTreatedAsCompletion() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine(#"data: {"type":"response.output_text.delta","delta":"partial"}"#)
        _ = try decoder.acceptLine(#"data: {"type":"response.failed","response":{"error":{"code":"server_error"}}}"#)
        XCTAssertThrowsError(try decoder.endOfStream())
    }

    func testValidHeartbeatWithoutBlankSeparator() throws {
        XCTAssertEqual(try finish([
            "data: :",
            #"data: {"type":"response.output_text.delta","delta":"OK"}"#,
            #"data: {"type":"response.completed"}"#
        ]), "OK")
    }
}
