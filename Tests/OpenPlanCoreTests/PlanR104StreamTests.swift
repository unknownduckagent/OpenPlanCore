import XCTest
@testable import OpenPlanCore

final class PlanR104StreamTests: XCTestCase {
    func testFinalTextOnlyEventIsAccepted() throws {
        var d = PlanEventDecoder()
        XCTAssertNil(try d.acceptLine(#"event: response.output_text.done"#))
        XCTAssertNil(try d.acceptLine(#"data: {"type":"response.output_text.done","text":"Hello"}"#))
        XCTAssertEqual(try d.acceptLine(""), "Hello")
        XCTAssertNil(try d.acceptLine(#"data: {"type":"response.completed"}"#))
        XCTAssertNil(try d.acceptLine(""))
        XCTAssertEqual(try d.endOfStream(), "Hello")
    }
    func testDeltasAndDoneDoNotDuplicateText() throws {
        var d = PlanEventDecoder()
        XCTAssertNil(try d.acceptLine(#"data: {"type":"response.output_text.delta","delta":"Hel"}"#))
        XCTAssertEqual(try d.acceptLine(""), "Hel")
        XCTAssertNil(try d.acceptLine(#"data: {"type":"response.output_text.done","text":"Hello"}"#))
        XCTAssertEqual(try d.acceptLine(""), "lo")
        XCTAssertNil(try d.acceptLine(#"data: {"type":"response.completed"}"#))
        XCTAssertNil(try d.acceptLine(""))
        XCTAssertEqual(try d.endOfStream(), "Hello")
    }
    func testMissingCompletionIsExplicit() throws {
        var d = PlanEventDecoder()
        XCTAssertNil(try d.acceptLine(#"data: {"type":"response.output_text.delta","delta":"hi"}"#))
        XCTAssertEqual(try d.acceptLine(""), "hi")
        XCTAssertThrowsError(try d.endOfStream()) { e in
            XCTAssertEqual(e as? PlanError, .streamIssue(.missingCompletion))
        }
    }
    func testCompletedButEmptyIsExplicit() throws {
        var d = PlanEventDecoder()
        XCTAssertNil(try d.acceptLine(#"data: {"type":"response.completed"}"#))
        XCTAssertNil(try d.acceptLine(""))
        XCTAssertThrowsError(try d.endOfStream()) { e in
            XCTAssertEqual(e as? PlanError, .streamIssue(.emptyCompletedResponse))
        }
    }
    func testCompletedFinalResponseOutputIsAccepted() throws {
        var d = PlanEventDecoder()
        let event = #"data: {"type":"response.completed","response":{"output":[{"type":"message","content":[{"type":"output_text","text":"OK"}]}]}}"#
        XCTAssertNil(try d.acceptLine(event))
        XCTAssertEqual(try d.acceptLine(""), "OK")
        XCTAssertEqual(try d.endOfStream(), "OK")
    }
    func testMalformedEventIsExplicit() throws {
        var d = PlanEventDecoder()
        XCTAssertNil(try d.acceptLine("data: not-json"))
        XCTAssertThrowsError(try d.acceptLine("")) { e in
            XCTAssertEqual(e as? PlanError, .streamIssue(.malformedEvent))
        }
    }
    func testNoUserMaterialInDiagnostic() {
        let d = PlanResponseDiagnostic(model: "gpt-6.1-sol", httpStatus: 200,
                                      responseKind: "sse", requestID: "req_test")
        XCTAssertEqual(d.model, "gpt-6.1-sol")
        XCTAssertEqual(d.responseKind, "sse")
        XCTAssertEqual(PlanError.streamIssue(.missingCompletion).localizedDescription,
                       "ChatGPT transport diagnostic: missing_completion.")
    }
}
