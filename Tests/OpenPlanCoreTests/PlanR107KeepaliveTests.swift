import XCTest
@testable import OpenPlanCore

final class PlanR107KeepaliveTests: XCTestCase {
    func testColonKeepaliveBetweenValidFrames() throws {
        var decoder = PlanWireDecoder()
        for line in ["data: :", "", ": keep-alive", "", "data:  :  ", ""] {
            XCTAssertNil(try decoder.acceptLine(line))
        }
        XCTAssertEqual(decoder.lastFrameClass, "colon_keepalive")
        for line in ["event: response.output_text.delta", #"data: {"type":"response.output_text.delta","delta":"Jupiter"}"#, ""] {
            _ = try decoder.acceptLine(line)
        }
        for line in ["data: :", "", #"data: {"type":"response.completed"}"#, ""] {
            _ = try decoder.acceptLine(line)
        }
        XCTAssertEqual(try decoder.endOfStream(), "Jupiter")
    }

    func testColonDoesNotCountAsCompleted() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine("data: :")
        _ = try decoder.acceptLine("")
        XCTAssertThrowsError(try decoder.endOfStream()) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.missingCompletion))
        }
    }

    func testInvalidControlPayloadStillRejected() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine("data: ::")
        XCTAssertThrowsError(try decoder.acceptLine("")) { error in
            XCTAssertEqual(error as? PlanError, .streamIssue(.malformedEvent))
        }
        XCTAssertEqual(decoder.lastFrameClass, "invalid_json_other")
    }

    func testUnexpectedColonInModelEventRejected() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine("event: response.output_text.delta")
        _ = try decoder.acceptLine("data: :")
        XCTAssertThrowsError(try decoder.acceptLine(""))
        XCTAssertEqual(decoder.lastFrameClass, "invalid_json_other")
    }

    func testMalformedResponseTextNoLeakInDiagnostic() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine("data: private@example.com personal text")
        XCTAssertThrowsError(try decoder.acceptLine(""))
        XCTAssertEqual(decoder.lastFrameClass, "invalid_json_other")
        XCTAssertFalse(decoder.lastFrameClass.contains("private"))
        XCTAssertFalse(decoder.lastFrameClass.contains("@"))
    }

    func testTruncatedJSONClassifiedNoContents() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine("data: {\"type\":\"response.created\"")
        XCTAssertThrowsError(try decoder.acceptLine(""))
        XCTAssertEqual(decoder.lastFrameClass, "invalid_json_partial_object")
    }

    func testNestedDataPrefixClassified() throws {
        var decoder = PlanWireDecoder()
        _ = try decoder.acceptLine(#"data: data: {"type":"response.created"}"#)
        XCTAssertThrowsError(try decoder.acceptLine(""))
        XCTAssertEqual(decoder.lastFrameClass, "invalid_json_nested_data")
    }
}
