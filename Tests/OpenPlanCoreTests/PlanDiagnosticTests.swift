import XCTest
@testable import OpenPlanCore

final class PlanDiagnosticTests: XCTestCase {
    func testBoundedAPIErrorCodeOnly() {
        let valid = Data(#"{"error":{"code":"subscription_sharing_user_not_eligible","message":"secret token user@example.com"}}"#.utf8)
        XCTAssertEqual(PlanContract.safeProviderErrorCode(valid), "subscription_sharing_user_not_eligible")
        XCTAssertNil(PlanContract.safeProviderErrorCode(Data(#"{"detail":"private server text"}"#.utf8)))
        XCTAssertNil(PlanContract.safeProviderErrorCode(Data(#"{"error":{"code":"secret@user.com"}}"#.utf8)))
    }
    func testResponseFailureRetainsSafeCode() throws {
        var decoder = PlanEventDecoder()
        XCTAssertNil(try decoder.acceptLine(#"data: {"type":"response.failed","response":{"error":{"code":"subscription_sharing_user_not_eligible","message":"private"}}}"#))
        XCTAssertThrowsError(try decoder.acceptLine("")) { error in
            XCTAssertEqual(error as? PlanError, .responseRejected(200, "subscription_sharing_user_not_eligible"))
        }
    }
    func testNoRawProviderBodyInErrorDescription() {
        let error = PlanError.responseRejected(403, "chatpass_v2_scope_not_authorized")
        XCTAssertEqual(error.localizedDescription, "ChatGPT rejected the HTTP 403 request (chatpass_v2_scope_not_authorized).")
    }
}
