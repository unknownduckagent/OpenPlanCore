import XCTest
@testable import OpenPlanCore
#if canImport(ImageIO) && canImport(CoreGraphics)
import ImageIO
import CoreGraphics
#endif

final class PlanR110SecurityTests: XCTestCase {
    func testAggregateTextBudgetBeforeJSONConstruction() throws {
        let long = String(repeating: "x", count: 490_000)
        let item = try PlanMessage(role: .user, text: long)
        // A single message fits; an aggregate of 64 cannot allocate freely.
        XCTAssertNotNil(try PlanContract.inferenceBody(model: "gpt-6.1-sol", messages: [item]))
        XCTAssertThrowsError(try PlanContract.inferenceBody(model: "gpt-6.1-sol", messages: Array(repeating: item, count: 64)))
    }

    func testBodyUsesStreamAndNoServerStorage() throws {
        let item = try PlanMessage(role: .user, text: "Hello")
        let data = try PlanContract.inferenceBody(model: "gpt-6.1-sol", messages: [item])
        XCTAssertLessThanOrEqual(data.count, 18_000_000)
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(body["store"] as? Bool, false)
        XCTAssertEqual(body["stream"] as? Bool, true)
    }

    func testBoundedReaderForbidsUnbrokenLineBeforeStringConversion() throws {
        var reader = PlanBoundedLineReader()
        for _ in 0..<1_000_000 { _ = try reader.accept(65) }
        XCTAssertThrowsError(try reader.accept(65)) { error in
            XCTAssertEqual(error as? PlanError, .invalidInput)
        }
    }

    func testReaderPreservesCRLFSplitUTF8AndFinalLine() throws {
        var reader = PlanBoundedLineReader()
        let bytes = Array("data: café\r\ndata: done".utf8)
        var first: String?
        for b in bytes {
            if let line = try reader.accept(b) { first = line }
        }
        XCTAssertEqual(first, "data: café")
        XCTAssertEqual(try reader.finish(), "data: done")
    }

    func testReaderFailsOnInvalidUTF8() throws {
        var reader = PlanBoundedLineReader()
        _ = try reader.accept(0xFF)
        XCTAssertThrowsError(try reader.accept(10))
    }

    func testBoundedReaderRetainsR109StreamingSemantics() throws {
        let stream = [
            #"data: {"type":"response.output_text.delta","delta":"hello"}"#,
            #"data: {"type":"response.completed"}"#
        ].joined(separator: "\n")
        var framer = PlanBoundedLineReader()
        var decoder = PlanWireDecoder()
        for b in stream.utf8 {
            if let line = try framer.accept(b) { _ = try decoder.acceptLine(line) }
        }
        if let last = try framer.finish() { _ = try decoder.acceptLine(last) }
        XCTAssertEqual(try decoder.endOfStream(), "hello")
    }

    #if canImport(ImageIO) && canImport(CoreGraphics)
    func testImageMetadataStrippedBeforeNetworkEncoding() throws {
        guard let ctx = CGContext(data: nil, width: 10, height: 10,
            bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue),
            let pixels = ctx.makeImage() else { throw PlanError.invalidInput }
        let sourceData = NSMutableData()
        guard let writer = CGImageDestinationCreateWithData(sourceData as CFMutableData,
            "public.jpeg" as CFString, 1, nil) else { throw PlanError.invalidInput }
        CGImageDestinationAddImage(writer, pixels, [
            kCGImagePropertyGPSDictionary: [
                kCGImagePropertyGPSLatitude: 37.7,
                kCGImagePropertyGPSLongitude: 122.4,
                kCGImagePropertyGPSLatitudeRef: "N",
                kCGImagePropertyGPSLongitudeRef: "E",
            ]
        ] as CFDictionary)
        XCTAssertTrue(CGImageDestinationFinalize(writer))
        let inputSource = try XCTUnwrap(CGImageSourceCreateWithData(sourceData as CFData, nil))
        let before = try XCTUnwrap(CGImageSourceCopyPropertiesAtIndex(inputSource, 0, nil) as? [CFString: Any])
        XCTAssertNotNil(before[kCGImagePropertyGPSDictionary], "Test fixture must contain source GPS metadata")
        let cleaned = try PlanImage(bytes: sourceData as Data, format: .jpeg)
        let src = try XCTUnwrap(CGImageSourceCreateWithData(cleaned.bytes as CFData, nil))
        let info = try XCTUnwrap(CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any])
        XCTAssertNil(info[kCGImagePropertyGPSDictionary])
        XCTAssertFalse(cleaned.bytes.isEmpty)
    }

    func testImageRejectsInvalidBytesOnApple() {
        XCTAssertThrowsError(try PlanImage(bytes: Data([0xFF, 0xD8, 0xFF]), format: .jpeg))
    }
    #else
    func testImagesFailClosedWhenImageIODecodingUnavailable() {
        XCTAssertThrowsError(try PlanImage(bytes: Data([0xFF, 0xD8, 0xFF]), format: .jpeg))
    }
    #endif

    #if canImport(Security) && canImport(CryptoKit) && canImport(Network)
    func testNetworkPolicyRejectsRedirectHostsAndSchemes() {
        XCTAssertTrue(PlanNetworkPolicy.isAllowed(PlanContract.responses))
        XCTAssertTrue(PlanNetworkPolicy.isAllowed(PlanContract.token))
        XCTAssertFalse(PlanNetworkPolicy.isAllowed(URL(string: "http://api.openai.com/v1/responses")!))
        XCTAssertFalse(PlanNetworkPolicy.isAllowed(URL(string: "https://example.com/")!))
        XCTAssertFalse(PlanNetworkPolicy.isAllowed(URL(string: "https://api.openai.com.evil.example/")!))
        XCTAssertFalse(PlanNetworkPolicy.isAllowed(URL(string: "https://api.openai.com:444/v1/responses")!))
    }

    func testRedirectionDelegateRefuses307And308() {
        let delegate = PlanNoRedirectDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: PlanContract.responses)
        for status in [301, 302, 307, 308] {
            let response = HTTPURLResponse(url: PlanContract.responses, statusCode: status,
                                           httpVersion: "HTTP/1.1", headerFields: ["Location": "https://example.com/"])!
            let redirected = URLRequest(url: URL(string: "https://example.com/")!)
            let didCall = expectation(description: "redirect rejected \(status)")
            delegate.urlSession(session, task: task, willPerformHTTPRedirection: response,
                newRequest: redirected) { request in
                XCTAssertNil(request)
                didCall.fulfill()
            }
            wait(for: [didCall], timeout: 1)
        }
    }
    #endif
}
