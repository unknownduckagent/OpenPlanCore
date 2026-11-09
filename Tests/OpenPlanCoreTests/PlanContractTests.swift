import XCTest
#if canImport(ImageIO) && canImport(CoreGraphics)
import ImageIO
import CoreGraphics
#endif
@testable import OpenPlanCore

final class PlanContractTests: XCTestCase {
    #if canImport(ImageIO) && canImport(CoreGraphics)
    private static func testPixelPNG() throws -> Data {
        let space = CGColorSpaceCreateDeviceRGB()
        guard let context = CGContext(data: nil, width: 2, height: 2,
            bitsPerComponent: 8, bytesPerRow: 0, space: space,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue),
            let image = context.makeImage() else { throw PlanError.invalidInput }
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data as CFMutableData,
            "public.png" as CFString, 1, nil) else { throw PlanError.invalidInput }
        CGImageDestinationAddImage(destination, image, nil)
        guard CGImageDestinationFinalize(destination) else { throw PlanError.invalidInput }
        return data as Data
    }
    #endif

    private let redirect = URL(string: "http://127.0.0.1:31234/auth/callback")!
    private let state = String(repeating: "s", count: 36)
    private let nonce = String(repeating: "n", count: 36)
    private let challenge = String(repeating: "c", count: 43)

    func testRegistrationContractAndHostIdentity() throws {
        let uri = try PlanContract.authorizationURL(
            clientID: "dynamic_agent_client", hostID: "urn:uuid:9e3e61db-7cd6-4e66-8e5c-a9a1b2772f35",
            agentName: "My Open App", redirectURI: redirect,
            state: state, nonce: nonce, challenge: challenge)
        let dict = Dictionary(uniqueKeysWithValues: URLComponents(url: uri, resolvingAgainstBaseURL: false)!
            .queryItems!.map { ($0.name, $0.value!) })
        XCTAssertEqual(dict["client_id"], "dynamic_agent_client")
        XCTAssertEqual(dict["agent_name_hint"], "My Open App")
        XCTAssertEqual(dict["ext_agent_host_id"], "urn:uuid:9e3e61db-7cd6-4e66-8e5c-a9a1b2772f35")
        XCTAssertEqual(dict["redirect_uri"], redirect.absoluteString)
        XCTAssertEqual(dict["scope"], PlanContract.scopes)
        XCTAssertEqual(dict["resource"], PlanContract.resource)
        XCTAssertEqual(dict["code_challenge_method"], "S256")
        XCTAssertEqual(dict["nonce"], nonce)
        XCTAssertEqual(dict["state"], state)
    }

    func testReturnAuthorizationOmitsAgentName() throws {
        let uri = try PlanContract.authorizationURL(clientID: "oaiapp_example",
            hostID: "urn:uuid:9e3e61db-7cd6-4e66-8e5c-a9a1b2772f35", agentName: "My Open App",
            redirectURI: redirect, state: state, nonce: nonce, challenge: challenge,
            retainedIDToken: "old-token", loginHint: "me@example.com")
        let items = URLComponents(url: uri, resolvingAgainstBaseURL: false)!.queryItems!
        XCTAssertNil(items.first(where: { $0.name == "agent_name_hint" }))
        XCTAssertNotNil(items.first(where: { $0.name == "id_token_hint" }))
    }

    func testCallbackValidatesStateAndRegistrationID() throws {
        let callback = URL(string: "http://127.0.0.1:31234/auth/callback?code=abc&state=\(state)&client_id=oaiapp_123")!
        let value = try PlanContract.callbackValues(callback, redirect: redirect,
                                                      expectedState: state, existingClientID: nil)
        XCTAssertEqual(value.code, "abc")
        XCTAssertEqual(value.issuedClientID, "oaiapp_123")
        XCTAssertThrowsError(try PlanContract.callbackValues(callback, redirect: redirect,
                           expectedState: "wrong", existingClientID: nil))
        XCTAssertThrowsError(try PlanContract.callbackValues(callback, redirect: redirect,
                           expectedState: state, existingClientID: "oaiapp_other"))
    }

    func testCallbackRejectsRedirectAndDuplicates() {
        let cases = [
            "http://evil.example:31234/auth/callback?code=abc&state=\(state)&client_id=oaiapp_x",
            "http://127.0.0.1:31235/auth/callback?code=abc&state=\(state)&client_id=oaiapp_x",
            "http://127.0.0.1:31234/other?code=abc&state=\(state)&client_id=oaiapp_x",
            "http://127.0.0.1:31234/auth/callback?code=abc&state=\(state)&state=\(state)&client_id=oaiapp_x",
            "http://127.0.0.1:31234/auth/callback?code=abc&state=\(state)&code=again&client_id=oaiapp_x",
            "http://127.0.0.1:31234/auth/callback?error=access_denied&state=\(state)",
            "http://127.0.0.1:31234/auth/callback?code=abc&state=\(state)",
        ]
        for value in cases {
            XCTAssertThrowsError(try PlanContract.callbackValues(URL(string: value)!, redirect: redirect,
                                   expectedState: state, existingClientID: nil), value)
        }
    }

    func testFormEncoding() {
        XCTAssertEqual(String(data: PlanContract.formBody([("code", "a+b c&d"),
                                                             ("resource", "https://api.openai.com/v1")]),
                              encoding: .utf8), "code=a%2Bb%20c%26d&resource=https%3A%2F%2Fapi.openai.com%2Fv1")
    }

    func testImageAndTextRequestContract() throws {
        #if canImport(ImageIO) && canImport(CoreGraphics)
        let image = try PlanImage(bytes: Self.testPixelPNG(), format: .png)
        let user = try PlanMessage(role: .user, text: "What is shown?", images: [image])
        #else
        // Portable builds deliberately cannot transmit un-sanitized images.
        XCTAssertThrowsError(try PlanImage(bytes: Data([0xFF, 0xD8, 0xFF]), format: .jpeg))
        let user = try PlanMessage(role: .user, text: "What is shown?")
        #endif
        let reply = try PlanMessage(role: .assistant, text: "A picture.")
        let body = try PlanContract.inferenceBody(model: "gpt-6.1-sol", messages: [user, reply])
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(object["store"] as? Bool, false)
        XCTAssertEqual(object["stream"] as? Bool, true)
        XCTAssertEqual(object["model"] as? String, "gpt-6.1-sol")
        let messages = try XCTUnwrap(object["input"] as? [[String: Any]])
        let parts = try XCTUnwrap(messages[0]["content"] as? [[String: String]])
        XCTAssertEqual(parts[0]["type"], "input_text")
        #if canImport(ImageIO) && canImport(CoreGraphics)
        XCTAssertEqual(parts[1]["type"], "input_image")
        XCTAssertTrue((parts[1]["image_url"] ?? "").hasPrefix("data:image/png;base64,"))
        #else
        XCTAssertEqual(parts.count, 1)
        #endif
        XCTAssertEqual(messages[1]["role"] as? String, "assistant")
    }

    func testRejectsOversizedOrUnapprovedInput() throws {
        XCTAssertThrowsError(try PlanImage(bytes: Data(), format: .png))
        XCTAssertThrowsError(try PlanImage(bytes: Data(repeating: 1, count: 10_000_001), format: .png))
        #if canImport(ImageIO) && canImport(CoreGraphics)
        XCTAssertThrowsError(try PlanMessage(role: .assistant, text: "", images: [
            try PlanImage(bytes: Self.testPixelPNG(), format: .png)]))
        #else
        XCTAssertThrowsError(try PlanImage(bytes: Data([1]), format: .png))
        #endif
        XCTAssertThrowsError(try PlanMessage(role: .user, text: "  "))
        let message = try PlanMessage(role: .user, text: "Ok")
        XCTAssertThrowsError(try PlanContract.inferenceBody(model: "bad\nname", messages: [message]))
        XCTAssertThrowsError(try PlanContract.inferenceBody(model: "safe", messages: []))
    }
}
