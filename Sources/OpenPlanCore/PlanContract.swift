import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum PlanContract {
    public static let resource = "https://api.openai.com/v1"
    public static let authorization = URL(string: "https://auth.openai.com/api/accounts/authorize")!
    public static let token = URL(string: "https://auth.openai.com/api/accounts/oauth/token")!
    public static let keys = URL(string: "https://auth.openai.com/.well-known/jwks.json")!
    public static let models = URL(string: "https://api.openai.com/v1/models")!
    public static let responses = URL(string: "https://api.openai.com/v1/responses")!
    public static let scopes = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"

    static func formBody(_ fields: [(String, String)]) -> Data {
        Data(fields.map { "\(encode($0.0))=\(encode($0.1))" }.joined(separator: "&").utf8)
    }

    private static func encode(_ value: String) -> String {
        var output = ""
        for byte in value.utf8 {
            if (65...90).contains(byte) || (97...122).contains(byte) ||
                (48...57).contains(byte) || byte == 45 || byte == 46 || byte == 95 || byte == 126 {
                output.append(Character(UnicodeScalar(byte)))
            } else { output += String(format: "%%%02X", byte) }
        }
        return output
    }

    public static func authorizationURL(clientID: String, hostID: String,
        agentName: String, redirectURI: URL, state: String, nonce: String,
        challenge: String, retainedIDToken: String? = nil, loginHint: String? = nil) throws -> URL {
        guard clientID == "dynamic_agent_client" || clientID.hasPrefix("oaiapp_"),
              hostID.hasPrefix("urn:uuid:"), !agentName.isEmpty,
              agentName.count <= 80, redirectURI.scheme == "http",
              redirectURI.host == "127.0.0.1", redirectURI.path == "/auth/callback",
              state.count >= 24, nonce.count >= 24, challenge.count >= 40 else { throw PlanError.invalidInput }
        var components = URLComponents(url: authorization, resolvingAgainstBaseURL: false)!
        var items = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "ext_agent_host_id", value: hostID),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: scopes),
            URLQueryItem(name: "resource", value: resource),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "code_challenge", value: challenge),
        ]
        if clientID == "dynamic_agent_client" {
            items.append(URLQueryItem(name: "agent_name_hint", value: agentName))
        } else {
            if let retainedIDToken, !retainedIDToken.isEmpty {
                items.append(URLQueryItem(name: "id_token_hint", value: retainedIDToken))
            }
            if let loginHint, !loginHint.isEmpty {
                items.append(URLQueryItem(name: "login_hint", value: loginHint))
            }
        }
        components.queryItems = items
        guard let url = components.url else { throw PlanError.invalidInput }
        return url
    }

    public static func callbackValues(_ callback: URL, redirect: URL, expectedState: String,
        existingClientID: String?) throws -> (code: String, issuedClientID: String) {
        guard callback.scheme == redirect.scheme,
              callback.host == redirect.host, callback.port == redirect.port,
              callback.path == redirect.path,
              let components = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              let items = components.queryItems else { throw PlanError.invalidCallback }
        var params = [String: String]()
        for item in items {
            guard params[item.name] == nil, let value = item.value else { throw PlanError.invalidCallback }
            params[item.name] = value
        }
        guard params["state"] == expectedState else { throw PlanError.invalidState }
        if params["error"] != nil { throw PlanError.authorizationFailed }
        guard let code = params["code"], !code.isEmpty, code.count <= 4096 else {
            throw PlanError.invalidCallback
        }
        let clientID: String
        if let existingClientID {
            if let returned = params["client_id"], returned != existingClientID { throw PlanError.invalidCallback }
            clientID = existingClientID
        } else {
            guard let returned = params["client_id"], returned.hasPrefix("oaiapp_"),
                  returned.count <= 256 else { throw PlanError.invalidCallback }
            clientID = returned
        }
        return (code, clientID)
    }

    static func inferenceBody(model: String, messages: [PlanMessage]) throws -> Data {
        guard isModelID(model), !messages.isEmpty, messages.count <= 64 else { throw PlanError.invalidInput }
        // Budget before making base64 strings or a JSON object. UTF-8 can
        // expand during JSON escaping, so count a conservative sixfold bound.
        // One conversation is capped at 12 MB raw / 18 MB serialized.
        var rawBudget = 0
        var encodedUpperBound = 16_384
        for message in messages {
            let count = message.text.utf8.count
            guard count <= 12_000_000 - rawBudget else { throw PlanError.invalidInput }
            rawBudget += count
            guard count <= (18_000_000 - encodedUpperBound) / 6 else { throw PlanError.invalidInput }
            encodedUpperBound += 6 * count
            for image in message.images {
                let imageSize = image.bytes.count
                guard imageSize <= 12_000_000 - rawBudget else { throw PlanError.invalidInput }
                rawBudget += imageSize
                let base64 = ((imageSize + 2) / 3) * 4
                guard base64 <= 18_000_000 - encodedUpperBound - 256 else {
                    throw PlanError.invalidInput
                }
                encodedUpperBound += base64 + 256
            }
            guard encodedUpperBound + 4096 <= 18_000_000 else { throw PlanError.invalidInput }
        }
        var input = [[String: Any]]()
        for message in messages {
            if message.role == .assistant {
                input.append(["role": "assistant", "content": message.text])
            } else {
                var parts = [[String: Any]]()
                if !message.text.isEmpty { parts.append(["type": "input_text", "text": message.text]) }
                for image in message.images {
                    parts.append(["type": "input_image",
                        "image_url": "data:\(image.format.mimeType);base64,\(image.bytes.base64EncodedString())"])
                }
                input.append(["role": "user", "content": parts])
            }
        }
        let body = try JSONSerialization.data(withJSONObject: [
            "model": model, "input": input, "store": false, "stream": true,
        ])
        guard body.count <= 18_000_000 else { throw PlanError.invalidInput }
        return body
    }

    /// Return only a bounded machine-readable error code; raw provider bodies can contain sensitive data.
    public static func safeProviderErrorCode(_ data: Data) -> String? {
        guard data.count <= 65_536,
              let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let nested = (parsed["error"] as? [String: Any]) ??
                     ((parsed["response"] as? [String: Any])?["error"] as? [String: Any])
        guard let code = nested?["code"] as? String,
              !code.isEmpty, code.count <= 96 else { return nil }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._-")
        guard code.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        return code
    }

    static func isModelID(_ id: String) -> Bool {
        guard !id.isEmpty, id.count <= 150 else { return false }
        let permitted = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:")
        return id.unicodeScalars.allSatisfy { permitted.contains($0) }
    }
}
