import Foundation

/// Incrementally frames incoming SSE bytes. Unlike AsyncBytes.lines, it
/// rejects an oversized line *before* allocating a complete String for it.
internal struct PlanBoundedLineReader {
    private var pending = Data()
    private var count = 0
    private let maximumLine = 1_000_000
    private let maximumBody = 8_000_000

    mutating func accept(_ byte: UInt8) throws -> String? {
        guard count < maximumBody else { throw PlanError.invalidInput }
        count += 1
        if byte == 10 { // LF; CRLF is normalized here.
            if pending.last == 13 { pending.removeLast() }
            guard let line = String(data: pending, encoding: .utf8) else {
                throw PlanError.streamIssue(.malformedEvent)
            }
            pending.removeAll(keepingCapacity: true)
            return line
        }
        guard pending.count < maximumLine else { throw PlanError.invalidInput }
        pending.append(byte)
        return nil
    }

    mutating func finish() throws -> String? {
        guard !pending.isEmpty else { return nil }
        if pending.last == 13 { pending.removeLast() }
        guard let line = String(data: pending, encoding: .utf8) else {
            throw PlanError.streamIssue(.malformedEvent)
        }
        pending.removeAll()
        return line
    }
}


/// Server-sent event decoder: never treats partial text as a successful response.
public struct PlanEventDecoder {
    private var eventName: String?
    private var dataLines: [String] = []
    private var completed = false
    private var failed = false
    private var receivedBytes = 0
    private var accumulated = ""
    /// A bounded, non-content diagnostic for the last protocol frame.
    /// Never includes the server's text, user prompts, credentials or tokens.
    public private(set) var lastFrameClass = "none"

    public init() {}

    /// Pass one line (without its terminator); returns newly emitted text, if any.
    public mutating func acceptLine(_ line: String) throws -> String? {
        guard !failed && !completed else { return nil }
        receivedBytes += line.utf8.count
        guard receivedBytes <= 8_000_000, line.utf8.count <= 1_000_000 else { throw PlanError.invalidInput }
        let cleanLine = line.hasPrefix("\u{FEFF}") ? String(line.dropFirst()) : line
        if cleanLine.isEmpty || cleanLine == "\r" { return try flush() }
        if cleanLine.hasPrefix(":") { return nil }
        // R109: Some transports omit or collapse the blank line separating
        // SSE messages. If a new data/event header follows a *complete* JSON
        // message, finish that previous frame first. Ordinary SSE still emits
        // only when its blank separator arrives, preserving existing behavior.
        // Keep incomplete multi-line JSON buffered; never silently discard it.
        var emitted: String?
        if (cleanLine.hasPrefix("data:") || cleanLine.hasPrefix("event:")) && !dataLines.isEmpty {
            let candidate = dataLines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
            if let bytes = candidate.data(using: .utf8), bytes.count <= 1_000_000,
               ((try? JSONSerialization.jsonObject(with: bytes)) is [String: Any] ||
                PlanFrameStructure.splitConcatenatedObjects(bytes) != nil) {
                emitted = try flush()
            } else if candidate == ":" { emitted = try flush() }
        }
        if cleanLine.hasPrefix("event:") {
            eventName = String(cleanLine.dropFirst(6)).trimmingCharacters(in: .whitespacesAndNewlines)
        } else if cleanLine.hasPrefix("data:") {
            dataLines.append(String(cleanLine.dropFirst(5)).trimmingCharacters(in: .init(charactersIn: " ")))
        }
        return emitted
    }

    private mutating func flush() throws -> String? {
        defer { eventName = nil; dataLines.removeAll(keepingCapacity: true) }
        guard !dataLines.isEmpty else { return nil }
        let payload = dataLines.joined(separator: "\n")
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        // SSE allows empty data frames and non-JSON keepalive events. Accept
        // only explicitly named control frames; never treat them as completion.
        if trimmed.isEmpty {
            lastFrameClass = "empty_control"
            return nil
        }
        // A few streaming gateways send an empty keepalive as `data: :`
        // instead of a legal SSE comment `: keepalive`. Accept ONLY the
        // one-character marker, with no asserted model event. This marker
        // never counts as response completion or an answer.
        if trimmed == ":" && (eventName == nil || eventName == "ping" || eventName == "heartbeat") {
            lastFrameClass = "colon_keepalive"
            return nil
        }
        if eventName == "ping" || eventName == "heartbeat" {
            guard trimmed.utf8.count <= 256 else {
                lastFrameClass = "oversized_heartbeat"
                throw PlanError.streamIssue(.malformedEvent)
            }
            lastFrameClass = "heartbeat"
            return nil
        }
        // Some streaming gateways append the legacy [DONE] marker. It does
        // not substitute for the required response.completed event.
        if trimmed == "[DONE]" {
            lastFrameClass = "done_without_completion"
            throw PlanError.streamIssue(.missingCompletion)
        }
        let cleanPayload = trimmed.hasPrefix("\u{FEFF}") ? String(trimmed.dropFirst()) : trimmed
        guard let data = cleanPayload.data(using: .utf8) else {
            lastFrameClass = "invalid_utf8"
            throw PlanError.streamIssue(.malformedEvent)
        }
        if let parsed = try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) {
            guard let json = parsed as? [String: Any] else {
                lastFrameClass = "json_not_object"
                throw PlanError.streamIssue(.malformedEvent)
            }
            lastFrameClass = "valid_json"
            return try acceptObject(json, rawData: data)
        }
        // Some SSE intermediaries coalesce multiple full JSON event objects into
        // a single `data:` frame. JSONSerialization rejects the concatenation.
        // Recover ONLY if a strict structural split yields 2+ individually valid
        // dictionary objects with explicit event types. Never discard malformed
        // messages or assume a success without a real response.completed event.
        if let objects = PlanFrameStructure.splitConcatenatedObjects(data) {
            var emitted = ""
            for object in objects {
                guard !completed && !failed else { break }
                if let delta = try acceptObject(object.json, rawData: object.data) {
                    emitted += delta
                }
            }
            if !failed { lastFrameClass = "coalesced_objects_accepted" }
            return emitted.isEmpty ? nil : emitted
        }
        // Emit only structural categories. Never expose byte snippets, model
        // output, raw JSON, account tokens, exact user text or content hashes.
        let shape = PlanFrameStructure.classifyMalformed(data)
        if cleanPayload.hasPrefix("data:") {
            lastFrameClass = "invalid_json_nested_data"
        } else if cleanPayload.hasPrefix("{") {
            lastFrameClass = !cleanPayload.hasSuffix("}") ? "invalid_json_partial_object" :
                (shape == "unspecified" ? "invalid_json_object" : "invalid_json_object_" + shape)
        } else if cleanPayload.hasPrefix("[") {
            lastFrameClass = "invalid_json_array"
        } else {
            lastFrameClass = "invalid_json_other"
        }
        throw PlanError.streamIssue(.malformedEvent)
    }


    private mutating func acceptObject(_ json: [String: Any], rawData data: Data) throws -> String? {
        // An error object may arrive as an SSE message with no `type` field.
        // Preserve safe machine-readable error codes, but not the raw payload.
        if json["type"] == nil, json["error"] is [String: Any] {
            failed = true
            lastFrameClass = "provider_error"
            throw PlanError.responseRejected(200, PlanContract.safeProviderErrorCode(data))
        }
        let name = (json["type"] as? String) ?? eventName ?? ""
        switch name {
        case "response.output_text.delta":
            guard let delta = json["delta"] as? String else { return nil }
            accumulated += delta
            guard accumulated.utf8.count <= 2_000_000 else { throw PlanError.invalidInput }
            return delta
        case "response.output_text.done":
            // Some compatible streams contain only a final text event, not deltas.
            guard let finalText = json["text"] as? String else { return nil }
            guard finalText.utf8.count <= 2_000_000 else { throw PlanError.invalidInput }
            if accumulated.isEmpty {
                accumulated = finalText
                return finalText
            }
            if finalText.hasPrefix(accumulated) && finalText != accumulated {
                let extra = String(finalText.dropFirst(accumulated.count))
                accumulated = finalText
                return extra
            }
            // The final event is authoritative. Avoid double-emitting duplicated deltas.
            accumulated = finalText
            return nil
        case "response.completed":
            completed = true
            if accumulated.isEmpty,
               let response = json["response"] as? [String: Any],
               let outputs = response["output"] as? [[String: Any]] {
                let texts = outputs.flatMap { output -> [String] in
                    guard output["type"] as? String == "message",
                          let parts = output["content"] as? [[String: Any]] else { return [] }
                    return parts.compactMap { part in
                        guard part["type"] as? String == "output_text" else { return nil }
                        return part["text"] as? String
                    }
                }
                let text = texts.joined(separator: "\n")
                guard text.utf8.count <= 2_000_000 else { throw PlanError.invalidInput }
                accumulated = text
                return text.isEmpty ? nil : text
            }
            return nil
        case "response.incomplete": failed = true; throw PlanError.incompleteResponse
        case "response.failed":
            failed = true
            let response = json["response"] as? [String: Any]
            let error = response?["error"] as? [String: Any]
            let code = error?["code"] as? String
            if code == "subscription_sharing_usage_limit_exceeded" ||
               code == "subscription_sharing_usage_unavailable" { throw PlanError.usageUnavailable }
            throw PlanError.responseRejected(200, code.flatMap { PlanContract.safeProviderErrorCode(
                (try? JSONSerialization.data(withJSONObject: ["error": ["code": $0]])) ?? Data()) })
        case "error":
            failed = true
            throw PlanError.responseRejected(200, PlanContract.safeProviderErrorCode(data))
        default: return nil
        }
    }

    public var result: String? { completed && !failed ? accumulated : nil }
    public mutating func endOfStream() throws -> String {
        _ = try flush()
        guard completed, !failed else { throw PlanError.streamIssue(.missingCompletion) }
        guard !accumulated.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw PlanError.streamIssue(.emptyCompletedResponse)
        }
        return accumulated
    }
}


/// Structural SSE diagnostics and a narrowly constrained recovery for
/// gateways that combine complete JSON event objects without SSE boundaries.
/// Does not retain or log source content; it never tries to repair broken JSON.
internal enum PlanFrameStructure {
    struct ObjectRecord {
        let json: [String: Any]
        let data: Data
    }

    static func splitConcatenatedObjects(_ data: Data) -> [ObjectRecord]? {
        guard data.count <= 1_000_000 else { return nil }
        let bytes = [UInt8](data)
        var ranges: [Range<Int>] = []
        var begin: Int?
        var depth = 0
        var inString = false
        var escape = false
        for (index, byte) in bytes.enumerated() {
            if inString {
                if escape { escape = false }
                else if byte == 92 { escape = true } // backslash
                else if byte == 34 { inString = false } // quote
                continue
            }
            if byte == 34 {
                guard depth > 0 else { return nil }
                inString = true
                continue
            }
            if byte == 123 { // {
                if depth == 0 { begin = index }
                depth += 1
                continue
            }
            if byte == 125 { // }
                guard depth > 0 else { return nil }
                depth -= 1
                if depth == 0, let start = begin {
                    ranges.append(start..<(index+1))
                    guard ranges.count <= 512 else { return nil }
                    begin = nil
                }
                continue
            }
            if depth == 0 && byte != 32 && byte != 9 && byte != 10 && byte != 13 {
                return nil
            }
        }
        guard depth == 0, !inString, ranges.count >= 2 else { return nil }
        var output: [ObjectRecord] = []
        for range in ranges {
            let objectData = Data(bytes[range])
            guard let object = try? JSONSerialization.jsonObject(with: objectData) as? [String: Any],
                  let name = object["type"] as? String,
                  !name.isEmpty, name.count <= 100 else { return nil }
            output.append(ObjectRecord(json: object, data: objectData))
        }
        return output
    }

    /// Deliberately conservative content-free classifications.
    static func classifyMalformed(_ data: Data) -> String {
        let bytes = [UInt8](data)
        var inString = false
        var escape = false
        var depth = 0
        var embeddedControl = false
        var unmatchedClose = false
        var countTopObjects = 0
        for byte in bytes {
            if inString {
                if escape { escape = false; continue }
                if byte == 92 { escape = true; continue }
                if byte == 34 { inString = false; continue }
                if byte < 32 { embeddedControl = true }
                continue
            }
            if byte == 34 { inString = true; continue }
            if byte == 123 { if depth == 0 { countTopObjects += 1 }; depth += 1 }
            if byte == 125 { depth -= 1; if depth < 0 { unmatchedClose = true; depth = 0 } }
        }
        if embeddedControl { return "control_in_string" }
        if inString { return "unterminated_string" }
        if unmatchedClose { return "unmatched_close" }
        if depth > 0 { return "unclosed_object" }
        if countTopObjects >= 2 { return "multiple_objects" }
        if bytes.contains(0) { return "nul_byte" }
        return "unspecified"
    }
}


/// Classifies the response *body*, not just the declared MIME type. Some proxies
/// and networking stacks omit or alter Content-Type even for legitimate SSE.
/// A non-streaming response is accepted only if it contains an explicitly
/// completed Responses API result. No raw response content is logged.
public struct PlanWireDecoder {
    public private(set) var detectedFormat = "unknown"
    public var lastFrameClass: String { events.lastFrameClass }
    private var events = PlanEventDecoder()
    private var jsonBody = Data()

    public init() {}

    /// Feed individual lines as received. The first meaningful line selects
    /// either strict SSE decoding or bounded completed-JSON decoding.
    public mutating func acceptLine(_ line: String) throws -> String? {
        if detectedFormat == "unknown" {
            var trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("\u{FEFF}") { trimmed.removeFirst() }
            if trimmed.isEmpty { return nil }
            if trimmed.hasPrefix("event:") || trimmed.hasPrefix("data:") ||
               trimmed.hasPrefix(":") || trimmed.hasPrefix("retry:") ||
               trimmed.hasPrefix("id:") {
                detectedFormat = "sse"
            } else if trimmed.hasPrefix("{") {
                detectedFormat = "json"
            } else if trimmed.hasPrefix("<") {
                detectedFormat = "html"
            } else {
                detectedFormat = "other"
            }
        }
        switch detectedFormat {
        case "sse":
            let normalized = line.hasPrefix("\u{FEFF}") ? String(line.dropFirst()) : line
            return try events.acceptLine(normalized)
        case "json":
            // JSON may span lines. This is a strict, size-bounded fallback;
            // the caller still requests SSE from OpenAI.
            guard jsonBody.count + line.utf8.count + 1 <= 2_000_000 else {
                throw PlanError.invalidInput
            }
            jsonBody.append(contentsOf: line.utf8)
            jsonBody.append(10)
            return nil
        default: throw PlanError.streamIssue(.unexpectedContentType)
        }
    }

    public mutating func endOfStream() throws -> String {
        switch detectedFormat {
        case "sse": return try events.endOfStream()
        case "json":
            guard let object = try? JSONSerialization.jsonObject(with: jsonBody) as? [String: Any] else {
                throw PlanError.streamIssue(.malformedEvent)
            }
            let response: [String: Any]
            if object["type"] as? String == "response.completed",
               let wrapped = object["response"] as? [String: Any] {
                response = wrapped
            } else if object["object"] as? String == "response" || object["status"] != nil {
                response = object
            } else {
                let code = PlanContract.safeProviderErrorCode(jsonBody)
                throw PlanError.responseRejected(200, code)
            }
            guard response["status"] as? String == "completed" else {
                if response["status"] as? String == "incomplete" { throw PlanError.incompleteResponse }
                if response["status"] as? String == "failed" {
                    throw PlanError.responseRejected(200, PlanContract.safeProviderErrorCode(jsonBody))
                }
                throw PlanError.streamIssue(.missingCompletion)
            }
            guard let outputs = response["output"] as? [[String: Any]] else {
                throw PlanError.streamIssue(.emptyCompletedResponse)
            }
            let texts = outputs.flatMap { output -> [String] in
                guard output["type"] as? String == "message",
                      let content = output["content"] as? [[String: Any]] else { return [] }
                return content.compactMap { item in
                    guard item["type"] as? String == "output_text" else { return nil }
                    return item["text"] as? String
                }
            }
            let result = texts.joined(separator: "\n")
            guard !result.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw PlanError.streamIssue(.emptyCompletedResponse)
            }
            return result
        default: throw PlanError.streamIssue(.unexpectedContentType)
        }
    }
}
