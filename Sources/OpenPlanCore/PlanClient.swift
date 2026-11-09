#if canImport(Security) && canImport(CryptoKit) && canImport(Network)
import Foundation
import Security
import CryptoKit
import Network


/// Reject redirects (including 307/308 POST replay) instead of following them
/// with Authorization headers or refresh/access tokens in the request body.
internal final class PlanNoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

internal enum PlanNetworkPolicy {
    static func isAllowed(_ url: URL) -> Bool {
        let c = URLComponents(url: url, resolvingAgainstBaseURL: false)
        return c?.scheme == "https" &&
            (c?.host == "api.openai.com" || c?.host == "auth.openai.com") &&
            (c?.port == nil || c?.port == 443) &&
            c?.user == nil && c?.password == nil && c?.fragment == nil
    }

    static func exactResponse(_ response: URLResponse, for expected: URL) -> Bool {
        isAllowed(expected) && response.url?.absoluteString == expected.absoluteString
    }
}

/// An optional open-source ChatGPT transport. The host decides when and what to send.
/// `enabledForHostApp` defaults to false: a bundled component does not establish
/// partner eligibility for a proprietary application's public release.
@MainActor
public final class PlanChatGPTClient {
    private let vault: PlanKeychainVault
    private var state: PlanVaultData
    private let session: URLSession
    private let noRedirect: PlanNoRedirectDelegate
    private var inProgress = false
    private let enabledForHostApp: Bool
    public private(set) var lastResponseDiagnostic: PlanResponseDiagnostic?

    public init(keychainService: String, enabledForHostApp: Bool = false) throws {
        vault = try PlanKeychainVault(service: keychainService)
        state = try vault.load()
        noRedirect = PlanNoRedirectDelegate()
        session = URLSession(configuration: .ephemeral, delegate: noRedirect, delegateQueue: nil)
        self.enabledForHostApp = enabledForHostApp
        // A stable host identifier is persisted on the first construction.
        try vault.save(state)
    }

    public var accounts: [PlanAccount] {
        state.profiles.map { PlanAccount(registrationID: $0.clientID,
                                         email: $0.email, subject: $0.subject) }
    }

    public var currentAccount: PlanAccount? {
        guard let id = state.selected, let p = state.profiles.first(where: { $0.clientID == id }) else { return nil }
        return PlanAccount(registrationID: id, email: p.email, subject: p.subject)
    }

    public func select(registrationID: String) throws {
        guard state.profiles.contains(where: { $0.clientID == registrationID }) else {
            throw PlanError.notConnected
        }
        var updated = state
        updated.selected = registrationID
        try vault.save(updated)
        state = updated
    }

    /// Open `authorizeURL` in the OS browser (for example UIApplication.shared.open).
    /// This method does not connect any account until OIDC signature and scopes validate.
    public func connect(agentName: String, existingRegistration: String? = nil,
                        openBrowser: @escaping @MainActor (URL) -> Void) async throws -> PlanAccount {
        guard enabledForHostApp else { throw PlanError.disabledUntilApproved }
        guard !inProgress else { throw PlanError.serviceUnavailable }
        let existing: PlanProfile?
        if let existingRegistration {
            guard let found = state.profiles.first(where: { $0.clientID == existingRegistration }) else {
                throw PlanError.notConnected
            }
            existing = found
        } else { existing = nil }
        inProgress = true
        defer { inProgress = false }

        let nonce = try PlanTrust.random()
        let challengeState = try PlanTrust.random()
        let verifier = try PlanTrust.random(48)
        let listener = PlanLoopback()
        let redirect = try await listener.start(state: challengeState, existingClientID: existing?.clientID)
        defer { listener.cancel() }
        let url = try PlanContract.authorizationURL(
            clientID: existing?.clientID ?? "dynamic_agent_client",
            hostID: state.hostID, agentName: agentName, redirectURI: redirect,
            state: challengeState, nonce: nonce, challenge: PlanTrust.pkce(verifier),
            retainedIDToken: existing?.idToken, loginHint: existing?.email
        )
        openBrowser(url)
        let callback = try await withTaskCancellationHandler(operation: {
            try await listener.wait()
        }, onCancel: { listener.cancel() })
        let values = try PlanContract.callbackValues(callback, redirect: redirect,
                          expectedState: challengeState, existingClientID: existing?.clientID)

        let response = try await exchange(fields: [
            ("grant_type", "authorization_code"), ("client_id", values.issuedClientID),
            ("code", values.code), ("code_verifier", verifier),
            ("redirect_uri", redirect.absoluteString), ("resource", PlanContract.resource),
        ])
        guard let jwt = response["id_token"] as? String,
              let access = response["access_token"] as? String,
              let refresh = response["refresh_token"] as? String,
              let scopes = response["scope"] as? String,
              let expiresIn = response["expires_in"] as? NSNumber,
              !access.isEmpty, !refresh.isEmpty, expiresIn.doubleValue > 0 else {
            throw PlanError.invalidToken
        }
        guard Set(scopes.split(separator: " ").map(String.init)).contains("chatgpt.tokens.use.direct") else {
            throw PlanError.permissionMissing
        }
        let identity = try await PlanTrust.validatedID(jwt, clientID: values.issuedClientID,
                                                       nonce: nonce, session: session)
        if let existing, identity.subject != existing.subject { throw PlanError.invalidIdentity }
        let p = PlanProfile(clientID: values.issuedClientID, subject: identity.subject,
                            email: identity.email, idToken: jwt, accessToken: access,
                            refreshToken: refresh, scopes: scopes,
                            expiry: Date().addingTimeInterval(expiresIn.doubleValue))
        var updated = state
        updated.profiles.removeAll(where: { $0.clientID == p.clientID })
        updated.profiles.append(p)
        updated.selected = p.clientID
        try vault.save(updated)
        state = updated
        return PlanAccount(registrationID: p.clientID, email: p.email, subject: p.subject)
    }

    /// Best-effort revocation before removing only this account's local credentials.
    public func disconnectCurrentAccount() async throws {
        guard let id = state.selected,
              let profile = state.profiles.first(where: { $0.clientID == id }) else { return }
        await revokeBestEffort(profile)
        var updated = state
        updated.profiles.removeAll(where: { $0.clientID == id })
        updated.selected = updated.profiles.first?.clientID
        try vault.save(updated)
        state = updated
    }

    private func revokeBestEffort(_ profile: PlanProfile) async {
        let discoveryURL = URL(string: "https://auth.openai.com/.well-known/openid-configuration")!
        var discovery = URLRequest(url: discoveryURL)
        discovery.timeoutInterval = 15
        guard let (data, response) = try? await session.data(for: discovery),
              data.count <= 250_000,
              PlanNetworkPolicy.exactResponse(response, for: discoveryURL),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawURL = object["revocation_endpoint"] as? String,
              let endpoint = URL(string: rawURL), endpoint.scheme == "https",
              endpoint.host == "auth.openai.com",
              PlanNetworkPolicy.isAllowed(endpoint) else { return }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = PlanContract.formBody([
            ("token", profile.refreshToken), ("token_type_hint", "refresh_token"),
            ("client_id", profile.clientID),
        ])
        if let (_, reply) = try? await session.data(for: request),
           !PlanNetworkPolicy.exactResponse(reply, for: endpoint) { return }
    }

    public func availableModels() async throws -> [PlanModel] {
        guard enabledForHostApp else { throw PlanError.disabledUntilApproved }
        let token = try await accessToken()
        var request = URLRequest(url: PlanContract.models)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = 30
        let (data, response) = try await session.data(for: request)
        guard PlanNetworkPolicy.exactResponse(response, for: PlanContract.models),
              let http = response as? HTTPURLResponse else { throw PlanError.serviceUnavailable }
        guard http.statusCode == 200 else {
            throw PlanError.responseRejected(http.statusCode, PlanContract.safeProviderErrorCode(data))
        }
        guard data.count < 2_000_000,
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PlanError.serviceUnavailable
        }
        let models = (root["models"] as? [[String: Any]]) ??
                     (root["data"] as? [[String: Any]]) ?? []
        return models.compactMap { entry in
            let visibility = entry["visibility"] as? String
            guard visibility == nil || visibility == "list",
                  let slug = (entry["slug"] as? String) ?? (entry["id"] as? String),
                  PlanContract.isModelID(slug) else { return nil }
            let name = (entry["display_name"] as? String) ?? slug
            return PlanModel(slug: slug, displayName: name)
        }
    }

    /// Always requires affirmative user authorization for the supplied content. No hidden
    /// account, file, system service, app-group or background-data access exists here.
    public func complete(model: String, messages: [PlanMessage],
                         userApprovedSendingContent: Bool,
                         onText: ((String) -> Void)? = nil) async throws -> PlanResult {
        guard enabledForHostApp else { throw PlanError.disabledUntilApproved }
        guard userApprovedSendingContent else { throw PlanError.permissionMissing }
        lastResponseDiagnostic = PlanResponseDiagnostic(model: model, httpStatus: nil,
                                                        responseKind: "pending", requestID: nil)
        let body = try PlanContract.inferenceBody(model: model, messages: messages)
        let token = try await accessToken()
        var request = URLRequest(url: PlanContract.responses)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        request.httpBody = body
        request.timeoutInterval = 120
        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: request)
        } catch let error as URLError {
            switch error.code {
            case .timedOut: throw PlanError.streamIssue(.timedOut)
            case .notConnectedToInternet, .networkConnectionLost, .cannotFindHost, .cannotConnectToHost:
                throw PlanError.streamIssue(.offline)
            default: throw PlanError.streamIssue(.transportFailed)
            }
        }
        guard PlanNetworkPolicy.exactResponse(response, for: PlanContract.responses),
              let http = response as? HTTPURLResponse else { throw PlanError.serviceUnavailable }
        let mime = (http.value(forHTTPHeaderField: "Content-Type") ?? "").lowercased()
        let kind = mime.contains("text/event-stream") ? "sse" :
                   (mime.contains("application/json") ? "json" : "other")
        let rawID = http.value(forHTTPHeaderField: "x-request-id") ?? ""
        let requestID: String? = rawID.count <= 96 && !rawID.isEmpty &&
            rawID.unicodeScalars.allSatisfy({ CharacterSet(charactersIn:
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-").contains($0) })
                ? rawID : nil
        lastResponseDiagnostic = PlanResponseDiagnostic(model: model, httpStatus: http.statusCode,
                                                        responseKind: kind, requestID: requestID)
        guard http.statusCode == 200 else {
            // HTTP admission failures are short JSON documents, not SSE. Extract
            // only a bounded error code; never log response body or bearer token.
            var errorBytes = Data()
            for try await byte in bytes {
                if errorBytes.count >= 65_536 { break }
                errorBytes.append(byte)
            }
            throw PlanError.responseRejected(http.statusCode, PlanContract.safeProviderErrorCode(errorBytes))
        }
        // Content-Type is advisory. Verify the body before deciding it is not
        // an SSE stream: real responses may have missing or rewritten headers.
        // Do not follow HTTP 200 redirects to a different host as a success.
        guard http.url?.scheme == "https", http.url?.host == "api.openai.com" else {
            lastResponseDiagnostic = PlanResponseDiagnostic(model: model, httpStatus: http.statusCode,
                                                            responseKind: "unexpected_host", requestID: requestID)
            throw PlanError.streamIssue(.unexpectedContentType)
        }
        var decoder = PlanWireDecoder()
        defer {
            let observed = decoder.detectedFormat
            lastResponseDiagnostic = PlanResponseDiagnostic(model: model, httpStatus: http.statusCode,
                responseKind: observed == "unknown" ? kind :
                    kind + "-body-" + observed +
                    (observed == "sse" ? "-frame-" + decoder.lastFrameClass : ""),
                requestID: requestID)
        }
        do {
            var reader = PlanBoundedLineReader()
            for try await byte in bytes {
                try Task.checkCancellation()
                if let line = try reader.accept(byte),
                   let delta = try decoder.acceptLine(line) { onText?(delta) }
            }
            if let finalLine = try reader.finish(),
               let delta = try decoder.acceptLine(finalLine) { onText?(delta) }
        } catch let error as URLError {
            switch error.code {
            case .timedOut: throw PlanError.streamIssue(.timedOut)
            case .notConnectedToInternet, .networkConnectionLost, .cannotFindHost, .cannotConnectToHost:
                throw PlanError.streamIssue(.offline)
            default: throw PlanError.streamIssue(.transportFailed)
            }
        }
        let answer = try decoder.endOfStream()
        return PlanResult(text: answer, model: model)
    }

    private func accessToken() async throws -> String {
        guard let id = state.selected, let index = state.profiles.firstIndex(where: { $0.clientID == id }) else {
            throw PlanError.notConnected
        }
        let p = state.profiles[index]
        guard Set(p.scopes.split(separator: " ").map(String.init)).contains("chatgpt.tokens.use.direct") else {
            throw PlanError.permissionMissing
        }
        if p.expiry.timeIntervalSinceNow > 120 { return p.accessToken }
        let response = try await exchange(fields: [
            ("grant_type", "refresh_token"), ("client_id", p.clientID),
            ("refresh_token", p.refreshToken), ("resource", PlanContract.resource),
        ])
        guard let access = response["access_token"] as? String, !access.isEmpty,
              let expiry = response["expires_in"] as? NSNumber, expiry.doubleValue > 0,
              let refreshed = response["refresh_token"] as? String, !refreshed.isEmpty else {
            throw PlanError.invalidToken
        }
        let scope = (response["scope"] as? String) ?? p.scopes
        guard Set(scope.split(separator: " ").map(String.init)).contains("chatgpt.tokens.use.direct") else {
            throw PlanError.permissionMissing
        }
        var updated = state
        guard let liveIndex = updated.profiles.firstIndex(where: { $0.clientID == id && $0.subject == p.subject }) else {
            throw PlanError.notConnected
        }
        updated.profiles[liveIndex].accessToken = access
        updated.profiles[liveIndex].refreshToken = refreshed
        updated.profiles[liveIndex].expiry = Date().addingTimeInterval(expiry.doubleValue)
        updated.profiles[liveIndex].scopes = scope
        try vault.save(updated)
        state = updated
        return access
    }

    private func exchange(fields: [(String, String)]) async throws -> [String: Any] {
        var request = URLRequest(url: PlanContract.token)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = PlanContract.formBody(fields)
        request.timeoutInterval = 30
        let (data, response) = try await session.data(for: request)
        guard PlanNetworkPolicy.exactResponse(response, for: PlanContract.token),
              let http = response as? HTTPURLResponse else { throw PlanError.authorizationFailed }
        // Never include raw endpoint errors in diagnostics: they may contain credentials.
        guard http.statusCode == 200 else { throw PlanError.authorizationFailed }
        guard data.count < 512_000,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PlanError.invalidToken
        }
        return json
    }
}
#endif
