#if canImport(Network)
import Foundation
import Network

/// A one-use, loopback-only HTTP listener. It never sends authorization data to its HTML page.
internal final class PlanLoopback: @unchecked Sendable {
    private let queue = DispatchQueue(label: "openplan.loopback.serial")
    private var listener: NWListener?
    private var ready: CheckedContinuation<URL, Error>?
    private var waiter: CheckedContinuation<URL, Error>?
    private var result: Result<URL, Error>?
    private var expectedState = ""
    private var existingClientID: String?
    private var port: UInt16 = 0

    func start(state: String, existingClientID: String? = nil) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.expectedState = state
                self.existingClientID = existingClientID
                self.ready = continuation
                do {
                    let params = NWParameters.tcp
                    params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
                    let listener = try NWListener(using: params)
                    self.listener = listener
                    listener.stateUpdateHandler = { [weak self] state in
                        guard let self else { return }
                        switch state {
                        case .ready:
                            guard let raw = listener.port?.rawValue, raw != 0 else {
                                self.ready?.resume(throwing: PlanError.serviceUnavailable)
                                self.ready = nil
                                return
                            }
                            self.port = raw
                            self.ready?.resume(returning: URL(string: "http://127.0.0.1:\(raw)/auth/callback")!)
                            self.ready = nil
                        case .failed:
                            if let ready = self.ready {
                                ready.resume(throwing: PlanError.serviceUnavailable)
                                self.ready = nil
                            } else { self.finish(.failure(PlanError.serviceUnavailable)) }
                        default: break
                        }
                    }
                    listener.newConnectionHandler = { [weak self] connection in
                        self?.receive(connection, bytes: Data())
                    }
                    listener.start(queue: self.queue)
                    self.queue.asyncAfter(deadline: .now() + 180) {
                        self.finish(.failure(PlanError.expiredSignIn))
                    }
                } catch {
                    self.ready?.resume(throwing: PlanError.serviceUnavailable)
                    self.ready = nil
                }
            }
        }
    }

    func wait() async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                if let result = self.result { continuation.resume(with: result) }
                else { self.waiter = continuation }
            }
        }
    }

    func cancel() {
        queue.async { self.finish(.failure(PlanError.cancelled)) }
    }

    private func finish(_ value: Result<URL, Error>) {
        guard result == nil else { return }
        result = value
        listener?.cancel()
        listener = nil
        if let ready { ready.resume(throwing: PlanError.cancelled); self.ready = nil }
        waiter?.resume(with: value)
        waiter = nil
    }

    private func receive(_ connection: NWConnection, bytes: Data) {
        connection.start(queue: queue)
        consume(connection, bytes: bytes)
    }

    private func consume(_ connection: NWConnection, bytes: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 2048) { [weak self] chunk, _, complete, error in
            guard let self else { return }
            var input = bytes
            if let chunk { input.append(chunk) }
            if input.count > 8192 || complete || error != nil {
                self.respond(connection, status: 400, accepted: nil)
                return
            }
            if input.range(of: Data("\r\n\r\n".utf8)) != nil {
                self.handle(connection, request: input)
            } else {
                self.consume(connection, bytes: input)
            }
        }
    }

    private func handle(_ connection: NWConnection, request: Data) {
        guard let text = String(data: request, encoding: .utf8),
              let headerEnd = text.range(of: "\r\n\r\n") else {
            respond(connection, status: 400, accepted: nil)
            return
        }
        let headers = text[..<headerEnd.lowerBound].components(separatedBy: "\r\n")
        guard let first = headers.first else { respond(connection, status: 400, accepted: nil); return }
        let parts = first.split(separator: " ").map(String.init)
        let validHost = headers.dropFirst().contains(where: {
            $0.lowercased() == "host: 127.0.0.1:\(port)"
        })
        guard parts.count == 3, parts[0] == "GET", parts[2] == "HTTP/1.1", validHost,
              parts[1].hasPrefix("/auth/callback?"),
              let url = URL(string: "http://127.0.0.1:\(port)\(parts[1])"),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let items = components.queryItems,
              items.filter({ $0.name == "state" }).count == 1 else {
            respond(connection, status: 400, accepted: nil)
            return
        }
        // Do not consume the one-use callback on an invalid same-state URL.
        // The full parser rejects duplicate keys, missing codes, bad client
        // identifiers and paths; legitimate OAuth error callbacks may terminate.
        let redirect = URL(string: "http://127.0.0.1:\(port)/auth/callback")!
        do {
            _ = try PlanContract.callbackValues(url, redirect: redirect,
                expectedState: expectedState, existingClientID: existingClientID)
        } catch PlanError.authorizationFailed {
            // Valid state with provider-denied authorization is terminal.
        } catch {
            respond(connection, status: 400, accepted: nil)
            return
        }
        respond(connection, status: 200, accepted: url)
    }

    private func respond(_ connection: NWConnection, status: Int, accepted: URL?) {
        let body = status == 200
            ? "<!doctype html><title>Connected</title><p>Authorization received. Return to your application.</p>"
            : "<!doctype html><title>Not accepted</title><p>Invalid request.</p>"
        let phrase = status == 200 ? "OK" : "Bad Request"
        let data = Data(body.utf8)
        let header = "HTTP/1.1 \(status) \(phrase)\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff\r\nContent-Length: \(data.count)\r\nConnection: close\r\n\r\n"
        connection.send(content: Data(header.utf8) + data, completion: .contentProcessed { _ in
            connection.cancel()
        })
        if let accepted { finish(.success(accepted)) }
    }
}
#endif
