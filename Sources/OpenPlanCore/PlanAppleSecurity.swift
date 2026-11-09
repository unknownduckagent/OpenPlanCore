#if canImport(Security) && canImport(CryptoKit)
import Foundation
import Security
import CryptoKit

internal struct PlanProfile: Codable {
    var clientID: String
    var subject: String
    var email: String?
    var idToken: String
    var accessToken: String
    var refreshToken: String
    var scopes: String
    var expiry: Date
}

internal struct PlanVaultData: Codable {
    var hostID: String
    var selected: String?
    var profiles: [PlanProfile]
}

internal final class PlanKeychainVault {
    private let service: String
    private let account = "credentials.v1"

    init(service: String) throws {
        guard !service.isEmpty, service.count <= 160,
              service.unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-").contains($0) }) else {
            throw PlanError.invalidInput
        }
        self.service = service
    }

    func load() throws -> PlanVaultData {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        let code = SecItemCopyMatching(base as CFDictionary, &result)
        if code == errSecItemNotFound {
            return PlanVaultData(hostID: "urn:uuid:\(UUID().uuidString.lowercased())",
                                 selected: nil, profiles: [])
        }
        guard code == errSecSuccess, let bytes = result as? Data,
              let state = try? JSONDecoder().decode(PlanVaultData.self, from: bytes),
              state.hostID.hasPrefix("urn:uuid:") else { throw PlanError.invalidToken }
        return state
    }

    func save(_ state: PlanVaultData) throws {
        let bytes = try JSONEncoder().encode(state)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attrs: [String: Any] = [kSecValueData as String: bytes]
        let status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw PlanError.invalidToken }
        var add = query
        add[kSecValueData as String] = bytes
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecAttrSynchronizable as String] = kCFBooleanFalse
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw PlanError.invalidToken }
    }
}

internal enum PlanTrust {
    static func random(_ count: Int = 32) throws -> String {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw PlanError.invalidToken
        }
        return urlSafe(Data(bytes))
    }

    static func pkce(_ verifier: String) -> String {
        urlSafe(Data(SHA256.hash(data: Data(verifier.utf8))))
    }

    private static func urlSafe(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func decode(_ text: String) -> Data? {
        guard !text.isEmpty, text.count <= 100_000,
              text.unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_").contains($0) }) else { return nil }
        var b64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
        return Data(base64Encoded: b64)
    }

    static func validatedID(_ jwt: String, clientID: String, nonce: String,
                            session: URLSession) async throws -> (subject: String, email: String?) {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3,
              let headerBytes = decode(parts[0]), let payloadBytes = decode(parts[1]),
              let signature = decode(parts[2]),
              let header = try? JSONSerialization.jsonObject(with: headerBytes) as? [String: Any],
              let payload = try? JSONSerialization.jsonObject(with: payloadBytes) as? [String: Any],
              (header["alg"] as? String) == "RS256", let kid = header["kid"] as? String,
              !kid.isEmpty else { throw PlanError.invalidIdentity }

        var request = URLRequest(url: PlanContract.keys)
        request.timeoutInterval = 20
        let (jwksBytes, response) = try await session.data(for: request)
        guard jwksBytes.count <= 250_000,
              let http = response as? HTTPURLResponse, http.statusCode == 200,
              http.url?.absoluteString == PlanContract.keys.absoluteString,
              let root = try? JSONSerialization.jsonObject(with: jwksBytes) as? [String: Any],
              let keys = root["keys"] as? [[String: Any]],
              let key = keys.first(where: { ($0["kid"] as? String) == kid &&
                  ($0["kty"] as? String) == "RSA" &&
                  (($0["alg"] as? String) ?? "RS256") == "RS256" }),
              let n = key["n"] as? String, let e = key["e"] as? String,
              let modulus = decode(n), let exponent = decode(e),
              modulus.count >= 256, exponent.count <= 8 else { throw PlanError.invalidIdentity }

        let publicKey = try rsaKey(modulus: modulus, exponent: exponent)
        let signed = Data("\(parts[0]).\(parts[1])".utf8)
        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256,
                                     signed as CFData, signature as CFData, &error) else {
            throw PlanError.invalidIdentity
        }

        let now = Date().timeIntervalSince1970
        let exp = (payload["exp"] as? NSNumber)?.doubleValue ?? 0
        let issued = (payload["iat"] as? NSNumber)?.doubleValue ?? 0
        let audience: [String]
        if let single = payload["aud"] as? String { audience = [single] }
        else { audience = (payload["aud"] as? [String]) ?? [] }
        guard payload["iss"] as? String == "https://auth.openai.com",
              audience.contains(clientID),
              (audience.count <= 1 || payload["azp"] as? String == clientID),
              payload["nonce"] as? String == nonce,
              exp > now - 5, issued > 0, issued <= now + 5,
              let subject = payload["sub"] as? String, !subject.isEmpty,
              subject.count <= 500 else { throw PlanError.invalidIdentity }
        return (subject, payload["email"] as? String)
    }

    private static func rsaKey(modulus: Data, exponent: Data) throws -> SecKey {
        let pkcs1 = der(0x30, der(0x02, unsigned(modulus)) + der(0x02, unsigned(exponent)))
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: modulus.count * 8,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, &error) else {
            throw PlanError.invalidIdentity
        }
        return key
    }

    private static func unsigned(_ raw: Data) -> Data {
        var bytes = raw
        while bytes.count > 1 && bytes.first == 0 { bytes.removeFirst() }
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        return bytes
    }
    private static func der(_ tag: UInt8, _ content: Data) -> Data {
        var output = Data([tag])
        let length = content.count
        if length < 128 { output.append(UInt8(length)) }
        else {
            var number = length
            var octets = [UInt8]()
            while number > 0 { octets.insert(UInt8(number & 0xFF), at: 0); number >>= 8 }
            output.append(UInt8(0x80 | octets.count))
            output.append(contentsOf: octets)
        }
        output.append(content)
        return output
    }
}
#endif
