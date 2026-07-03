import Foundation

public protocol TokenClock: Sendable {
    var now: Date { get }
}

public struct SystemClock: TokenClock {
    public init() {}

    public var now: Date {
        Date()
    }
}

public struct JWTValidator: Sendable {
    private let clock: any TokenClock

    public init(clock: any TokenClock = SystemClock()) {
        self.clock = clock
    }

    public func isExpired(_ token: String) throws -> Bool {
        let claims = try temporalClaims(from: token)
        if let notBefore = claims.notBefore, notBefore > clock.now {
            throw Failure.auth("token is not yet valid")
        }
        return claims.expiration <= clock.now
    }

    public func expirationDate(from token: String) throws -> Date {
        try temporalClaims(from: token).expiration
    }

    public func validate(
        _ token: String,
        expectedAudience: String,
        expectedIssuerHost: String
    ) throws {
        let claims = try claims(from: token)
        let temporalClaims = try temporalClaims(from: claims)
        guard temporalClaims.expiration > clock.now else {
            throw Failure.auth("token is expired")
        }
        if let notBefore = temporalClaims.notBefore, notBefore > clock.now {
            throw Failure.auth("token is not yet valid")
        }

        let audiences: [String]
        if let audience = claims["aud"] as? String {
            audiences = [audience]
        } else if let values = claims["aud"] as? [String] {
            audiences = values
        } else {
            throw Failure.auth("token missing aud claim")
        }
        guard audiences.contains(expectedAudience) else {
            throw Failure.auth("token audience does not match Access application")
        }

        guard let issuer = claims["iss"] as? String,
              let issuerHost = URL(string: issuer)?.host,
              issuerHost.caseInsensitiveCompare(expectedIssuerHost) == .orderedSame else {
            throw Failure.auth("token issuer does not match Access team")
        }
    }

    private func temporalClaims(from token: String) throws -> (expiration: Date, notBefore: Date?) {
        try temporalClaims(from: claims(from: token))
    }

    private func claims(from token: String) throws -> [String: Any] {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty }) else {
            throw Failure.auth("token is not a JWT")
        }

        let payloadData = try decodeBase64URL(String(parts[1]))
        let payload = try JSONSerialization.jsonObject(with: payloadData, options: [])

        guard let object = payload as? [String: Any] else {
            throw Failure.auth("invalid JWT payload")
        }
        return object
    }

    private func temporalClaims(from claims: [String: Any]) throws -> (expiration: Date, notBefore: Date?) {
        guard let exp = numericDate(claims["exp"]) else {
            throw Failure.auth("token missing exp claim")
        }

        let notBefore = numericDate(claims["nbf"]).map(Date.init(timeIntervalSince1970:))
        return (Date(timeIntervalSince1970: exp), notBefore)
    }

    private func numericDate(_ value: Any?) -> TimeInterval? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else {
            return nil
        }
        let result = number.doubleValue
        return result.isFinite ? result : nil
    }

    private func decodeBase64URL(_ value: String) throws -> Data {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }

        guard let data = Data(base64Encoded: base64) else {
            throw Failure.auth("invalid JWT payload encoding")
        }

        return data
    }
}
