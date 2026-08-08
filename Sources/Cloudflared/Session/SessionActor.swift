public struct RetryPolicy: Sendable, Equatable {
    public let maxReconnectAttempts: Int
    public let baseDelayNanoseconds: UInt64

    public init(maxReconnectAttempts: Int = 0, baseDelayNanoseconds: UInt64 = 250_000_000) {
        self.maxReconnectAttempts = max(0, maxReconnectAttempts)
        self.baseDelayNanoseconds = baseDelayNanoseconds
    }

    public func delayNanoseconds(for attempt: Int) -> UInt64 {
        let multiplier = UInt64(max(1, attempt))
        let (delay, overflow) = baseDelayNanoseconds.multipliedReportingOverflow(by: multiplier)
        return overflow ? UInt64.max : delay
    }
}

public actor SessionActor: Client {
    private struct SupersededConnection: Error {}

    public nonisolated let state: AsyncStream<ConnectionState>

    private let authProvider: any AuthProviding
    private let tunnelProvider: any TunnelProviding
    private let retryPolicy: RetryPolicy
    private let oauthFallback: (@Sendable (String) -> AuthMethod?)?
    private let sleep: @Sendable (UInt64) async -> Void

    private var continuation: AsyncStream<ConnectionState>.Continuation?
    private var currentState: ConnectionState = .idle
    private var connectionGeneration: UInt64 = 0

    public init(
        authProvider: any AuthProviding,
        tunnelProvider: any TunnelProviding,
        retryPolicy: RetryPolicy,
        oauthFallback: (@Sendable (String) -> AuthMethod?)?,
        sleep: @escaping @Sendable (UInt64) async -> Void
    ) {
        var localContinuation: AsyncStream<ConnectionState>.Continuation?
        self.state = AsyncStream { continuation in
            continuation.yield(.idle)
            localContinuation = continuation
        }

        self.continuation = localContinuation
        self.authProvider = authProvider
        self.tunnelProvider = tunnelProvider
        self.retryPolicy = retryPolicy
        self.oauthFallback = oauthFallback
        self.sleep = sleep
        self.currentState = .idle
    }

    public nonisolated static func noopSleep(_: UInt64) async {}

    public func connect(hostname: String, method: AuthMethod) async throws -> UInt16 {
        guard canStartConnection(from: currentState) else {
            let failure = Failure.invalidState("cannot connect from state \(currentState)")
            publish(.failed(failure))
            throw failure
        }

        connectionGeneration &+= 1
        let generation = connectionGeneration

        let originURL = try URLTools.normalizeOriginURL(from: hostname)
        let normalizedHost = originURL.host!

        do {
            return try await connectWithMethod(
                hostname: normalizedHost,
                method: method,
                generation: generation
            )
        } catch is SupersededConnection {
            throw CancellationError()
        } catch {
            if case .serviceToken = method, let fallbackMethod = oauthFallback?(hostname) {
                do {
                    return try await connectWithMethod(
                        hostname: normalizedHost,
                        method: fallbackMethod,
                        generation: generation
                    )
                } catch is SupersededConnection {
                    throw CancellationError()
                } catch {
                    let failure = toFailure(error)
                    publish(.failed(failure))
                    throw failure
                }
            }

            let failure = toFailure(error)
            publish(.failed(failure))
            throw failure
        }
    }

    public func disconnect() async {
        connectionGeneration &+= 1
        await tunnelProvider.close()
        publish(.disconnected)
    }

    private func connectWithMethod(
        hostname: String,
        method: AuthMethod,
        generation: UInt64
    ) async throws -> UInt16 {
        try ensureCurrent(generation)
        publish(.authenticating)
        let authContext = try await authProvider.authenticate(hostname: hostname, method: method)
        try ensureCurrent(generation)

        var attempt = 0
        var lastFailure = Failure.transport("connection attempts exhausted", retryable: false)
        while attempt <= retryPolicy.maxReconnectAttempts {
            try ensureCurrent(generation)
            publish(.connecting)
            do {
                let localPort = try await tunnelProvider.open(hostname: hostname, authContext: authContext, method: method)
                guard isCurrent(generation) else {
                    await tunnelProvider.close()
                    throw SupersededConnection()
                }
                publish(.connected(localPort: localPort))
                return localPort
            } catch {
                guard isCurrent(generation) else {
                    throw SupersededConnection()
                }
                let failure = toFailure(error)
                lastFailure = failure
                guard failure.isRetryable, attempt < retryPolicy.maxReconnectAttempts else {
                    break
                }

                attempt += 1
                publish(.reconnecting(attempt: attempt))
                await sleep(retryPolicy.delayNanoseconds(for: attempt))
            }
        }

        throw lastFailure
    }

    private func ensureCurrent(_ generation: UInt64) throws {
        guard isCurrent(generation) else {
            throw SupersededConnection()
        }
    }

    private func isCurrent(_ generation: UInt64) -> Bool {
        connectionGeneration == generation
    }

    private func canStartConnection(from state: ConnectionState) -> Bool {
        switch state {
        case .idle, .disconnected, .failed:
            return true
        default:
            return false
        }
    }

    private func toFailure(_ error: Error) -> Failure {
        if let failure = error as? Failure {
            return failure
        }

        return .internalError(String(describing: error))
    }

    private func publish(_ newState: ConnectionState) {
        currentState = newState
        continuation?.yield(newState)
    }
}
