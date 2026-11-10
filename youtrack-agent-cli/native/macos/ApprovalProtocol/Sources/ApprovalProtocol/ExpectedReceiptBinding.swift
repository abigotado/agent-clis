/// Caller-supplied comparison claims, not verified registry authority or ledger state.
public struct ExpectedReceiptBinding: Equatable, Sendable {
    public let registryRevision: Int
    public let authorizationContextSHA256: String

    public init(registryRevision: Int, authorizationContextSHA256: String) throws {
        guard (1...ProtocolGrammar.maximumRegistryRevision).contains(registryRevision), ProtocolGrammar.isDigest(authorizationContextSHA256) else {
            throw ApprovalProtocolError.invalidField("expected receipt binding")
        }
        self.registryRevision = registryRevision
        self.authorizationContextSHA256 = authorizationContextSHA256
    }
}
