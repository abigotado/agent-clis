public enum ApprovalProtocolError: Error, Equatable, Sendable {
    case inputTooLarge(limit: Int)
    case malformedJSON
    case duplicateField(String)
    case unknownField(String)
    case missingField(String)
    case invalidField(String)
    case nonCanonicalEncoding
    case invalidPublicKey
    case invalidSignature
    case invalidEscapedBytes
}
