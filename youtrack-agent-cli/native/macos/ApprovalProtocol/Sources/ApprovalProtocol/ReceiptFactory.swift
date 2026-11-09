import func Foundation.floor
import struct Foundation.Calendar
import struct Foundation.Data
import struct Foundation.Date
import struct Foundation.TimeZone
import typealias Foundation.TimeInterval

public struct EnrolledSigningKey: Equatable, Sendable {
    public let generation: String
    public let spkiDER: Data
    public let fingerprintSHA256: String

    public init(generation: String, spkiDER input: Data) throws {
        let x963 = try P256PublicKeyCodec.x963(fromSPKIDER: input)
        let copied = input.withUnsafeBytes { Data($0) }
        guard ProtocolGrammar.isKeyGeneration(generation) else {
            throw ApprovalProtocolError.invalidField("key_generation")
        }
        self.generation = generation
        spkiDER = copied
        fingerprintSHA256 = try P256PublicKeyCodec.fingerprintSHA256(x963: x963)
    }
}

public protocol ApprovalSigner: AnyObject {
    var enrolledKey: EnrolledSigningKey { get }
    func sign(message: Data) throws -> Data
}

public protocol CryptographicRandomSource {
    func randomBytes(count: Int) throws -> Data
}

public protocol ApprovalClock {
    func now() -> Date
}

public enum ApprovalReceiptFactory {
    public static func makeReceipt(
        for snapshot: ValidatedPlanSnapshot,
        challenge: ApprovalIPCChallenge,
        expectedBinding: ExpectedReceiptBinding,
        signer: any ApprovalSigner,
        random: any CryptographicRandomSource,
        clock: any ApprovalClock
    ) throws -> ApprovalReceipt {
        let identity = signer.enrolledKey
        guard ProtocolGrammar.keyGenerationRevision(identity.generation) == expectedBinding.registryRevision else {
            throw ApprovalProtocolError.invalidField("expected receipt binding")
        }
        let receiptID = try identifier(prefix: "YTAR-", random: random)
        let nonce = try identifier(prefix: "YTAN-", random: random)
        let issued = floor(clock.now().timeIntervalSince1970)
        guard issued.isFinite, issued >= -62_135_596_800, issued < 253_402_300_800 else {
            throw ApprovalProtocolError.invalidField("issued_at")
        }
        let issuedAt = try utcString(seconds: Int64(issued))
        let expiresAt = try utcString(seconds: Int64(issued) + 120)
        let binding = snapshot.bindings
        let unsigned = try UnsignedApprovalReceipt(
            receiptID: receiptID, nonce: nonce, challengeSHA256: challenge.sha256,
            registryRevision: expectedBinding.registryRevision,
            authorizationContextSHA256: expectedBinding.authorizationContextSHA256,
            planID: binding.planID,
            planSHA256: binding.planSHA256, profileIdentitySHA256: binding.profileIdentitySHA256,
            accountID: binding.accountID, projectID: binding.projectID, projectKey: binding.projectKey,
            schemaSHA256: binding.schemaSHA256, requestSHA256: binding.requestSHA256,
            expectedSHA256: binding.expectedSHA256, issuedAt: issuedAt, expiresAt: expiresAt,
            keyGeneration: identity.generation, keyFingerprintSHA256: identity.fingerprintSHA256
        )
        let message = unsigned.encodedSigningBytes()
        let signerOutput = try signer.sign(message: message) // Exactly one signing call.
        let signature = try P256Signature.normalizeLowS(der: signerOutput)
        let x963 = try P256PublicKeyCodec.x963(fromSPKIDER: identity.spkiDER)
        guard try P256PublicKeyCodec.verify(message: message, derSignature: signature.der, x963: x963) else {
            throw ApprovalProtocolError.invalidSignature
        }
        return try ApprovalReceipt(unsigned: unsigned, signatureDER: signature.der)
    }

    private static func identifier(prefix: String, random: any CryptographicRandomSource) throws -> String {
        let bytes = try random.randomBytes(count: 16)
        guard bytes.count == 16 else { throw ApprovalProtocolError.invalidField("random") }
        return try ProtocolGrammar.base32ID(prefix: prefix, bytes: bytes)
    }

    private static func utcString(seconds: Int64) throws -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        guard let year = c.year, (1...9999).contains(year), let month = c.month, let day = c.day,
              let hour = c.hour, let minute = c.minute, let second = c.second
        else { throw ApprovalProtocolError.invalidField("issued_at") }
        return String(format: "%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour, minute, second)
    }
}
