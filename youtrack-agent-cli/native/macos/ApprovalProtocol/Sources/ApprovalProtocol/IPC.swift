import func Foundation.floor
import struct Foundation.Data
import struct Foundation.Date

public struct ApprovalIPCChallenge: Equatable, Sendable {
    public static let byteCount = 32
    private let storage: Data

    public init(bytes input: Data) throws {
        guard input.count == Self.byteCount else { throw ApprovalProtocolError.invalidField("challenge") }
        storage = input.withUnsafeBytes { Data($0) }
    }

    func bytes() -> Data { storage }
    public var sha256: String { ProtocolGrammar.sha256(storage) }

    public func constantTimeEquals(_ other: ApprovalIPCChallenge) -> Bool {
        zip(storage, other.storage).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}

public enum ApprovalIPCErrorCode: UInt8, Equatable, Sendable {
    case userCanceled = 1
    case requestInvalid = 2
    case userPresenceUnavailable = 3
    case keyUnavailable = 4
    case signingFailed = 5
    case internalFailure = 6
}

public struct ApprovalIPCSuccess: Equatable, Sendable {
    public let enrolledKey: EnrolledSigningKey
    public let receipt: ApprovalReceipt
}

public enum ApprovalIPCResponse: Equatable, Sendable {
    case success(ApprovalIPCSuccess)
    case failure(ApprovalIPCErrorCode)
}

public enum ApprovalIPCCodec {
    private static let magic = Data([0x59, 0x54, 0x41, 0x50, 0x49, 0x50, 0x43, 0x00])
    private static let headerBytes = 16

    public static func encodeRequest(challenge: ApprovalIPCChallenge, snapshot: ValidatedPlanSnapshot) -> Data {
        var payload = challenge.bytes()
        payload.append(snapshot.exactBytes())
        return frame(kind: 1, payload: payload)
    }

    public static func decodeRequest(_ input: Data) throws -> (ApprovalIPCChallenge, ValidatedPlanSnapshot) {
        let payload = try decodeFrame(input, expectedKind: 1, maximumPayload: 32 + ValidatedPlanSnapshot.maximumBytes)
        guard payload.count >= 33 else { throw ApprovalProtocolError.invalidField("request frame") }
        let challenge = try ApprovalIPCChallenge(bytes: Data(payload.prefix(32)))
        let snapshot: ValidatedPlanSnapshot
        do {
            snapshot = try ValidatedPlanSnapshot(canonicalBytes: Data(payload.dropFirst(32)))
        } catch {
            throw ApprovalProtocolError.malformedJSON
        }
        return (challenge, snapshot)
    }

    public static func encodeSuccess(
        challenge: ApprovalIPCChallenge,
        enrolledKey: EnrolledSigningKey,
        receipt: ApprovalReceipt
    ) -> Data {
        var payload = challenge.bytes()
        payload.append(enrolledKey.spkiDER)
        payload.append(receipt.encodedReceiptBytes())
        return frame(kind: 2, payload: payload)
    }

    public static func encodeFailure(challenge: ApprovalIPCChallenge, code: ApprovalIPCErrorCode) -> Data {
        var payload = challenge.bytes()
        payload.append(code.rawValue)
        return frame(kind: 3, payload: payload)
    }

    public static func decodeAndValidateResponse(
        _ input: Data,
        expectedChallenge: ApprovalIPCChallenge,
        snapshot: ValidatedPlanSnapshot,
        expectedKey: EnrolledSigningKey,
        expectedBinding: ExpectedReceiptBinding,
        now: Date
    ) throws -> ApprovalIPCResponse {
        let header = try parseHeader(input)
        switch header.kind {
        case 2:
            let payload = try decodeFrame(input, expectedKind: 2, maximumPayload: 32 + 91 + ApprovalReceipt.maximumReceiptBytes)
            guard payload.count >= 124 else { throw ApprovalProtocolError.invalidField("success frame") }
            let challenge = try ApprovalIPCChallenge(bytes: Data(payload.prefix(32)))
            guard challenge.constantTimeEquals(expectedChallenge) else { throw ApprovalProtocolError.invalidField("challenge") }
            guard ProtocolGrammar.keyGenerationRevision(expectedKey.generation) == expectedBinding.registryRevision else {
                throw ApprovalProtocolError.invalidField("expected receipt binding")
            }
            let spki = Data(payload.dropFirst(32).prefix(91))
            guard spki == expectedKey.spkiDER else { throw ApprovalProtocolError.invalidPublicKey }
            let receipt = try ApprovalReceipt(receiptBytes: Data(payload.dropFirst(123)))
            try validate(
                receipt: receipt, expectedChallenge: expectedChallenge,
                expectedKey: expectedKey, expectedBinding: expectedBinding, snapshot: snapshot, now: now
            )
            return .success(ApprovalIPCSuccess(enrolledKey: expectedKey, receipt: receipt))
        case 3:
            let payload = try decodeFrame(input, expectedKind: 3, maximumPayload: 33)
            guard payload.count == 33 else { throw ApprovalProtocolError.invalidField("error frame") }
            let challenge = try ApprovalIPCChallenge(bytes: Data(payload.prefix(32)))
            guard challenge.constantTimeEquals(expectedChallenge), let rawCode = payload.last,
                  let code = ApprovalIPCErrorCode(rawValue: rawCode) else {
                throw ApprovalProtocolError.invalidField("error frame")
            }
            return .failure(code)
        default:
            throw ApprovalProtocolError.invalidField("response kind")
        }
    }

    private static func validate(
        receipt: ApprovalReceipt,
        expectedChallenge: ApprovalIPCChallenge,
        expectedKey: EnrolledSigningKey,
        expectedBinding: ExpectedReceiptBinding,
        snapshot: ValidatedPlanSnapshot,
        now: Date
    ) throws {
        let receiptBinding = receipt.unsigned
        let plan = snapshot.bindings
        // Direct revision equality remains defense in depth alongside generation checks.
        guard receiptBinding.planID == plan.planID,
              receiptBinding.registryRevision == expectedBinding.registryRevision,
              receiptBinding.authorizationContextSHA256 == expectedBinding.authorizationContextSHA256,
              receiptBinding.planSHA256 == plan.planSHA256,
              receiptBinding.profileIdentitySHA256 == plan.profileIdentitySHA256,
              receiptBinding.accountID == plan.accountID,
              receiptBinding.projectID == plan.projectID,
              receiptBinding.projectKey == plan.projectKey,
              receiptBinding.schemaSHA256 == plan.schemaSHA256,
              receiptBinding.requestSHA256 == plan.requestSHA256,
              receiptBinding.expectedSHA256 == plan.expectedSHA256,
              receiptBinding.challengeSHA256 == expectedChallenge.sha256,
              receiptBinding.keyGeneration == expectedKey.generation,
              receiptBinding.keyFingerprintSHA256 == expectedKey.fingerprintSHA256,
              let issued = UnsignedApprovalReceipt.wholeSecondUTCValue(receiptBinding.issuedAt),
              let expires = UnsignedApprovalReceipt.wholeSecondUTCValue(receiptBinding.expiresAt),
              expires > issued, expires - issued <= 300
        else { throw ApprovalProtocolError.invalidField("receipt binding") }
        let currentSeconds = floor(now.timeIntervalSince1970)
        guard currentSeconds.isFinite,
              currentSeconds >= -62_135_596_800,
              currentSeconds < 253_402_300_800
        else { throw ApprovalProtocolError.invalidField("current time") }
        let current = Int64(currentSeconds)
        guard issued <= current + 30, current < expires else { throw ApprovalProtocolError.invalidField("receipt ttl") }
        let x963 = try P256PublicKeyCodec.x963(fromSPKIDER: expectedKey.spkiDER)
        let signature = try P256Signature(derBase64URL: receipt.signature)
        guard try P256PublicKeyCodec.verify(
            message: receiptBinding.encodedSigningBytes(), derSignature: signature.der, x963: x963
        ) else { throw ApprovalProtocolError.invalidSignature }
    }

    private static func frame(kind: UInt8, payload: Data) -> Data {
        var output = magic
        output.append(2)
        output.append(kind)
        output.append(contentsOf: [0, 0])
        let length = UInt32(payload.count)
        output.append(contentsOf: [
            UInt8((length >> 24) & 0xFF), UInt8((length >> 16) & 0xFF),
            UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF),
        ])
        output.append(payload)
        return output
    }

    private static func parseHeader(_ input: Data) throws -> (kind: UInt8, length: Int) {
        let header = Array(input.prefix(headerBytes))
        guard header.count == headerBytes, Data(header.prefix(8)) == magic, header[8] == 2,
              header[10] == 0, header[11] == 0 else { throw ApprovalProtocolError.invalidField("frame header") }
        let length = Int(header[12]) << 24 | Int(header[13]) << 16 | Int(header[14]) << 8 | Int(header[15])
        return (header[9], length)
    }

    private static func decodeFrame(_ input: Data, expectedKind: UInt8, maximumPayload: Int) throws -> Data {
        let header = try parseHeader(input)
        guard header.kind == expectedKind, header.length <= maximumPayload,
              input.count == headerBytes + header.length
        else { throw ApprovalProtocolError.invalidField("frame") }
        return input.dropFirst(headerBytes)
    }
}
