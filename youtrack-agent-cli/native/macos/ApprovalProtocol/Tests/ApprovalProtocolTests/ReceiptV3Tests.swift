import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

func receiptBindingForTest() throws -> ExpectedReceiptBinding {
    try ExpectedReceiptBinding(registryRevision: 1, authorizationContextSHA256: String(repeating: "a", count: 64))
}

@Test func sharedReceiptV3RevisionCorpus() throws {
    struct Vector: Decodable { let name: String; let accepted: Bool; let signing: String; let receipt: String }
    let vectors = try JSONDecoder().decode([Vector].self, from: v3Fixture("revision-boundaries.json"))
    try #require(vectors.count == 3)
    for vector in vectors {
        if vector.accepted {
            let unsigned = try UnsignedApprovalReceipt(signingBytes: Data(vector.signing.utf8))
            let receipt = try ApprovalReceipt(receiptBytes: Data(vector.receipt.utf8))
            #expect(receipt.unsigned == unsigned)
            #expect(unsigned.encodedSigningBytes() == Data(vector.signing.utf8))
            #expect(receipt.encodedReceiptBytes() == Data(vector.receipt.utf8))
        } else {
            #expect(throws: ApprovalProtocolError.self, "accepted \(vector.name)") { _ = try UnsignedApprovalReceipt(signingBytes: Data(vector.signing.utf8)) }
            #expect(throws: ApprovalProtocolError.self, "accepted \(vector.name)") { _ = try ApprovalReceipt(receiptBytes: Data(vector.receipt.utf8)) }
        }
    }
    #expect(throws: ApprovalProtocolError.self) {
        _ = try EnrolledSigningKey(generation: "YTAG-00000000000000000257", spkiDER: v3Hex(sharedFixture("public-key.spki.hex")))
    }
}

@Test func IPCFailureUnionDoesNotRequireMatchingSigningRevision() throws {
    let (challenge, snapshot) = try ApprovalIPCCodec.decodeRequest(v3Hex(sharedFixture("ipc-request.hex")))
    let key = try EnrolledSigningKey(generation: "YTAG-00000000000000000001", spkiDER: v3Hex(sharedFixture("public-key.spki.hex")))
    let binding = try ExpectedReceiptBinding(registryRevision: 2, authorizationContextSHA256: String(repeating: "a", count: 64))
    for code in [ApprovalIPCErrorCode.userCanceled, .requestInvalid, .userPresenceUnavailable, .keyUnavailable, .signingFailed, .internalFailure] {
        let frame = ApprovalIPCCodec.encodeFailure(challenge: challenge, code: code)
        #expect(try ApprovalIPCCodec.decodeAndValidateResponse(frame, expectedChallenge: challenge, snapshot: snapshot, expectedKey: key, expectedBinding: binding, now: Date()) == .failure(code))
        var changedChallenge = challenge.bytes(); changedChallenge[0] ^= 1
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ApprovalIPCCodec.decodeAndValidateResponse(frame, expectedChallenge: ApprovalIPCChallenge(bytes: changedChallenge), snapshot: snapshot, expectedKey: key, expectedBinding: binding, now: Date())
        }
        var unknown = frame; unknown[unknown.count - 1] = 255
        for malformed in [Data(frame.dropLast()), frame + Data([0]), unknown] {
            #expect(throws: ApprovalProtocolError.self) {
                _ = try ApprovalIPCCodec.decodeAndValidateResponse(malformed, expectedChallenge: challenge, snapshot: snapshot, expectedKey: key, expectedBinding: binding, now: Date())
            }
        }
    }
    #expect(throws: ApprovalProtocolError.invalidField("expected receipt binding")) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(v3Hex(v3Fixture("ipc-success.hex")), expectedChallenge: challenge, snapshot: snapshot, expectedKey: key, expectedBinding: binding, now: v3Date())
    }
}

@Test func receiptV3RegistryErrorsIdentifyTheInvalidField() throws {
    let valid = try v3Fixture("signing.json")
    for (old, new, expected) in [
        (#","registry_revision":1"#, "", ApprovalProtocolError.missingField("registry_revision")),
        (#""registry_revision":1"#, #""registry_revision":"1""#, .invalidField("registry_revision")),
        (#""registry_revision":1"#, #""registry_revision":0"#, .invalidField("registry_revision")),
        (#""registry_revision":1"#, #""registry_revision":257"#, .invalidField("registry_revision")),
        ("YTAG-00000000000000000001", "invalid", .invalidField("key_generation")),
    ] {
        let changed = v3Replacing(valid, old, new)
        #expect(throws: expected) { _ = try UnsignedApprovalReceipt(signingBytes: changed) }
        #expect(throws: expected) { _ = try ApprovalReceipt(receiptBytes: v3SignedBytes(changed)) }
    }
}

@Test func receiptV3RevisionAndContextBoundaries() throws {
    let valid = try v3Fixture("signing.json")
    for revision in [1, 256] {
        let generation = "YTAG-" + String(repeating: "0", count: 20 - String(revision).count) + String(revision)
        var changed = String(decoding: valid, as: UTF8.self)
        changed = changed.replacingOccurrences(of: #""registry_revision":1"#, with: #""registry_revision":\#(revision)"#)
        changed = changed.replacingOccurrences(of: "YTAG-00000000000000000001", with: generation)
        let parsed = try UnsignedApprovalReceipt(signingBytes: Data(changed.utf8))
        #expect(parsed.registryRevision == revision)
        #expect(parsed.keyGeneration == generation)
        #expect(parsed.authorizationContextSHA256 == String(repeating: "a", count: 64))
        #expect(try ApprovalReceipt(receiptBytes: v3SignedBytes(Data(changed.utf8))).unsigned == parsed)
        _ = try EnrolledSigningKey(generation: generation, spkiDER: v3Hex(sharedFixture("public-key.spki.hex")))
        let binding = try ExpectedReceiptBinding(registryRevision: revision, authorizationContextSHA256: parsed.authorizationContextSHA256)
        #expect(binding.registryRevision == revision)
        #expect(binding.authorizationContextSHA256 == parsed.authorizationContextSHA256)
    }
    for revision in [-1, 0, 257] {
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ExpectedReceiptBinding(registryRevision: revision, authorizationContextSHA256: String(repeating: "a", count: 64))
        }
    }
    for digest in ["", String(repeating: "a", count: 63), String(repeating: "a", count: 65), String(repeating: "A", count: 64), String(repeating: "g", count: 64)] {
        #expect(throws: ApprovalProtocolError.self) { _ = try ExpectedReceiptBinding(registryRevision: 1, authorizationContextSHA256: digest) }
    }
    for value in ["0", "-1", "257", "999999999999999999999999999999", "1.0", "1e0", "null", #""1""#] {
        let changed = v3Replacing(valid, #""registry_revision":1"#, #""registry_revision":\#(value)"#)
        #expect(throws: ApprovalProtocolError.self) { _ = try UnsignedApprovalReceipt(signingBytes: changed) }
        #expect(throws: ApprovalProtocolError.self) { _ = try ApprovalReceipt(receiptBytes: v3SignedBytes(changed)) }
    }
    let context = String(repeating: "a", count: 64)
    let fields = #""registry_revision":1,"authorization_context_sha256":"\#(context)""#
    for (old, new) in [
        (#","registry_revision":1"#, ""),
        (#""registry_revision":1"#, #""registry_revision":1,"registry_revision":1"#),
        (#","authorization_context_sha256":"\#(context)""#, ""),
        (#""authorization_context_sha256":"\#(context)""#, #""authorization_context_sha256":null"#),
        (#""authorization_context_sha256":"\#(context)""#, #""authorization_context_sha256":"\#(context)","authorization_context_sha256":"\#(context)""#),
        (fields, #""authorization_context_sha256":"\#(context)","registry_revision":1"#),
        ("YTAG-00000000000000000001", "YTAG-00000000000000000002"),
        (#""registry_revision":1"#, #""registry_revision":2"#),
    ] {
        let changed = v3Replacing(valid, old, new)
        #expect(throws: ApprovalProtocolError.self) { _ = try UnsignedApprovalReceipt(signingBytes: changed) }
        #expect(throws: ApprovalProtocolError.self) { _ = try ApprovalReceipt(receiptBytes: v3SignedBytes(changed)) }
    }
}

@Test func historicalV2ReceiptAndFrameAreRejected() throws {
    #expect(throws: ApprovalProtocolError.self) { _ = try UnsignedApprovalReceipt(signingBytes: historicalFixture("signing.json")) }
    for name in ["receipt.json", "ipc-success-receipt.json"] {
        #expect(throws: ApprovalProtocolError.self) { _ = try ApprovalReceipt(receiptBytes: historicalFixture(name)) }
    }
    let (challenge, snapshot) = try ApprovalIPCCodec.decodeRequest(v3Hex(sharedFixture("ipc-request.hex")))
    let key = try EnrolledSigningKey(generation: "YTAG-00000000000000000001", spkiDER: v3Hex(sharedFixture("public-key.spki.hex")))
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(v3Hex(historicalFixture("ipc-success.hex")), expectedChallenge: challenge, snapshot: snapshot, expectedKey: key, expectedBinding: receiptBindingForTest(), now: v3Date())
    }
}

@Test func receiptV3ParsersRedactDuplicateAndUnknownFieldDiagnostics() throws {
    let valid = try v3Fixture("signing.json")
    for marker in ["UNTRUSTED_SENTINEL_FIRST", "UNTRUSTED_SENTINEL_SECOND"] {
        let duplicateTail = #", "\#(marker)":1,"\#(marker)":2}"#
        let duplicate = Data(valid.dropLast()) + Data(duplicateTail.utf8)
        var control = try StrictJSONObjectParser(data: duplicate, maximumBytes: 4096)
        #expect(throws: ApprovalProtocolError.duplicateField(marker)) { _ = try control.parse() }
        #expect(throws: ApprovalProtocolError.malformedJSON) { _ = try UnsignedApprovalReceipt(signingBytes: duplicate) }
        #expect(throws: ApprovalProtocolError.malformedJSON) { _ = try ApprovalReceipt(receiptBytes: v3SignedBytes(duplicate)) }
        let unknown = Data(valid.dropLast()) + Data(#", "\#(marker)":1}"#.utf8)
        #expect(throws: ApprovalProtocolError.malformedJSON) { _ = try UnsignedApprovalReceipt(signingBytes: unknown) }

        // Keep the unsigned prefix canonical and put the duplicate entirely
        // inside the signature wrapper, exercising its separate catch.
        let wrapper = Data(#"{"signature":"MAYCAQECAQI"\#(duplicateTail)"#.utf8)
        var wrapperControl = try StrictJSONObjectParser(data: wrapper, maximumBytes: 4096)
        #expect(throws: ApprovalProtocolError.duplicateField(marker)) { _ = try wrapperControl.parse() }
        let signedWrapper = Data(valid.dropLast()) + Data(#","signature":"MAYCAQECAQI"\#(duplicateTail)"#.utf8)
        #expect(throws: ApprovalProtocolError.malformedJSON) { _ = try ApprovalReceipt(receiptBytes: signedWrapper) }
    }
}

@Test func receiptV3IPCChecksIndependentBindingAndSignedFields() throws {
    let (challenge, snapshot) = try ApprovalIPCCodec.decodeRequest(v3Hex(sharedFixture("ipc-request.hex")))
    let now = try v3Date()
    let original = try v3Hex(v3Fixture("ipc-success.hex"))
    let spki = try v3Hex(sharedFixture("public-key.spki.hex"))
    let key = try EnrolledSigningKey(generation: "YTAG-00000000000000000001", spkiDER: spki)
    let binding = try receiptBindingForTest()
    _ = try ApprovalIPCCodec.decodeAndValidateResponse(original, expectedChallenge: challenge, snapshot: snapshot, expectedKey: key, expectedBinding: binding, now: now)
    let wrongContext = try ExpectedReceiptBinding(registryRevision: 1, authorizationContextSHA256: String(repeating: "f", count: 64))
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(original, expectedChallenge: challenge, snapshot: snapshot, expectedKey: key, expectedBinding: wrongContext, now: now)
    }
    // The test-only signer produces real signatures for independently selected
    // authority values, so rejection cannot be explained by bad signatures.
    let signer = V3Signer(revision: 2)
    let revisionBinding = try ExpectedReceiptBinding(registryRevision: 2, authorizationContextSHA256: binding.authorizationContextSHA256)
    let receipt = try ApprovalReceiptFactory.makeReceipt(for: snapshot, challenge: challenge, expectedBinding: revisionBinding, signer: signer, random: V3Random(), clock: V3Clock(now: now.addingTimeInterval(-30)))
    let revisionFrame = ApprovalIPCCodec.encodeSuccess(challenge: challenge, enrolledKey: signer.enrolledKey, receipt: receipt)
    _ = try ApprovalIPCCodec.decodeAndValidateResponse(revisionFrame, expectedChallenge: challenge, snapshot: snapshot, expectedKey: signer.enrolledKey, expectedBinding: revisionBinding, now: now)
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(revisionFrame, expectedChallenge: challenge, snapshot: snapshot, expectedKey: signer.enrolledKey, expectedBinding: binding, now: now)
    }
    let contextSigner = V3Signer(revision: 1)
    let contextReceipt = try ApprovalReceiptFactory.makeReceipt(for: snapshot, challenge: challenge, expectedBinding: wrongContext, signer: contextSigner, random: V3Random(), clock: V3Clock(now: now.addingTimeInterval(-30)))
    let contextFrame = ApprovalIPCCodec.encodeSuccess(challenge: challenge, enrolledKey: contextSigner.enrolledKey, receipt: contextReceipt)
    _ = try ApprovalIPCCodec.decodeAndValidateResponse(contextFrame, expectedChallenge: challenge, snapshot: snapshot, expectedKey: contextSigner.enrolledKey, expectedBinding: wrongContext, now: now)
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(contextFrame, expectedChallenge: challenge, snapshot: snapshot, expectedKey: contextSigner.enrolledKey, expectedBinding: binding, now: now)
    }

    let contextTamper = v3Replacing(original, String(repeating: "a", count: 64), String(repeating: "f", count: 64))
    #expect(throws: ApprovalProtocolError.invalidSignature) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(contextTamper, expectedChallenge: challenge, snapshot: snapshot, expectedKey: key, expectedBinding: wrongContext, now: now)
    }
    var revisionTamper = v3Replacing(original, #""registry_revision":1"#, #""registry_revision":2"#)
    revisionTamper = v3Replacing(revisionTamper, "YTAG-00000000000000000001", "YTAG-00000000000000000002")
    let tamperKey = try EnrolledSigningKey(generation: "YTAG-00000000000000000002", spkiDER: spki)
    #expect(throws: ApprovalProtocolError.invalidSignature) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(revisionTamper, expectedChallenge: challenge, snapshot: snapshot, expectedKey: tamperKey, expectedBinding: revisionBinding, now: now)
    }
}

@Test func receiptV3FactoryRejectsRevisionMismatchBeforeSignerUse() throws {
    let (_, snapshot) = try ApprovalIPCCodec.decodeRequest(v3Hex(sharedFixture("ipc-request.hex")))
    let challenge = try ApprovalIPCChallenge(bytes: Data(0..<32))
    let signer = V3Signer(revision: 2)
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalReceiptFactory.makeReceipt(for: snapshot, challenge: challenge, expectedBinding: receiptBindingForTest(), signer: signer, random: V3Random(), clock: V3Clock(now: v3Date()))
    }
    #expect(signer.calls == 0)
}

@Test func IPCRequestRedactsPlanDecoderDiagnostics() throws {
    for marker in ["UNTRUSTED_SENTINEL_FIRST", "UNTRUSTED_SENTINEL_SECOND"] {
        let raw = Data(#"{"\#(marker)":0,"\#(marker)":1}"#.utf8)
        #expect(throws: ApprovalProtocolError.duplicateField(marker)) { _ = try ValidatedPlanSnapshot(canonicalBytes: raw) }
        let length = UInt32(32 + raw.count)
        var frame = Data([0x59, 0x54, 0x41, 0x50, 0x49, 0x50, 0x43, 0, 2, 1, 0, 0])
        frame.append(contentsOf: [UInt8((length >> 24) & 255), UInt8((length >> 16) & 255), UInt8((length >> 8) & 255), UInt8(length & 255)])
        frame.append(Data(0..<32))
        frame.append(raw)
        #expect(throws: ApprovalProtocolError.malformedJSON) { _ = try ApprovalIPCCodec.decodeRequest(frame) }
    }
}

private final class V3Signer: ApprovalSigner {
    private let key = P256.Signing.PrivateKey()
    private let revision: Int
    private(set) var calls = 0
    init(revision: Int) { self.revision = revision }
    lazy var enrolledKey: EnrolledSigningKey = try! EnrolledSigningKey(
        generation: "YTAG-" + String(repeating: "0", count: 20 - String(revision).count) + String(revision),
        spkiDER: P256PublicKeyCodec.spkiDER(fromX963: key.publicKey.x963Representation)
    )
    func sign(message: Data) throws -> Data { calls += 1; return try key.signature(for: message).derRepresentation }
}
private struct V3Random: CryptographicRandomSource {
    func randomBytes(count: Int) throws -> Data { Data((0..<count).map { UInt8($0) }) }
}
private struct V3Clock: ApprovalClock {
    let value: Date
    init(now: Date) { value = now }
    func now() -> Date { value }
}
private func v3Date() throws -> Date { try #require(ISO8601DateFormatter().date(from: "2026-09-02T15:35:56Z")) }
private func v3SignedBytes(_ unsigned: Data) -> Data { Data(unsigned.dropLast()) + Data(#","signature":"MAYCAQECAQI"}"#.utf8) }
private func v3Replacing(_ input: Data, _ old: String, _ new: String) -> Data {
    var output = input
    guard let range = output.range(of: Data(old.utf8)) else { preconditionFailure("test mutation did not match") }
    output.replaceSubrange(range, with: Data(new.utf8))
    return output
}
func v3Fixture(_ name: String) throws -> Data {
    try readApprovalFixture(name, directory: "gate1a-v3")
}
func v3FixtureString(_ name: String) throws -> String {
    try #require(String(data: v3Fixture(name), encoding: .utf8))
}
private func sharedFixture(_ name: String) throws -> Data {
    try readApprovalFixture(name, directory: "gate1a")
}
private func historicalFixture(_ name: String) throws -> Data {
    try readApprovalFixture(name, directory: "gate1a")
}
private func readApprovalFixture(_ name: String, directory: String) throws -> Data {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<6 { root.deleteLastPathComponent() }
    var raw = try Data(contentsOf: root.appendingPathComponent("testdata/\(directory)/\(name)"))
    try #require(raw.last == 0x0A)
    raw.removeLast()
    return raw
}
private func v3Hex(_ data: Data) throws -> Data {
    let bytes = Array(data)
    try #require(bytes.count.isMultiple(of: 2))
    var result = Data()
    for index in stride(from: 0, to: bytes.count, by: 2) {
        let part = String(decoding: bytes[index..<index + 2], as: UTF8.self)
        result.append(try #require(UInt8(part, radix: 16)))
    }
    return result
}
