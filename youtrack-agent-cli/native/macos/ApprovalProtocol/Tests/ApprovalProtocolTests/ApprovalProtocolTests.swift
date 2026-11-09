import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

@Test func sharedGoFixturesMatchEverySwiftCodec() throws {
    let signing = try v3Fixture("signing.json")
    let receiptBytes = try v3Fixture("receipt.json")
    let x963 = try decodeHex(try sharedFixtureString("public-key.x963.hex"))
    let spki = try decodeHex(try sharedFixtureString("public-key.spki.hex"))
    let signatureDER = try decodeHex(try sharedFixtureString("signature.der.hex"))
    let display = try decodeHex(try sharedFixtureString("display.hex"))
    let expectedEscapedDisplay = try sharedFixtureString("display.escaped.txt")
    let expectedFingerprint = try sharedFixtureString("public-key.fingerprint-sha256")
    let expectedSignatureBase64URL = try sharedFixtureString("signature.base64url")
    let expectedSigningSHA256 = try v3FixtureString("signing.sha256")
    let expectedReceiptSHA256 = try v3FixtureString("receipt.sha256")
    let expectedDisplaySHA256 = try sharedFixtureString("display.sha256")

    let unsigned = try UnsignedApprovalReceipt(signingBytes: signing)
    let receipt = try ApprovalReceipt(receiptBytes: receiptBytes)
    #expect(unsigned.encodedSigningBytes() == signing)
    #expect(receipt.unsigned == unsigned)
    #expect(receipt.encodedReceiptBytes() == receiptBytes)
    #expect(try ApprovalReceipt(unsigned: unsigned, signatureDER: signatureDER).encodedReceiptBytes() == receiptBytes)

    #expect(try P256PublicKeyCodec.spkiDER(fromX963: x963) == spki)
    #expect(try P256PublicKeyCodec.x963(fromSPKIDER: spki) == x963)
    #expect(try P256PublicKeyCodec.fingerprintSHA256(x963: x963) == expectedFingerprint)

    let signature = try P256Signature(der: signatureDER)
    #expect(signature.base64URL == expectedSignatureBase64URL)
    #expect(try P256Signature(derBase64URL: signature.base64URL).der == signatureDER)

    #expect(sha256Hex(signing) == expectedSigningSHA256)
    #expect(sha256Hex(receiptBytes) == expectedReceiptSHA256)
    #expect(sha256Hex(display) == expectedDisplaySHA256)
    #expect(unsigned.signingSHA256 == expectedSigningSHA256)
    #expect(receipt.receiptSHA256 == expectedReceiptSHA256)

    #expect(InertByteCodec.encode(display) == expectedEscapedDisplay)
    #expect(try InertByteCodec.decode(expectedEscapedDisplay) == display)
}

@Test func receiptSchemaV1IsRejected() throws {
    let signing = Data(#"{"schema_version":1,"receipt_id":"YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA","nonce":"YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBY","plan_id":"YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA","plan_sha256":"1111111111111111111111111111111111111111111111111111111111111111","profile_identity_sha256":"2222222222222222222222222222222222222222222222222222222222222222","account_id":"1-2","project_id":"0-1","project_key":"APP","schema_sha256":"3333333333333333333333333333333333333333333333333333333333333333","request_sha256":"4444444444444444444444444444444444444444444444444444444444444444","expected_sha256":"5555555555555555555555555555555555555555555555555555555555555555","issued_at":"2026-09-02T15:34:56Z","expires_at":"2026-09-02T15:39:56Z","key_generation":"key-1","key_fingerprint_sha256":"6666666666666666666666666666666666666666666666666666666666666666"}"#.utf8)

    #expect(throws: ApprovalProtocolError.self) {
        _ = try UnsignedApprovalReceipt(signingBytes: signing)
    }
}

private func sharedFixture(_ name: String) throws -> Data {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<6 {
        root.deleteLastPathComponent()
    }
    var data = try Data(contentsOf: root.appendingPathComponent("testdata/gate1a/\(name)"))
    guard data.last == 0x0A else {
        throw ApprovalProtocolError.nonCanonicalEncoding
    }
    data.removeLast()
    return data
}

private func sharedFixtureString(_ name: String) throws -> String {
    guard let value = String(data: try sharedFixture(name), encoding: .utf8) else {
        throw ApprovalProtocolError.nonCanonicalEncoding
    }
    return value
}

private func decodeHex(_ value: String) throws -> Data {
    let bytes = Array(value.utf8)
    guard bytes.count.isMultiple(of: 2) else {
        throw ApprovalProtocolError.nonCanonicalEncoding
    }
    var output = Data()
    output.reserveCapacity(bytes.count / 2)
    for offset in stride(from: 0, to: bytes.count, by: 2) {
        guard let high = hex(bytes[offset]), let low = hex(bytes[offset + 1]) else {
            throw ApprovalProtocolError.nonCanonicalEncoding
        }
        output.append((high << 4) | low)
    }
    return output
}

private func hex(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x30...0x39: byte - 0x30
    case 0x61...0x66: byte - 0x61 + 10
    default: nil
    }
}

private func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

@Test func signingBytesRejectUnknownDuplicateAndNonCanonicalInput() throws {
    let valid = Data(#"{"schema_version":1,"receipt_id":"YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA","nonce":"YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBY","plan_id":"YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA","plan_sha256":"1111111111111111111111111111111111111111111111111111111111111111","profile_identity_sha256":"2222222222222222222222222222222222222222222222222222222222222222","account_id":"a","project_id":"i","project_key":"P","schema_sha256":"3333333333333333333333333333333333333333333333333333333333333333","request_sha256":"4444444444444444444444444444444444444444444444444444444444444444","expected_sha256":"5555555555555555555555555555555555555555555555555555555555555555","issued_at":"2026-09-02T15:34:56Z","expires_at":"2026-09-02T15:39:56Z","key_generation":"k","key_fingerprint_sha256":"6666666666666666666666666666666666666666666666666666666666666666"}"#.utf8)
    _ = valid // Retained as an explicit schema-v1 negative vector above.
    let canonical = try v3Fixture("signing.json")
    var unknown = canonical
    unknown.removeLast()
    unknown.append(contentsOf: Data(#", "extra":"x"}"#.utf8))
    #expect(throws: ApprovalProtocolError.self) {
        try UnsignedApprovalReceipt(signingBytes: unknown)
    }

    var spaced = canonical
    spaced.insert(0x20, at: 1)
    #expect(throws: ApprovalProtocolError.nonCanonicalEncoding) {
        try UnsignedApprovalReceipt(signingBytes: spaced)
    }
}

@Test func p256SPKIAndFingerprintAreExact() throws {
    let privateKey = P256.Signing.PrivateKey()
    let x963 = privateKey.publicKey.x963Representation
    let spki = try P256PublicKeyCodec.spkiDER(fromX963: x963)

    #expect(spki.count == 91)
    #expect(spki.prefix(26) == Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    ]))
    #expect(try P256PublicKeyCodec.x963(fromSPKIDER: spki) == x963)
    let expected = SHA256.hash(data: spki).map { String(format: "%02x", $0) }.joined()
    #expect(try P256PublicKeyCodec.fingerprintSHA256(x963: x963) == expected)
}

@Test func signatureIsStrictDERAndVerifies() throws {
    let privateKey = P256.Signing.PrivateKey()
    let message = Data("approved bytes".utf8)
    var lowSRepresentation: Data?
    for _ in 0..<128 {
        let candidate = try privateKey.signature(for: message).derRepresentation
        if (try? P256Signature(der: candidate)) != nil {
            lowSRepresentation = candidate
            break
        }
    }
    let signatureDER = try #require(lowSRepresentation)
    let parsed = try P256Signature(der: signatureDER)

    #expect(try P256Signature(derBase64URL: parsed.base64URL).der == signatureDER)
    #expect(try P256PublicKeyCodec.verify(
        message: message,
        derSignature: signatureDER,
        x963: privateKey.publicKey.x963Representation
    ))
    #expect(throws: ApprovalProtocolError.invalidSignature) {
        try P256Signature(der: Data([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]))
    }
}

@Test func inertRendererIsCompleteAndReversible() throws {
    let input = Data((0...255).map(UInt8.init))
    let rendered = InertByteCodec.encode(input)

    #expect(rendered.contains("\\x00"))
    #expect(rendered.contains("\\\\"))
    #expect(rendered.contains("~"))
    #expect(try InertByteCodec.decode(rendered) == input)
}

@Test func signingInputEnforcesSizeAndCanonicalSchema() throws {
    let valid = try v3Fixture("signing.json")
    let cases: [(String, Data)] = [
        ("empty", Data()),
        ("one over maximum", Data(repeating: 0x20, count: UnsignedApprovalReceipt.maximumSigningBytes + 1)),
        ("non object", Data("[]".utf8)),
        ("missing challenge binding", replacing(
            valid,
            ",\"challenge_sha256\":\"630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd\"",
            with: ""
        )),
        ("missing field", replacing(valid, ",\"key_generation\":\"YTAG-00000000000000000001\"", with: "")),
        ("duplicate field", replacing(valid, #"{"schema_version":3"#, with: #"{"schema_version":3,"schema_version":3"#)),
        ("unknown field", insertingBeforeClosingBrace(valid, ",\"unknown\":\"x\"")),
        ("reordered fields", replacing(
            valid,
            #"{"schema_version":3,"receipt_id":"YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4""#,
            with: #"{"receipt_id":"YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4","schema_version":3"#
        )),
        ("leading whitespace", Data([0x20]) + valid),
        ("internal whitespace", replacing(valid, #","receipt_id""#, with: #", "receipt_id""#)),
        ("trailing whitespace", valid + Data([0x20])),
        ("trailing JSON", valid + Data("{}".utf8)),
        ("alternate escaping", replacing(valid, #""account_id":"1-2""#, with: #""account_id":"1\u002d2""#)),
    ]

    for (name, bytes) in cases {
        #expect(throws: ApprovalProtocolError.self, "accepted \(name)", performing: {
            _ = try UnsignedApprovalReceipt(signingBytes: bytes)
        })
    }
    #expect(try UnsignedApprovalReceipt(signingBytes: valid).encodedSigningBytes() == valid)
}

@Test func signedReceiptEnforcesSizeAndReceiptSpecificSchema() throws {
    let valid = try v3Fixture("receipt.json")
    let cases: [(String, Data)] = [
        ("empty", Data()),
        ("one over maximum", Data(repeating: 0x20, count: ApprovalReceipt.maximumReceiptBytes + 1)),
        ("non object", Data("[]".utf8)),
        ("missing signature", replacing(valid, #","signature":"MAYCAQECAQI""#, with: "")),
        ("duplicate signature", replacing(valid, #","signature":"MAYCAQECAQI""#, with: #","signature":"MAYCAQECAQI","signature":"MAYCAQECAQI""#)),
        ("unknown receipt field", replacing(valid, #","signature":"#, with: #","unknown":"x","signature":"#)),
        ("signature not last", replacing(
            valid,
            #","key_fingerprint_sha256":"5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3","signature":"MAYCAQECAQI""#,
            with: #","signature":"MAYCAQECAQI","key_fingerprint_sha256":"5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3""#
        )),
        ("signature alternate escape", replacing(valid, #""signature":"MAYCAQECAQI""#, with: #""signature":"M\u0041YCAQECAQI""#)),
        ("leading whitespace", Data([0x20]) + valid),
        ("trailing whitespace", valid + Data([0x20])),
        ("trailing JSON", valid + Data("{}".utf8)),
    ]

    for (name, bytes) in cases {
        #expect(throws: ApprovalProtocolError.self, "accepted \(name)", performing: {
            _ = try ApprovalReceipt(receiptBytes: bytes)
        })
    }
    #expect(try ApprovalReceipt(receiptBytes: valid).encodedReceiptBytes() == valid)
}

@Test func canonicalApprovalIdentifiersAreExactly128BitBase32() throws {
    let valid = try v3Fixture("signing.json")
    let cases: [(String, String, String)] = [
        ("receipt wrong prefix", "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", "NOPE-AAAQEAYEAUDAOCAJBIFQYDIOB4"),
        ("receipt short", "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB"),
        ("receipt lowercase", "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", "YTAR-aaaQEAYEAUDAOCAJBIFQYDIOB4"),
        ("receipt padded", "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB="),
        ("receipt noncanonical final bits", "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB5"),
        ("nonce wrong prefix", "YTAN-6DQNBQFQUCIIA4DAKBADAIAQAA", "YTAR-6DQNBQFQUCIIA4DAKBADAIAQAA"),
        ("nonce noncanonical final bits", "YTAN-6DQNBQFQUCIIA4DAKBADAIAQAA", "YTAN-6DQNBQFQUCIIA4DAKBADAIAQAB"),
    ]

    for (name, old, new) in cases {
        #expect(throws: ApprovalProtocolError.self, "accepted \(name)", performing: {
            _ = try UnsignedApprovalReceipt(signingBytes: replacing(valid, old, with: new))
        })
    }
}

@Test func bindingFieldsUseTheSameCanonicalShapesAsGo() throws {
    let valid = try v3Fixture("signing.json")
    let cases: [(String, String, String)] = [
        ("plan id", "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", "p"),
        ("account id", #""account_id":"1-2""#, #""account_id":"-bad""#),
        ("project id", #""project_id":"0-1""#, #""project_id":":bad""#),
        ("project key lowercase", #""project_key":"APP""#, #""project_key":"app""#),
        ("project key punctuation", #""project_key":"APP""#, #""project_key":"APP-1""#),
    ]

    for (name, old, new) in cases {
        #expect(throws: ApprovalProtocolError.self, "accepted noncanonical \(name)", performing: {
            _ = try UnsignedApprovalReceipt(signingBytes: replacing(valid, old, with: new))
        })
    }
}

@Test func keyGenerationBoundariesMatchGo() throws {
    let valid = try v3Fixture("signing.json")
    let rejected = ["", "a", "A0._-z", "-key", "key:1", "kéy", "YTAG-00000000000000000000", "YTAG-00000000000000000002", "YTAG-99999999999999999999", "YTAG-0000000000000000001", "YTAG-000000000000000000001"]

    #expect(try UnsignedApprovalReceipt(signingBytes: valid).keyGeneration == "YTAG-00000000000000000001")
    for value in rejected {
        let bytes = replacing(valid, #""key_generation":"YTAG-00000000000000000001""#, with: #""key_generation":"\#(value)""#)
        #expect(throws: ApprovalProtocolError.self) {
            _ = try UnsignedApprovalReceipt(signingBytes: bytes)
        }
    }
}

@Test func timestampsRequireWholeSecondUTCAndNoMoreThanFiveMinutes() throws {
    let valid = try v3Fixture("signing.json")
    let invalid: [(String, String, String)] = [
        ("fractional", "2026-09-02T15:34:56Z", "2026-09-02T15:34:56.1Z"),
        ("offset", "2026-09-02T15:34:56Z", "2026-09-02T12:34:56-03:00"),
        ("year zero", "2026-09-02T15:34:56Z", "0000-09-02T15:34:56Z"),
        ("invalid date", "2026-09-02T15:34:56Z", "2026-02-30T15:34:56Z"),
        ("equal", "2026-09-02T15:39:56Z", "2026-09-02T15:34:56Z"),
        ("negative", "2026-09-02T15:39:56Z", "2026-09-02T15:34:55Z"),
        ("five minutes one second", "2026-09-02T15:39:56Z", "2026-09-02T15:39:57Z"),
    ]

    for (name, old, new) in invalid {
        #expect(throws: ApprovalProtocolError.self, "accepted \(name) timestamp window", performing: {
            _ = try UnsignedApprovalReceipt(signingBytes: replacing(valid, old, with: new))
        })
    }
    #expect(try UnsignedApprovalReceipt(signingBytes: valid).expiresAt == "2026-09-02T15:39:56Z")
}

@Test func strictDERSignatureRejectsScalarAndEncodingFailures() throws {
    let order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    let invalidHex = [
        "",
        "30060201010201",
        "300602010102010200",
        "3006020100020101",
        "3006020101020100",
        "3006020180020101",
        "300702020001020101",
        "3026022100" + order + "020101",
        "3026020101022100" + order,
        "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
        String(repeating: "00", count: P256Signature.maximumDERBytes + 1),
    ]
    for value in invalidHex {
        #expect(throws: ApprovalProtocolError.invalidSignature) {
            _ = try P256Signature(der: decodeHex(value))
        }
    }

    let validBase64URL = try sharedFixtureString("signature.base64url")
    for value in ["", validBase64URL + "=", "MAYCAQECAQI+", String(repeating: "A", count: P256Signature.maximumBase64URLBytes + 1)] {
        #expect(throws: ApprovalProtocolError.invalidSignature) {
            _ = try P256Signature(derBase64URL: value)
        }
    }
}

@Test func publicKeyEncodingsAndFingerprintBindExactBytes() throws {
    let x963 = try decodeHex(try sharedFixtureString("public-key.x963.hex"))
    let spki = try decodeHex(try sharedFixtureString("public-key.spki.hex"))
    let expectedFingerprint = try sharedFixtureString("public-key.fingerprint-sha256")

    var compressedMarker = x963
    compressedMarker[0] = 0x02
    var offCurve = Data(repeating: 0, count: P256PublicKeyCodec.x963ByteCount)
    offCurve[0] = 0x04
    for value in [Data(), Data(x963.dropLast()), compressedMarker, offCurve] {
        #expect(throws: ApprovalProtocolError.invalidPublicKey) {
            _ = try P256PublicKeyCodec.spkiDER(fromX963: value)
        }
    }

    var badPrefix = spki
    badPrefix[0] = 0x31
    for value in [Data(spki.dropLast()), spki + Data([0]), badPrefix] {
        #expect(throws: ApprovalProtocolError.invalidPublicKey) {
            _ = try P256PublicKeyCodec.x963(fromSPKIDER: value)
        }
    }

    let alternate = P256.Signing.PrivateKey().publicKey.x963Representation
    #expect(try P256PublicKeyCodec.fingerprintSHA256(x963: alternate) != expectedFingerprint)
    #expect(try P256PublicKeyCodec.fingerprintSHA256(x963: x963) == expectedFingerprint)
}

@Test func inertByteCodecNeverTruncatesAtMaximum() throws {
    let maximum = Data(repeating: 0, count: InertByteCodec.maximumBytes)
    let rendered = InertByteCodec.encode(maximum)
    #expect(rendered.utf8.count == InertByteCodec.maximumBytes * 4)
    #expect(try InertByteCodec.decode(rendered) == maximum)

    #expect(throws: ApprovalProtocolError.self) {
        _ = try InertByteCodec.decode(String(repeating: "A", count: InertByteCodec.maximumBytes * 4 + 1))
    }
}

@Test func validatedPlanRetainsAnImmutableSnapshot() throws {
    var original = try sharedFixture("plan-issue-create.json")
    let snapshot = try ValidatedPlanSnapshot(canonicalBytes: original)
    let expected = original
    original[0] = 0x20

    #expect(snapshot.exactBytes() == expected)
    let escaped = ApprovalPlanRenderer.render(snapshot)
    #expect(!escaped.contains("\n"))
    #expect(!escaped.contains("\r"))
    #expect(try InertByteCodec.decode(escaped) == expected)

    for malformed in ["", "\\", "\\x0a", "\\q00", "\\x20", "\\x41", "\\x5C", "é"] {
        #expect(throws: ApprovalProtocolError.invalidEscapedBytes) {
            _ = try InertByteCodec.decode(malformed)
        }
    }
}

@Test func allGoPlanFixturesValidateAndPreserveFullUInt64() throws {
    for name in ["plan-issue-create.json", "plan-issue-update.json", "plan-comment-add.json"] {
        let bytes = try sharedFixture(name)
        let snapshot = try ValidatedPlanSnapshot(canonicalBytes: bytes)
        #expect(snapshot.exactBytes() == bytes)
        #expect(snapshot.sha256 == sha256Hex(bytes))
    }

    let maximum = replacing(
        try sharedFixture("plan-issue-create.json"),
        "\"policy_revision\":1",
        with: "\"policy_revision\":18446744073709551615"
    )
    _ = try ValidatedPlanSnapshot(canonicalBytes: maximum)
    let overflow = replacing(maximum, "18446744073709551615", with: "18446744073709551616")
    #expect(throws: ApprovalProtocolError.self) { _ = try ValidatedPlanSnapshot(canonicalBytes: overflow) }
}

@Test func planIDAndURLCorporaMatchGo() throws {
    let base = try sharedFixture("plan-issue-create.json")
    let idCorpus = try #require(JSONSerialization.jsonObject(with: try sharedFixture("plan-id-corpus.json")) as? [String: [String]])
    for value in idCorpus["valid"] ?? [] {
        let changed = value == "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA" ? base : replacing(base, "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", with: value)
        _ = try ValidatedPlanSnapshot(canonicalBytes: changed)
    }
    for value in idCorpus["invalid"] ?? [] {
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ValidatedPlanSnapshot(canonicalBytes: replacing(base, "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", with: value))
        }
    }

    let urlCorpus = try #require(JSONSerialization.jsonObject(with: try sharedFixture("approval-url-corpus.json")) as? [String: [String]])
    for value in urlCorpus["valid"] ?? [] {
        var changed = value == "https://acme.youtrack.cloud" ? base : replacing(base, "https://acme.youtrack.cloud/api", with: value + "/api")
        if value != "https://acme.youtrack.cloud" { changed = replacing(changed, "https://acme.youtrack.cloud", with: value) }
        _ = try ValidatedPlanSnapshot(canonicalBytes: changed)
    }
    for value in urlCorpus["invalid"] ?? [] {
        var changed = replacing(base, "https://acme.youtrack.cloud/api", with: value + "/api")
        changed = replacing(changed, "https://acme.youtrack.cloud", with: value)
        #expect(throws: ApprovalProtocolError.self) { _ = try ValidatedPlanSnapshot(canonicalBytes: changed) }
    }
}

@Test func sharedIPCFramesRoundTripAndValidateSuccessUnion() throws {
    let requestFrame = try decodeHex(try sharedFixtureString("ipc-request.hex"))
    let (challenge, snapshot) = try ApprovalIPCCodec.decodeRequest(requestFrame)
    #expect(ApprovalIPCCodec.encodeRequest(challenge: challenge, snapshot: snapshot) == requestFrame)

    let successFrame = try decodeHex(try v3FixtureString("ipc-success.hex"))
    let validationTime = try #require(ISO8601DateFormatter().date(from: "2026-09-02T15:35:00Z"))
    let expectedKey = try EnrolledSigningKey(
        generation: "YTAG-00000000000000000001",
        spkiDER: decodeHex(try sharedFixtureString("public-key.spki.hex"))
    )
    let response = try ApprovalIPCCodec.decodeAndValidateResponse(
        successFrame,
        expectedChallenge: challenge,
        snapshot: snapshot,
        expectedKey: expectedKey, expectedBinding: try receiptBindingForTest(),
        now: validationTime
    )
    guard case let .success(success) = response else { Issue.record("expected success"); return }
    let expectedReceipt = try v3Fixture("ipc-success-receipt.json")
    #expect(success.receipt.encodedReceiptBytes() == expectedReceipt)
    #expect(ApprovalIPCCodec.encodeSuccess(challenge: challenge, enrolledKey: success.enrolledKey, receipt: success.receipt) == successFrame)

    let errorFrame = try decodeHex(try sharedFixtureString("ipc-error.hex"))
    #expect(try ApprovalIPCCodec.decodeAndValidateResponse(
        errorFrame, expectedChallenge: challenge, snapshot: snapshot, expectedKey: expectedKey, expectedBinding: try receiptBindingForTest(), now: Date()
    ) == .failure(.userCanceled))
}

@Test func receiptFactoryUsesOneKeyHandleOneSignatureAndSelfVerifies() throws {
    let snapshot = try ValidatedPlanSnapshot(canonicalBytes: try sharedFixture("plan-comment-add.json"))
    let signer = TestSigner()
    let random = TestRandom()
    let wholeSecond = try #require(ISO8601DateFormatter().date(from: "2026-09-02T15:34:56Z"))
    let clock = TestClock(value: wholeSecond.addingTimeInterval(0.987))
    let challenge = try ApprovalIPCChallenge(bytes: Data(0..<32))

    let receipt = try ApprovalReceiptFactory.makeReceipt(
        for: snapshot, challenge: challenge, expectedBinding: try receiptBindingForTest(), signer: signer, random: random, clock: clock
    )
    #expect(signer.calls == 1)
    #expect(random.calls == 2)
    #expect(receipt.unsigned.issuedAt == "2026-09-02T15:34:56Z")
    #expect(receipt.unsigned.expiresAt == "2026-09-02T15:36:56Z")
    #expect(receipt.unsigned.planSHA256 == snapshot.sha256)
    #expect(receipt.unsigned.challengeSHA256 == challenge.sha256)
    #expect(receipt.unsigned.keyFingerprintSHA256 == signer.enrolledKey.fingerprintSHA256)
    _ = try ApprovalReceipt(receiptBytes: receipt.encodedReceiptBytes())
}

private final class TestSigner: ApprovalSigner {
    private let key = P256.Signing.PrivateKey()
    private(set) var calls = 0
    lazy var enrolledKey: EnrolledSigningKey = try! EnrolledSigningKey(
        generation: "YTAG-00000000000000000001",
        spkiDER: P256PublicKeyCodec.spkiDER(fromX963: key.publicKey.x963Representation)
    )

    func sign(message: Data) throws -> Data {
        calls += 1
        return try key.signature(for: message).derRepresentation
    }
}

private final class TestRandom: CryptographicRandomSource {
    private(set) var calls = 0
    func randomBytes(count: Int) throws -> Data {
        calls += 1
        return Data((0..<count).map { UInt8(($0 + calls) & 0xFF) })
    }
}

private struct TestClock: ApprovalClock {
    let value: Date
    func now() -> Date { value }
}

private func replacing(_ data: Data, _ old: String, with new: String) -> Data {
    let source = String(decoding: data, as: UTF8.self)
    let replaced = source.replacingOccurrences(of: old, with: new)
    precondition(replaced != source, "test mutation did not match input")
    return Data(replaced.utf8)
}

private func insertingBeforeClosingBrace(_ data: Data, _ addition: String) -> Data {
    var result = data
    precondition(result.last == 0x7D)
    result.removeLast()
    result.append(contentsOf: addition.utf8)
    result.append(0x7D)
    return result
}
