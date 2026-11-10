import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

@Test func receiptPlanIDRejectsNonCanonicalFinalBase32Bits() throws {
    let valid = try v3Fixture("signing.json")
    let invalid = boundaryReplacing(
        valid,
        "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA",
        with: "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAB"
    )
    #expect(throws: ApprovalProtocolError.self) {
        _ = try UnsignedApprovalReceipt(signingBytes: invalid)
    }
}

@Test func requiredAndBoundStringsMatchGoTrimSpaceExactly() throws {
    let goWhitespace: [(String, String)] = [
        ("NEL", "\u{0085}"),
        ("NBSP", "\u{00A0}"),
        ("en quad", "\u{2000}"),
        ("figure space", "\u{2007}"),
        ("narrow NBSP", "\u{202F}"),
        ("ideographic space", "\u{3000}"),
    ]
    for (name, value) in goWhitespace {
        #expect(throws: ApprovalProtocolError.self, "bound string accepted \(name)") {
            _ = try ValidatedPlanSnapshot(canonicalBytes: boundaryPlan(loginPrefix: value))
        }
        #expect(throws: ApprovalProtocolError.self, "required text accepted \(name)") {
            _ = try ValidatedPlanSnapshot(canonicalBytes: boundaryCommentPlan(text: value))
        }
    }

    let zeroWidth = "\u{200B}"
    _ = try ValidatedPlanSnapshot(canonicalBytes: boundaryPlan(loginPrefix: zeroWidth))
    _ = try ValidatedPlanSnapshot(canonicalBytes: boundaryCommentPlan(text: zeroWidth))
}

@Test func leadingBOMInEveryAcceptedTextPositionIsByteFaithful() throws {
    let bom = "\u{FEFF}"
    _ = try ValidatedPlanSnapshot(canonicalBytes: boundaryPlan(loginPrefix: bom))
    _ = try ValidatedPlanSnapshot(canonicalBytes: boundaryCommentPlan(text: bom + "Comment fixture"))
    for (old, new) in [
        ("Create fixture", bom + "Create fixture"),
        (#"Untrusted \u003cb\u003etext\u003c/b\u003e"#, bom + #"Untrusted \u003cb\u003etext\u003c/b\u003e"#),
        ("\"value_id\":\"normal\"", "\"text_value\":\"\(bom)normal\""),
    ] {
        _ = try ValidatedPlanSnapshot(canonicalBytes: boundaryCreatePlan(replacing: old, with: new))
    }
}

@Test func CRLFBeforeVisibleMarkerMatchesGoByteSemantics() throws {
    let planID = "YTAP-6DQNBQFQUCIIA4DAKBADAIAQAA"
    let originalRequest = Data(
        #"{"issue_id":"APP-1","text":"Comment fixture","visibility":{"mode":"public"},"marker":"none"}"#.utf8
    )
    let changedRequest = Data(
        #"{"issue_id":"APP-1","text":"hello\r\n\nAgent plan: \#(planID)","visibility":{"mode":"public"},"marker":"visible_footer"}"#.utf8
    )
    var plan = boundaryReplacing(
        try sharedFixture("plan-comment-add.json"),
        String(decoding: originalRequest, as: UTF8.self),
        with: String(decoding: changedRequest, as: UTF8.self)
    )
    plan = boundaryReplacing(
        plan,
        "87ecebe85e37fca8dd48b2cb607822c539e859ce19d5a8be2afe78171f73b37d",
        with: boundarySHA256(changedRequest)
    )
    _ = try ValidatedPlanSnapshot(canonicalBytes: plan)
}

@Test func missingColonIsMalformedNotDuplicate() throws {
    var parser = try BoundedJSONParser(data: Data(#"{"x"0}"#.utf8), maximumBytes: 32)
    #expect(throws: ApprovalProtocolError.malformedJSON) { _ = try parser.parse() }

    var invalidUTF8 = Data(#"{"x":""#.utf8)
    invalidUTF8.append(0xFF)
    invalidUTF8.append(contentsOf: Data(#""}"#.utf8))
    var invalidParser = try BoundedJSONParser(data: invalidUTF8, maximumBytes: 32)
    #expect(throws: ApprovalProtocolError.malformedJSON) { _ = try invalidParser.parse() }
}

@Test func boundedJSONEnforcesDepthCollectionValueAndPreallocationLimits() throws {
    let exactDepth = String(repeating: "[", count: BoundedJSONParser.maximumDepth) + "0" +
        String(repeating: "]", count: BoundedJSONParser.maximumDepth)
    _ = try parseBoundaryJSON(exactDepth)
    let overDepth = "[" + exactDepth + "]"
    #expect(throws: ApprovalProtocolError.self) { _ = try parseBoundaryJSON(overDepth) }

    let exactObject = "{" + (0..<BoundedJSONParser.maximumObjectFields)
        .map { "\"k\($0)\":0" }.joined(separator: ",") + "}"
    _ = try parseBoundaryJSON(exactObject)
    let overObject = "{" + (0...BoundedJSONParser.maximumObjectFields)
        .map { "\"k\($0)\":0" }.joined(separator: ",") + "}"
    #expect(throws: ApprovalProtocolError.self) { _ = try parseBoundaryJSON(overObject) }

    let exactArray = "[" + Array(repeating: "0", count: BoundedJSONParser.maximumArrayElements).joined(separator: ",") + "]"
    _ = try parseBoundaryJSON(exactArray)
    let overArray = "[" + Array(repeating: "0", count: BoundedJSONParser.maximumArrayElements + 1).joined(separator: ",") + "]"
    #expect(throws: ApprovalProtocolError.self) { _ = try parseBoundaryJSON(overArray) }

    let firstNinetyNine = Array(repeating: boundaryJSONList(count: 9), count: 99)
    let exactValues = "[" + (firstNinetyNine + [boundaryJSONList(count: 32)]).joined(separator: ",") + "]"
    _ = try parseBoundaryJSON(exactValues)
    let overValues = "[" + (firstNinetyNine + [boundaryJSONList(count: 33)]).joined(separator: ",") + "]"
    #expect(throws: ApprovalProtocolError.self) { _ = try parseBoundaryJSON(overValues) }

    var exactBound = try BoundedJSONParser(data: Data("null".utf8), maximumBytes: 4)
    _ = try exactBound.parse()
    #expect(throws: ApprovalProtocolError.inputTooLarge(limit: 3)) {
        _ = try BoundedJSONParser(data: Data("null".utf8), maximumBytes: 3)
    }
}

@Test func boundedJSONAcceptsFullValueDomainAndRejectsNumericExtensions() throws {
    let valid = [
        "18446744073709551615",
        #"{"s":"text","a":[true,false,null,0]}"#,
    ]
    for value in valid {
        let parsed = try parseBoundaryJSON(value)
        #expect(JSONCanonicalEncoder.encode(parsed) == Data(value.utf8))
    }
    for value in ["18446744073709551616", "-1", "1.0", "1e2", "+1", "01"] {
        #expect(throws: ApprovalProtocolError.self, "accepted JSON number \(value)") {
            _ = try parseBoundaryJSON(value)
        }
    }
}

@Test func everyPlanUnionRejectsContentDigestAndUnionTampering() throws {
    let cases = [
        ("plan-issue-create.json", "Create fixture", "Create fixture!", "comment_add"),
        ("plan-issue-update.json", "Updated fixture", "Updated fixture!", "comment_add"),
        ("plan-comment-add.json", "Comment fixture", "Comment fixture!", "issue_create"),
    ]
    for (name, content, changedContent, secondUnion) in cases {
        let valid = try sharedFixture(name)
        let snapshot = try ValidatedPlanSnapshot(canonicalBytes: valid)
        #expect(snapshot.exactBytes() == valid)

        let changedRequest = boundaryReplacing(valid, content, with: changedContent)
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ValidatedPlanSnapshot(canonicalBytes: changedRequest)
        }
        for field in ["request_sha256", "expected_sha256"] {
            let changedDigest = boundaryFlipDigest(valid, field: field)
            #expect(throws: ApprovalProtocolError.self) {
                _ = try ValidatedPlanSnapshot(canonicalBytes: changedDigest)
            }
        }
        let changedUnion = boundaryReplacing(
            valid,
            #""operation":{"#,
            with: #""operation":{"\#(secondUnion)":null,"#
        )
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ValidatedPlanSnapshot(canonicalBytes: changedUnion)
        }
    }
}

@Test func validatedSnapshotDefensivelyCopiesInputAndReturnedData() throws {
    var input = try sharedFixture("plan-comment-add.json")
    let expected = input
    let snapshot = try ValidatedPlanSnapshot(canonicalBytes: input)
    input[0] ^= 1
    #expect(snapshot.exactBytes() == expected)

    var returned = snapshot.exactBytes()
    returned[0] ^= 1
    #expect(snapshot.exactBytes() == expected)
}

@Test func highSSignaturesNormalizeToTheUniqueLowSTwin() throws {
    let highS = try boundaryDecodeHex(
        "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f"
    )
    let expectedLowS = try boundaryDecodeHex("3006020101020102")
    #expect(throws: ApprovalProtocolError.invalidSignature) { _ = try P256Signature(der: highS) }
    #expect(try P256Signature.normalizeLowS(der: highS).der == expectedLowS)
    #expect(try P256Signature.normalizeLowS(der: expectedLowS).der == expectedLowS)
}

@Test func receiptFactoryRejectsSignerIdentityAndMessageSubstitution() throws {
    let snapshot = try ValidatedPlanSnapshot(canonicalBytes: sharedFixture("plan-comment-add.json"))
    let clock = BoundaryClock(value: try boundaryDate("2026-09-02T15:34:56Z"))
    let challenge = try boundaryChallenge()

    for signer in [BoundarySigner(mode: .wrongIdentity), BoundarySigner(mode: .wrongMessage)] {
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ApprovalReceiptFactory.makeReceipt(
                for: snapshot,
                challenge: challenge,
                expectedBinding: try receiptBindingForTest(),
                signer: signer,
                random: BoundaryRandom(),
                clock: clock
            )
        }
        #expect(signer.calls == 1)
    }

    var inputSPKI = try boundaryDecodeHex(try sharedFixtureString("public-key.spki.hex"))
    let expected = inputSPKI
    let identity = try EnrolledSigningKey(generation: "YTAG-00000000000000000001", spkiDER: inputSPKI)
    inputSPKI[0] ^= 1
    #expect(identity.spkiDER == expected)
}

@Test func receiptFactoryAcceptsExactRandomBytesFromNonzeroStartSlices() throws {
    let snapshot = try ValidatedPlanSnapshot(canonicalBytes: sharedFixture("plan-comment-add.json"))
    let challenge = try boundaryChallenge()
    let receipt = try ApprovalReceiptFactory.makeReceipt(
        for: snapshot,
        challenge: challenge,
        expectedBinding: try receiptBindingForTest(),
        signer: BoundarySigner(mode: .valid),
        random: SlicedBoundaryRandom(),
        clock: BoundaryClock(value: try boundaryDate("2026-09-02T15:34:56Z"))
    )
    #expect(receipt.unsigned.receiptID.hasPrefix("YTAR-"))
    #expect(receipt.unsigned.nonce.hasPrefix("YTAN-"))
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalReceiptFactory.makeReceipt(
            for: snapshot,
            challenge: challenge,
            expectedBinding: try receiptBindingForTest(),
            signer: BoundarySigner(mode: .valid),
            random: WrongSizedBoundaryRandom(),
            clock: BoundaryClock(value: try boundaryDate("2026-09-02T15:34:56Z"))
        )
    }
}

@Test func IPCHeaderLengthsTruncationTrailingAndClosedErrorUnionFailClosed() throws {
    let requestFrame = try boundaryDecodeHex(try sharedFixtureString("ipc-request.hex"))
    let (challenge, snapshot) = try ApprovalIPCCodec.decodeRequest(requestFrame)
    let now = try boundaryDate("2026-09-02T15:35:00Z")
    let expectedKey = try boundaryFixtureKey()
    let fixtures: [(String, UInt8, Data, UInt32, UInt32)] = [
        ("request", 1, requestFrame, 33, UInt32(32 + ValidatedPlanSnapshot.maximumBytes)),
        ("success", 2, try boundaryDecodeHex(try v3FixtureString("ipc-success.hex")), 124, UInt32(32 + 91 + ApprovalReceipt.maximumReceiptBytes)),
        ("error", 3, try boundaryDecodeHex(try sharedFixtureString("ipc-error.hex")), 33, 33),
    ]
    for (name, kind, valid, minimum, maximum) in fixtures {
        for (caseName, malformed) in [
            ("truncated", Data(valid.dropLast())),
            ("trailing", valid + Data([0])),
            ("under minimum", boundaryFrameHeader(kind: kind, length: minimum - 1)),
            ("over maximum", boundaryFrameHeader(kind: kind, length: maximum + 1)),
        ] {
            #expect(throws: ApprovalProtocolError.self, "accepted \(name) \(caseName)") {
                if kind == 1 {
                    _ = try ApprovalIPCCodec.decodeRequest(malformed)
                } else {
                    _ = try ApprovalIPCCodec.decodeAndValidateResponse(
                        malformed, expectedChallenge: challenge, snapshot: snapshot,
                        expectedKey: expectedKey, expectedBinding: try receiptBindingForTest(), now: now
                    )
                }
            }
        }
    }

    let codes: [ApprovalIPCErrorCode] = [
        .userCanceled, .requestInvalid, .userPresenceUnavailable,
        .keyUnavailable, .signingFailed, .internalFailure,
    ]
    for code in codes {
        let frame = ApprovalIPCCodec.encodeFailure(challenge: challenge, code: code)
        #expect(try ApprovalIPCCodec.decodeAndValidateResponse(
            frame, expectedChallenge: challenge, snapshot: snapshot,
            expectedKey: expectedKey, expectedBinding: try receiptBindingForTest(), now: now
        ) == .failure(code))
    }
    for rawCode: UInt8 in [0, 7, 255] {
        var frame = ApprovalIPCCodec.encodeFailure(challenge: challenge, code: .userCanceled)
        frame[frame.count - 1] = rawCode
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ApprovalIPCCodec.decodeAndValidateResponse(
                frame, expectedChallenge: challenge, snapshot: snapshot,
                expectedKey: expectedKey, expectedBinding: try receiptBindingForTest(), now: now
            )
        }
    }
}

@Test func IPCFramesAcceptNonzeroStartSlicesWithoutUnsafeIndexing() throws {
    let request = try boundaryDecodeHex(try sharedFixtureString("ipc-request.hex"))
    let storage = Data(repeating: 0xA5, count: 37) + request + Data([0x5A])
    let sliced = storage.dropFirst(37).dropLast()
    let (challenge, snapshot) = try ApprovalIPCCodec.decodeRequest(sliced)
    #expect(ApprovalIPCCodec.encodeRequest(challenge: challenge, snapshot: snapshot) == request)

    let shortStorage = Data(repeating: 0xA5, count: 37) + request.prefix(8)
    let shortSlice = shortStorage.dropFirst(37)
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeRequest(shortSlice)
    }
}

@Test func IPCChallengeComparesEveryFixedByteAndBindsBothResponseKinds() throws {
    let bytes = Data(0..<UInt8(ApprovalIPCChallenge.byteCount))
    let challenge = try ApprovalIPCChallenge(bytes: bytes)
    let snapshot = try ValidatedPlanSnapshot(canonicalBytes: sharedFixture("plan-comment-add.json"))
    let expectedKey = try boundaryFixtureKey()
    for index in [0, ApprovalIPCChallenge.byteCount / 2, ApprovalIPCChallenge.byteCount - 1] {
        var changed = bytes
        changed[index] ^= 0xFF
        let wrong = try ApprovalIPCChallenge(bytes: changed)
        #expect(!challenge.constantTimeEquals(wrong))
        let failure = ApprovalIPCCodec.encodeFailure(challenge: challenge, code: .userCanceled)
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ApprovalIPCCodec.decodeAndValidateResponse(
                failure, expectedChallenge: wrong, snapshot: snapshot,
                expectedKey: expectedKey, expectedBinding: try receiptBindingForTest(), now: Date()
            )
        }
    }
    #expect(challenge.constantTimeEquals(try ApprovalIPCChallenge(bytes: bytes)))
    #expect(throws: ApprovalProtocolError.self) { _ = try ApprovalIPCChallenge(bytes: Data(bytes.dropLast())) }
    #expect(throws: ApprovalProtocolError.self) { _ = try ApprovalIPCChallenge(bytes: bytes + Data([0])) }

    var v1Request = ApprovalIPCCodec.encodeRequest(challenge: challenge, snapshot: snapshot)
    v1Request[8] = 1
    #expect(throws: ApprovalProtocolError.self) { _ = try ApprovalIPCCodec.decodeRequest(v1Request) }
    var v1Failure = ApprovalIPCCodec.encodeFailure(challenge: challenge, code: .userCanceled)
    v1Failure[8] = 1
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(
            v1Failure, expectedChallenge: challenge, snapshot: snapshot,
            expectedKey: expectedKey, expectedBinding: try receiptBindingForTest(), now: Date()
        )
    }
}

@Test func IPCSuccessBindsKeyMessagePlanAndTTLBoundariesCryptographically() throws {
    let request = try boundaryDecodeHex(try sharedFixtureString("ipc-request.hex"))
    let (challenge, snapshot) = try ApprovalIPCCodec.decodeRequest(request)
    let signer = BoundarySigner(mode: .valid)
    let issued = try boundaryDate("2026-09-02T15:34:56Z")
    let receipt = try ApprovalReceiptFactory.makeReceipt(
        for: snapshot,
        challenge: challenge,
        expectedBinding: try receiptBindingForTest(),
        signer: signer,
        random: BoundaryRandom(),
        clock: BoundaryClock(value: issued)
    )
    let validFrame = ApprovalIPCCodec.encodeSuccess(
        challenge: challenge,
        enrolledKey: signer.enrolledKey,
        receipt: receipt
    )
    _ = try ApprovalIPCCodec.decodeAndValidateResponse(
        validFrame, expectedChallenge: challenge, snapshot: snapshot,
        expectedKey: signer.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(60)
    )

    let wrongIdentity = BoundarySigner(mode: .valid).enrolledKey
    let wrongKeyFrame = ApprovalIPCCodec.encodeSuccess(
        challenge: challenge,
        enrolledKey: wrongIdentity,
        receipt: receipt
    )
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(
            wrongKeyFrame, expectedChallenge: challenge, snapshot: snapshot,
            expectedKey: signer.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(60)
        )
    }

    let wrongMessageDER = try signer.signature(for: Data("wrong message".utf8))
    let wrongMessageReceipt = try ApprovalReceipt(
        unsigned: receipt.unsigned,
        signatureDER: P256Signature.normalizeLowS(der: wrongMessageDER).der
    )
    let wrongMessageFrame = ApprovalIPCCodec.encodeSuccess(
        challenge: challenge, enrolledKey: signer.enrolledKey, receipt: wrongMessageReceipt
    )
    #expect(throws: ApprovalProtocolError.invalidSignature) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(
            wrongMessageFrame, expectedChallenge: challenge, snapshot: snapshot,
            expectedKey: signer.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(60)
        )
    }

    let changedBinding = try boundaryUnsigned(
        copying: receipt.unsigned,
        planSHA256: String(repeating: "f", count: 64)
    )
    let changedBindingReceipt = try ApprovalReceipt(
        unsigned: changedBinding,
        signatureDER: P256Signature.normalizeLowS(der: try signer.signature(for: changedBinding.encodedSigningBytes())).der
    )
    let changedBindingFrame = ApprovalIPCCodec.encodeSuccess(
        challenge: challenge, enrolledKey: signer.enrolledKey, receipt: changedBindingReceipt
    )
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(
            changedBindingFrame, expectedChallenge: challenge, snapshot: snapshot,
            expectedKey: signer.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(60)
        )
    }

    let fiveMinute = try boundaryUnsigned(
        copying: receipt.unsigned,
        issuedAt: "2026-09-02T15:34:56Z",
        expiresAt: "2026-09-02T15:39:56Z"
    )
    let fiveMinuteReceipt = try ApprovalReceipt(
        unsigned: fiveMinute,
        signatureDER: P256Signature.normalizeLowS(der: try signer.signature(for: fiveMinute.encodedSigningBytes())).der
    )
    let fiveMinuteFrame = ApprovalIPCCodec.encodeSuccess(
        challenge: challenge, enrolledKey: signer.enrolledKey, receipt: fiveMinuteReceipt
    )
    _ = try ApprovalIPCCodec.decodeAndValidateResponse(
        fiveMinuteFrame, expectedChallenge: challenge, snapshot: snapshot,
        expectedKey: signer.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(-30)
    )
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(
            fiveMinuteFrame, expectedChallenge: challenge, snapshot: snapshot,
            expectedKey: signer.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(-31)
        )
    }
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(
            fiveMinuteFrame, expectedChallenge: challenge, snapshot: snapshot,
            expectedKey: signer.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(300)
        )
    }
}

@Test func IPCSuccessRejectsNonFiniteAndOutOfProtocolRangeClocks() throws {
    let request = try boundaryDecodeHex(try sharedFixtureString("ipc-request.hex"))
    let (challenge, snapshot) = try ApprovalIPCCodec.decodeRequest(request)
    let success = try boundaryDecodeHex(try v3FixtureString("ipc-success.hex"))
    let expectedKey = try boundaryFixtureKey()
    for seconds in [
        Double.nan,
        Double.infinity,
        -Double.infinity,
        -62_135_596_801,
        253_402_300_800,
        Double.greatestFiniteMagnitude,
    ] {
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ApprovalIPCCodec.decodeAndValidateResponse(
                success,
                expectedChallenge: challenge,
                snapshot: snapshot,
                expectedKey: expectedKey, expectedBinding: try receiptBindingForTest(),
                now: Date(timeIntervalSince1970: seconds)
            )
        }
    }
}

@Test func IPCV2RejectsChallengeReplayAndSelfSelectedKey() throws {
    let snapshot = try ValidatedPlanSnapshot(canonicalBytes: sharedFixture("plan-comment-add.json"))
    let expectedSigner = BoundarySigner(mode: .valid)
    let challengeA = try boundaryChallenge()
    var challengeBBytes = challengeA.bytes()
    challengeBBytes[0] ^= 0xFF
    let challengeB = try ApprovalIPCChallenge(bytes: challengeBBytes)
    let issued = try boundaryDate("2026-09-02T15:34:56Z")
    let receiptA = try ApprovalReceiptFactory.makeReceipt(
        for: snapshot, challenge: challengeA, expectedBinding: try receiptBindingForTest(), signer: expectedSigner,
        random: BoundaryRandom(), clock: BoundaryClock(value: issued)
    )
    let spliced = ApprovalIPCCodec.encodeSuccess(
        challenge: challengeB, enrolledKey: expectedSigner.enrolledKey, receipt: receiptA
    )
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(
            spliced, expectedChallenge: challengeB, snapshot: snapshot,
            expectedKey: expectedSigner.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(10)
        )
    }

    let attacker = BoundarySigner(mode: .valid)
    let attackerReceipt = try ApprovalReceiptFactory.makeReceipt(
        for: snapshot, challenge: challengeA, expectedBinding: try receiptBindingForTest(), signer: attacker,
        random: BoundaryRandom(), clock: BoundaryClock(value: issued)
    )
    let selfSelected = ApprovalIPCCodec.encodeSuccess(
        challenge: challengeA, enrolledKey: attacker.enrolledKey, receipt: attackerReceipt
    )
    #expect(throws: ApprovalProtocolError.self) {
        _ = try ApprovalIPCCodec.decodeAndValidateResponse(
            selfSelected, expectedChallenge: challengeA, snapshot: snapshot,
            expectedKey: expectedSigner.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(10)
        )
    }
}

@Test func IPCV2RejectsWrongEnrolledGenerationAndFingerprint() throws {
    let snapshot = try ValidatedPlanSnapshot(canonicalBytes: sharedFixture("plan-comment-add.json"))
    let signer = BoundarySigner(mode: .valid)
    let challenge = try boundaryChallenge()
    let issued = try boundaryDate("2026-09-02T15:34:56Z")
    let receipt = try ApprovalReceiptFactory.makeReceipt(
        for: snapshot, challenge: challenge, expectedBinding: try receiptBindingForTest(), signer: signer,
        random: BoundaryRandom(), clock: BoundaryClock(value: issued)
    )
    for changed in [
        try boundaryUnsigned(copying: receipt.unsigned, keyGeneration: "YTAG-00000000000000000002", registryRevision: 2),
        try boundaryUnsigned(copying: receipt.unsigned, keyFingerprintSHA256: String(repeating: "f", count: 64)),
    ] {
        let signed = try ApprovalReceipt(
            unsigned: changed,
            signatureDER: P256Signature.normalizeLowS(der: try signer.signature(for: changed.encodedSigningBytes())).der
        )
        let frame = ApprovalIPCCodec.encodeSuccess(
            challenge: challenge, enrolledKey: signer.enrolledKey, receipt: signed
        )
        #expect(throws: ApprovalProtocolError.self) {
            _ = try ApprovalIPCCodec.decodeAndValidateResponse(
                frame, expectedChallenge: challenge, snapshot: snapshot,
                expectedKey: signer.enrolledKey, expectedBinding: try receiptBindingForTest(), now: issued.addingTimeInterval(10)
            )
        }
    }
}

private enum BoundarySignerMode {
    case valid
    case wrongIdentity
    case wrongMessage
}

private final class BoundarySigner: ApprovalSigner {
    private let signingKey = P256.Signing.PrivateKey()
    private let identityKey: P256.Signing.PrivateKey
    private let mode: BoundarySignerMode
    private(set) var calls = 0

    init(mode: BoundarySignerMode) {
        self.mode = mode
        identityKey = mode == .wrongIdentity ? P256.Signing.PrivateKey() : signingKey
    }

    lazy var enrolledKey: EnrolledSigningKey = try! EnrolledSigningKey(
        generation: "YTAG-00000000000000000001",
        spkiDER: P256PublicKeyCodec.spkiDER(fromX963: identityKey.publicKey.x963Representation)
    )

    func sign(message: Data) throws -> Data {
        calls += 1
        return try signature(for: mode == .wrongMessage ? Data("substituted".utf8) : message)
    }

    func signature(for message: Data) throws -> Data {
        try signingKey.signature(for: message).derRepresentation
    }
}

private final class BoundaryRandom: CryptographicRandomSource {
    private var call = 0
    func randomBytes(count: Int) throws -> Data {
        call += 1
        return Data((0..<count).map { UInt8(($0 + call) & 0xFF) })
    }
}

private struct SlicedBoundaryRandom: CryptographicRandomSource {
    func randomBytes(count: Int) throws -> Data {
        let storage = Data(repeating: 0xA5, count: 13) + Data((0..<count).map { UInt8($0) })
        return storage.dropFirst(13)
    }
}

private struct WrongSizedBoundaryRandom: CryptographicRandomSource {
    func randomBytes(count: Int) throws -> Data {
        Data(repeating: 0xA5, count: count + 1)
    }
}

private struct BoundaryClock: ApprovalClock {
    let value: Date
    func now() -> Date { value }
}

private func boundaryUnsigned(
    copying receipt: UnsignedApprovalReceipt,
    planSHA256: String? = nil,
    challengeSHA256: String? = nil,
    keyGeneration: String? = nil,
    registryRevision: Int? = nil,
    keyFingerprintSHA256: String? = nil,
    issuedAt: String? = nil,
    expiresAt: String? = nil
) throws -> UnsignedApprovalReceipt {
    try UnsignedApprovalReceipt(
        receiptID: receipt.receiptID,
        nonce: receipt.nonce,
        challengeSHA256: challengeSHA256 ?? receipt.challengeSHA256,
        registryRevision: registryRevision ?? receipt.registryRevision,
        authorizationContextSHA256: receipt.authorizationContextSHA256,
        planID: receipt.planID,
        planSHA256: planSHA256 ?? receipt.planSHA256,
        profileIdentitySHA256: receipt.profileIdentitySHA256,
        accountID: receipt.accountID,
        projectID: receipt.projectID,
        projectKey: receipt.projectKey,
        schemaSHA256: receipt.schemaSHA256,
        requestSHA256: receipt.requestSHA256,
        expectedSHA256: receipt.expectedSHA256,
        issuedAt: issuedAt ?? receipt.issuedAt,
        expiresAt: expiresAt ?? receipt.expiresAt,
        keyGeneration: keyGeneration ?? receipt.keyGeneration,
        keyFingerprintSHA256: keyFingerprintSHA256 ?? receipt.keyFingerprintSHA256
    )
}

private func boundaryPlan(loginPrefix: String) throws -> Data {
    boundaryReplacing(
        try sharedFixture("plan-issue-create.json"),
        #""login":"alice""#,
        with: #""login":"\#(loginPrefix)alice""#
    )
}

private func boundaryCommentPlan(text: String) throws -> Data {
    let originalRequest = Data(
        #"{"issue_id":"APP-1","text":"Comment fixture","visibility":{"mode":"public"},"marker":"none"}"#.utf8
    )
    let changedRequest = boundaryReplacing(originalRequest, "Comment fixture", with: text)
    var plan = boundaryReplacing(try sharedFixture("plan-comment-add.json"), "Comment fixture", with: text)
    plan = boundaryReplacing(
        plan,
        "87ecebe85e37fca8dd48b2cb607822c539e859ce19d5a8be2afe78171f73b37d",
        with: boundarySHA256(changedRequest)
    )
    return plan
}

private func boundaryCreatePlan(replacing old: String, with new: String) throws -> Data {
    let originalRequest = Data(
        #"{"summary":"Create fixture","description":"Untrusted \u003cb\u003etext\u003c/b\u003e","visibility":{"mode":"public"},"custom_fields":[{"field_id":"priority","field_type":"enum","value_id":"normal"}],"marker":"none"}"#.utf8
    )
    let changedRequest = boundaryReplacing(originalRequest, old, with: new)
    var plan = boundaryReplacing(try sharedFixture("plan-issue-create.json"), old, with: new)
    plan = boundaryReplacing(
        plan,
        "bb6a78c3861939df7fd7f5a9e6112397c94d318f6e944a44a626d8194af42f18",
        with: boundarySHA256(changedRequest)
    )
    return plan
}

private func parseBoundaryJSON(_ value: String) throws -> JSONNode {
    var parser = try BoundedJSONParser(data: Data(value.utf8), maximumBytes: 512 << 10)
    return try parser.parse()
}

private func boundaryJSONList(count: Int) -> String {
    "[" + Array(repeating: "0", count: count).joined(separator: ",") + "]"
}

private func boundaryFlipDigest(_ data: Data, field: String) -> Data {
    var result = data
    let marker = Data("\"\(field)\":\"".utf8)
    guard let range = result.range(of: marker) else { preconditionFailure("missing digest field") }
    let index = range.upperBound
    result[index] = result[index] == 0x30 ? 0x31 : 0x30
    return result
}

private func boundaryFrameHeader(kind: UInt8, length: UInt32) -> Data {
    var output = Data([0x59, 0x54, 0x41, 0x50, 0x49, 0x50, 0x43, 0x00, 2, kind, 0, 0])
    output.append(contentsOf: [
        UInt8((length >> 24) & 0xFF),
        UInt8((length >> 16) & 0xFF),
        UInt8((length >> 8) & 0xFF),
        UInt8(length & 0xFF),
    ])
    return output
}

private func boundaryChallenge() throws -> ApprovalIPCChallenge {
    try ApprovalIPCChallenge(bytes: Data(0..<32))
}

private func boundaryFixtureKey() throws -> EnrolledSigningKey {
    try EnrolledSigningKey(
        generation: "YTAG-00000000000000000001",
        spkiDER: boundaryDecodeHex(try sharedFixtureString("public-key.spki.hex"))
    )
}

private func boundaryDate(_ value: String) throws -> Date {
    try #require(ISO8601DateFormatter().date(from: value))
}

private func sharedFixture(_ name: String) throws -> Data {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<6 { root.deleteLastPathComponent() }
    var data = try Data(contentsOf: root.appendingPathComponent("testdata/gate1a/\(name)"))
    guard data.last == 0x0A else { throw ApprovalProtocolError.nonCanonicalEncoding }
    data.removeLast()
    return data
}

private func sharedFixtureString(_ name: String) throws -> String {
    guard let value = String(data: try sharedFixture(name), encoding: .utf8) else {
        throw ApprovalProtocolError.nonCanonicalEncoding
    }
    return value
}

private func boundaryDecodeHex(_ value: String) throws -> Data {
    let bytes = Array(value.utf8)
    guard bytes.count.isMultiple(of: 2) else { throw ApprovalProtocolError.nonCanonicalEncoding }
    var output = Data()
    for offset in stride(from: 0, to: bytes.count, by: 2) {
        guard let high = boundaryHex(bytes[offset]), let low = boundaryHex(bytes[offset + 1]) else {
            throw ApprovalProtocolError.nonCanonicalEncoding
        }
        output.append(high << 4 | low)
    }
    return output
}

private func boundaryHex(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x30...0x39: byte - 0x30
    case 0x61...0x66: byte - 0x61 + 10
    default: nil
    }
}

private func boundaryReplacing(_ data: Data, _ old: String, with new: String) -> Data {
    let source = String(decoding: data, as: UTF8.self)
    let changed = source.replacingOccurrences(of: old, with: new)
    precondition(source != changed, "test mutation did not match")
    return Data(changed.utf8)
}

private func boundarySHA256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
