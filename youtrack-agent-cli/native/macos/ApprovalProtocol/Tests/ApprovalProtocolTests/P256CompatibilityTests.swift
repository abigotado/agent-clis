import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

private struct P256CompatibilityCorpus: Decodable {
    struct Key: Decodable { let generation: String; let spki: String }
    struct Transcript: Decodable { let final_body: String; let record: String }
    struct Negative: Decodable { let id: String; let transcript: Transcript }
    let keys: [Key]
    let negatives: [Negative]
}

private func compatibilityHex(_ text: String) throws -> Data {
    let bytes = Array(text.utf8)
    try #require(bytes.count.isMultiple(of: 2))
    return try Data(stride(from: 0, to: bytes.count, by: 2).map {
        try #require(UInt8(String(decoding: bytes[$0..<$0 + 2], as: UTF8.self), radix: 16))
    })
}

private func compatibilityBase64URL(_ text: String) throws -> Data {
    let padded = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        + String(repeating: "=", count: (4 - text.utf8.count % 4) % 4)
    return try #require(Data(base64Encoded: padded))
}

private struct P256CompatibilityFixture {
    let message: Data
    let signature: Data
    let key: Data
    let wrongKey: Data

    init() throws {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let corpus = try JSONDecoder().decode(P256CompatibilityCorpus.self, from: Data(contentsOf: root.appendingPathComponent("testdata/gate1a-registry/corpus.json")))
        let transcript = try #require(corpus.negatives.first { $0.id == "recovery-continuity-success" }).transcript
        message = Data(("YTA-REGISTRY-RECORD-NEW-V1\0" + transcript.final_body).utf8)
        try #require(message.count == 1855)
        let digest = SHA256.hash(data: message).map { String(format: "%02x", $0) }.joined()
        try #require(digest == "953be2f28a5e846a47fff27d61cc0514fedb34e7888d1536adea8172974c9ec5")
        struct Record: Decodable { let new_signature: String }
        let record = try JSONDecoder().decode(Record.self, from: Data(transcript.record.utf8))
        signature = try compatibilityBase64URL(record.new_signature)
        let pinnedSignature = try compatibilityHex("30450221008e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a30220648aa18839a06f1c9c66a40b4f2b25d3753f1c54f73f079dc9ce486f64dd2521")
        try #require(signature == pinnedSignature)
        let spki = try #require(corpus.keys.first { $0.generation == "YTAG-00000000000000000003" }).spki
        try #require(spki == "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXsvk0aYzCkTI9--VHUvxZebGtyHvramF-0FmG8bn_WyHNGQMSZj_fjdLBs4aZKLs2CqwNjhPuD2aebEnon1QMg")
        key = try P256PublicKeyCodec.x963(fromSPKIDER: compatibilityBase64URL(spki))
        let otherSPKI = try #require(corpus.keys.first { $0.generation == "YTAG-00000000000000000004" }).spki
        wrongKey = try P256PublicKeyCodec.x963(fromSPKIDER: compatibilityBase64URL(otherSPKI))
        try #require(wrongKey != key)
    }
}

@Test func p256CompatibilityAcceptsCanonicalLowSRegression() throws {
    let fixture = try P256CompatibilityFixture()
    // Pin public correctness, not a platform defect: this also passes if the
    // native backend eventually accepts the original representation directly.
    #expect(try P256PublicKeyCodec.verify(message: fixture.message, derSignature: fixture.signature, x963: fixture.key))
}

@Test func p256CompatibilityRejectsChangedInputs() throws {
    let fixture = try P256CompatibilityFixture()
    var wrongR = fixture.signature
    wrongR[36] ^= 1
    var wrongS = fixture.signature
    wrongS[wrongS.count - 1] ^= 1
    let cases: [(String, Data, Data, Data)] = [
        ("message", fixture.message + Data([0]), fixture.signature, fixture.key),
        ("key", fixture.message, fixture.signature, fixture.wrongKey),
        ("r", fixture.message, wrongR, fixture.key),
        ("s", fixture.message, wrongS, fixture.key),
    ]
    for (name, message, signature, key) in cases {
        _ = try P256Signature(der: signature)
        #expect(try !P256PublicKeyCodec.verify(message: message, derSignature: signature, x963: key), "accepted changed \(name)")
    }
}

@Test func p256CompatibilityRejectsHighSAndMalformedIngress() throws {
    let fixture = try P256CompatibilityFixture()
    let order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    let cases = [
        ("equivalent high-S", "30460221008e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a30221009b755e76c65f90e463995bf4b0d4da2c47a7de58afd896e729eb825397860030"),
        ("truncated", "30060201010201"),
        ("trailing data", "300602010102010100"),
        ("zero r", "3006020100020101"),
        ("zero s", "3006020101020100"),
        ("out-of-range r", "3026022100" + order + "020101"),
        ("out-of-range s", "3026020101022100" + order),
        ("nonminimal integer", "300702020001020101"),
    ]
    for (name, hex) in cases {
        let der = try compatibilityHex(hex)
        #expect(throws: ApprovalProtocolError.invalidSignature, "parser accepted \(name)") {
            _ = try P256Signature(der: der)
        }
        #expect(throws: ApprovalProtocolError.invalidSignature, "verifier accepted \(name)") {
            _ = try P256PublicKeyCodec.verify(message: fixture.message, derSignature: der, x963: fixture.key)
        }
    }
}

@Test func p256CompatibilityErrorsAreClosedAndRedacted() throws {
    let fixture = try P256CompatibilityFixture()
    let sentinel = "UNTRUSTED_SENTINEL"
    let malformed = Data(sentinel.utf8)
    let cases: [(Data, Data)] = [
        (malformed, fixture.key),
        (fixture.signature, malformed),
    ]
    for (signature, key) in cases {
        do {
            _ = try P256PublicKeyCodec.verify(message: fixture.message, derSignature: signature, x963: key)
            Issue.record("malformed input did not throw")
        } catch {
            #expect(error as? ApprovalProtocolError == .invalidSignature)
            #expect(String(describing: error) == "invalidSignature")
            #expect(!String(reflecting: error).contains(sentinel))
        }
    }
}
