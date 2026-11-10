import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

private func signatureControlHex(_ text: String) throws -> Data {
    let bytes = Array(text.utf8)
    try #require(bytes.count.isMultiple(of: 2))
    return try Data(stride(from: 0, to: bytes.count, by: 2).map {
        try #require(UInt8(String(decoding: bytes[$0..<$0 + 2], as: UTF8.self), radix: 16))
    })
}

// Frozen public fixture from fixed test scalar 9, independently verified using
// Go's standard ECDSA implementation. No test requires a native defect to persist.
private struct RegistrySignatureControlFixture {
    let message: Data
    let low: Data
    let high: Data
    let lowRaw: Data
    let highRaw: Data
    let key: Data
    let wrongKey: Data

    init() throws {
        struct Document: Decodable {
            let schema_version: Int
            let scope: String
            let public_scalar: Int
            let message_hex: String
            let message_length: Int
            let message_sha256: String
            let spki_hex: String
            let x963_hex: String
            let wrong_x963_hex: String
            let low_der_hex: String
            let high_der_hex: String
            let low_raw_hex: String
            let high_raw_hex: String
        }
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("testdata/gate1a-registry/signature-control.json"))
        let fields = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        try #require(Set(fields.keys) == Set([
            "schema_version", "scope", "public_scalar", "message_hex",
            "message_length", "message_sha256", "spki_hex", "x963_hex",
            "wrong_x963_hex", "low_der_hex", "high_der_hex", "low_raw_hex", "high_raw_hex",
        ]))
        let document = try JSONDecoder().decode(Document.self, from: data)
        try #require(document.schema_version == 1)
        try #require(document.scope == "registry-signature-control")
        try #require(document.public_scalar == 9)
        try #require(document.message_length == 1_795)
        try #require(document.message_sha256 == "0d76c17d481b96dcfb6c8bcf2ff3fae316858e0b0f6af5db7c3519eb655835ba")
        message = try signatureControlHex(document.message_hex)
        low = try signatureControlHex(document.low_der_hex)
        high = try signatureControlHex(document.high_der_hex)
        lowRaw = try signatureControlHex(document.low_raw_hex)
        highRaw = try signatureControlHex(document.high_raw_hex)
        key = try signatureControlHex(document.x963_hex)
        wrongKey = try signatureControlHex(document.wrong_x963_hex)
        try #require(message.count == 1_795)
        let digest = SHA256.hash(data: message).map { String(format: "%02x", $0) }.joined()
        try #require(digest == "0d76c17d481b96dcfb6c8bcf2ff3fae316858e0b0f6af5db7c3519eb655835ba")
        let spki = try signatureControlHex(document.spki_hex)
        try #require(P256PublicKeyCodec.x963(fromSPKIDER: spki) == key)
        var scalar = Data(repeating: 0, count: 32)
        scalar[31] = 9
        let knownKey = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        try #require(knownKey.publicKey.x963Representation == key)
        try #require(key != wrongKey)
    }
}

@Test func registrySignatureControlAcceptsFrozenEquivalentSignatures() throws {
    struct Observation: Encodable {
        let schema_version = 1
        let event = "registry_signature_control_frozen"
        let public_scalar = 9
        let os_version: String
        let form: String
        let native_original_accepted: Bool
        let control_outcome: String
    }
    let fixture = try RegistrySignatureControlFixture()
    let nativeKey = try P256.Signing.PublicKey(x963Representation: fixture.key)
    for (name, der) in [("low-S", fixture.low), ("high-S", fixture.high)] {
        let nativeSignature = try P256.Signing.ECDSASignature(derRepresentation: der)
        let originalAccepted = nativeKey.isValidSignature(nativeSignature, for: fixture.message)
        let outcome = try registrySignatureControlOutcome(message: fixture.message, derSignature: der, x963: fixture.key)
        let expected: RegistrySignatureControlOutcome = originalAccepted ? .original : .equivalent
        #expect(outcome == expected, "\(name)")
        let controlOutcome = switch outcome {
        case .original: "original"
        case .equivalent: "equivalent"
        case .rejected: "rejected"
        }
        let observation = Observation(
            os_version: ProcessInfo.processInfo.operatingSystemVersionString,
            form: name,
            native_original_accepted: originalAccepted,
            control_outcome: controlOutcome
        )
        print(String(decoding: try JSONEncoder().encode(observation), as: UTF8.self))
        #expect(try registrySignatureControl(message: fixture.message, derSignature: der, x963: fixture.key), "\(name)")
    }
}

@Test func registrySignatureControlFrozenDERMatchesRawScalars() throws {
    let fixture = try RegistrySignatureControlFixture()
    try #require(fixture.low.count == 70)
    try #require(fixture.high.count == 71)
    #expect(fixture.low.prefix(4) == Data([0x30, 0x44, 0x02, 0x20]))
    #expect(fixture.low[36..<38] == Data([0x02, 0x20]))
    #expect(fixture.high.prefix(4) == Data([0x30, 0x45, 0x02, 0x20]))
    #expect(fixture.high[36..<39] == Data([0x02, 0x21, 0]))
    // Fixed DER offsets expose the two independently verified scalar magnitudes.
    #expect(Data(fixture.low[4..<36]) + Data(fixture.low[38..<70]) == fixture.lowRaw)
    #expect(Data(fixture.high[4..<36]) + Data(fixture.high[39..<71]) == fixture.highRaw)
    #expect(try P256.Signing.ECDSASignature(derRepresentation: fixture.low).rawRepresentation == fixture.lowRaw)
    #expect(try P256.Signing.ECDSASignature(derRepresentation: fixture.high).rawRepresentation == fixture.highRaw)
    #expect(try P256Signature(der: fixture.low).der == fixture.low)
}

@Test func registrySignatureControlTwinPreservesFrozenScalars() throws {
    let fixture = try RegistrySignatureControlFixture()
    #expect(try registrySignatureControlTwin(raw: fixture.lowRaw) == fixture.highRaw)
    #expect(try registrySignatureControlTwin(raw: fixture.highRaw) == fixture.lowRaw)
    for raw in [fixture.lowRaw, fixture.highRaw] {
        let twin = try registrySignatureControlTwin(raw: raw)
        #expect(twin.prefix(32) == raw.prefix(32))
        #expect(try registrySignatureControlTwin(raw: twin) == raw)
    }
}

@Test func registrySignatureControlTwinHandlesScalarBoundaries() throws {
    // Expected N-s values were calculated independently with Go math/big.
    let r = try signatureControlHex("0000000000000000000000000000000000000000000000000000000000000001")
    try #require(r.count == 32, "fixed boundary r must contain 32 bytes")
    let cases = [
        ("one", "0000000000000000000000000000000000000000000000000000000000000001", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),
        ("order minus one", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", "0000000000000000000000000000000000000000000000000000000000000001"),
        ("byte boundary", "0000000000000000000000000000000000000000000000000000000000000100", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632451"),
        ("borrow across zeros", "0000000000000001000000000000000000000000000000000000000000000000", "fffffffeffffffffffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    ]
    for (name, scalar, expectedScalar) in cases {
        try #require(scalar.utf8.count == 64, "\(name) scalar must contain 64 hex characters")
        try #require(expectedScalar.utf8.count == 64, "\(name) expected scalar must contain 64 hex characters")
        let scalarBytes: Data = try signatureControlHex(scalar)
        let expectedScalarBytes: Data = try signatureControlHex(expectedScalar)
        try #require(scalarBytes.count == 32, "\(name) scalar must contain 32 bytes")
        try #require(expectedScalarBytes.count == 32, "\(name) expected scalar must contain 32 bytes")
        let raw = r + scalarBytes
        let expected = r + expectedScalarBytes
        let twin = try registrySignatureControlTwin(raw: raw)
        #expect(twin == expected, "\(name)")
        #expect(try registrySignatureControlTwin(raw: twin) == raw, "\(name)")
    }
}

@Test func registrySignatureControlTwinRejectsInvalidRawScalars() throws {
    let fixture = try RegistrySignatureControlFixture()
    let zero = Data(repeating: 0, count: 32)
    let one = try signatureControlHex("0000000000000000000000000000000000000000000000000000000000000001")
    let order = try signatureControlHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    let cases: [(String, Data)] = [
        ("short", Data(fixture.lowRaw.dropLast())),
        ("long", fixture.lowRaw + Data([0])),
        ("zero r", zero + one),
        ("zero s", one + zero),
        ("out-of-range r", order + one),
        ("out-of-range s", one + order),
    ]
    for (name, raw) in cases {
        #expect(throws: RegistrySignatureControlError.invalidSignature, "\(name)") {
            try registrySignatureControlTwin(raw: raw)
        }
    }
}

@Test func registrySignatureControlRejectsChangedInputs() throws {
    let fixture = try RegistrySignatureControlFixture()
    for (form, der) in [("low-S", fixture.low), ("high-S", fixture.high)] {
        var wrongR = der
        wrongR[35] ^= 1
        var wrongS = der
        wrongS[wrongS.count - 1] ^= 1
        let cases: [(String, Data, Data, Data)] = [
            ("message", fixture.message + Data([0]), der, fixture.key),
            ("key", fixture.message, der, fixture.wrongKey),
            ("r", fixture.message, wrongR, fixture.key),
            ("s", fixture.message, wrongS, fixture.key),
        ]
        for (name, message, signature, key) in cases {
            #expect(try registrySignatureControlOutcome(message: message, derSignature: signature, x963: key) == .rejected, "\(form) changed \(name)")
            #expect(try !registrySignatureControl(message: message, derSignature: signature, x963: key), "\(form) changed \(name)")
        }
    }
}

@Test func registrySignatureControlRejectsMalformedSignatures() throws {
    let fixture = try RegistrySignatureControlFixture()
    let order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    let cases: [(String, Data)] = [
        ("empty", Data()),
        ("truncated", try signatureControlHex("30060201010201")),
        ("trailing data", fixture.low + Data([0])),
        ("zero r", try signatureControlHex("3006020100020101")),
        ("zero s", try signatureControlHex("3006020101020100")),
        ("out-of-range r", try signatureControlHex("3026022100" + order + "020101")),
        ("out-of-range s", try signatureControlHex("3026020101022100" + order)),
        ("negative integer", try signatureControlHex("3006020180020101")),
        ("nonminimal integer", try signatureControlHex("300702020001020101")),
        ("nonminimal sequence length", try signatureControlHex("308106020101020101")),
    ]
    for (name, der) in cases {
        #expect(throws: RegistrySignatureControlError.invalidSignature, "\(name)") {
            try registrySignatureControl(message: fixture.message, derSignature: der, x963: fixture.key)
        }
    }
}

@Test func registrySignatureControlRejectsInvalidPublicKeys() throws {
    let fixture = try RegistrySignatureControlFixture()
    var invalidPoint = Data(repeating: 0, count: 65)
    invalidPoint[0] = 0x04
    var wrongPrefix = fixture.key
    wrongPrefix[0] = 0x02
    let cases: [(String, Data)] = [
        ("empty", Data()),
        ("short", Data(fixture.key.dropLast())),
        ("long", fixture.key + Data([0])),
        ("wrong prefix", wrongPrefix),
        ("off-curve point", invalidPoint),
    ]
    for (name, key) in cases {
        #expect(throws: RegistrySignatureControlError.invalidPublicKey, "\(name)") {
            try registrySignatureControl(message: fixture.message, derSignature: fixture.low, x963: key)
        }
    }
}

@Test func registrySignatureControlPreservesProductionLowSIngress() throws {
    let fixture = try RegistrySignatureControlFixture()
    _ = try P256Signature(der: fixture.low)
    #expect(try P256PublicKeyCodec.verify(message: fixture.message, derSignature: fixture.low, x963: fixture.key))
    #expect(throws: ApprovalProtocolError.invalidSignature) {
        _ = try P256Signature(der: fixture.high)
    }
    #expect(throws: ApprovalProtocolError.invalidSignature) {
        _ = try P256PublicKeyCodec.verify(message: fixture.message, derSignature: fixture.high, x963: fixture.key)
    }
}
