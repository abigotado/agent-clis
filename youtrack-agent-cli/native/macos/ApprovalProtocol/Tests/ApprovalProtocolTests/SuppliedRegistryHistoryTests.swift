import CryptoKit
import Foundation
import Testing

@testable import ApprovalProtocol

// Independent literal schema and synthetic-key construction. No production
// codec or transcript oracle supplies expected state or ordered signing bytes.
private let suppliedHistoryFields =
  "schema_version record_type transition_kind registry_revision previous_record_sha256 request_sha256 proposal_sha256 acceptance_sha256 challenge_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 requested_at accepted_at committed_at target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 target_previous_status target_new_status new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 new_status revokes_all_prior old_signature new_signature"
  .split(separator: " ").map(String.init)

private func suppliedHistoryHash(_ bytes: Data) -> String {
  SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
}

private func suppliedHistoryQuote(_ value: String) -> String { "\"" + value + "\"" }

private func suppliedHistoryObject(_ bytes: Data) throws -> [String: String] {
  let object = try #require(try JSONSerialization.jsonObject(with: bytes) as? [String: Any])
  var result: [String: String] = [:]
  for (field, value) in object {
    if value is NSNull {
      result[field] = "null"
    } else if let text = value as? String {
      result[field] = suppliedHistoryQuote(text)
    } else if let number = value as? NSNumber {
      result[field] =
        field == "revokes_all_prior" ? (number.boolValue ? "true" : "false") : number.stringValue
    } else {
      Issue.record("unexpected fixture primitive")
    }
  }
  return result
}

private func suppliedHistoryEncode(_ object: [String: String], body: Bool = false) throws -> Data {
  let fields = body ? Array(suppliedHistoryFields.prefix(28)) : suppliedHistoryFields
  let pairs = try fields.map { "\"" + $0 + "\":" + (try #require(object[$0])) }
  return Data(("{" + pairs.joined(separator: ",") + "}").utf8)
}

private func suppliedHistoryBase64(_ data: Data) -> String {
  data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(
    of: "/", with: "_"
  ).replacingOccurrences(of: "=", with: "")
}

private func suppliedHistoryKey(_ revision: Int) throws -> P256.Signing.PrivateKey {
  // Public fixture scalars are deliberately unsafe, never enrolled credentials.
  var raw = Data(repeating: 0, count: 32)
  raw[30] = UInt8(revision >> 8)
  raw[31] = UInt8(revision & 255)
  return try P256.Signing.PrivateKey(rawRepresentation: raw)
}

private func suppliedHistorySPKI(_ key: P256.Signing.PrivateKey) -> Data {
  var bytes = Data([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  ])
  bytes.append(key.publicKey.x963Representation)
  return bytes
}

private func suppliedHistorySign(
  _ fields: [String: String], old: P256.Signing.PrivateKey? = nil, fresh: P256.Signing.PrivateKey?
) throws -> Data {
  var object = fields
  let body = try suppliedHistoryEncode(object, body: true)
  for (field, domain, key) in [
    ("old_signature", "YTA-REGISTRY-RECORD-OLD-V1\0", old),
    ("new_signature", "YTA-REGISTRY-RECORD-NEW-V1\0", fresh),
  ] {
    object[field] = "null"
    guard let key else { continue }
    var message = Data(domain.utf8)
    message.append(body)
    let signature = try key.signature(for: message)
    #expect(try registrySignatureControl(
      message: message, derSignature: signature.derRepresentation,
      x963: key.publicKey.x963Representation))
    let low = try P256Signature.normalizeLowS(der: signature.derRepresentation)
    #expect(try P256PublicKeyCodec.verify(
      message: message, derSignature: low.der, x963: key.publicKey.x963Representation))
    object[field] = suppliedHistoryQuote(low.base64URL)
  }
  return try suppliedHistoryEncode(object)
}

private func suppliedHistoryRecords(_ names: [String]) throws -> [Data] {
  let corpus = try registryCorpus()
  return try names.map { name in
    Data(try #require(corpus.positives.first { $0.id == name }).record.utf8)
  }
}

@Test func suppliedRegistryHistoryPinnedPrefixes() throws {
  let hashes = [
    "enroll1": "c8154cd7d2a72f7e23dcbfa9f52d1b9ca97afad557c6becedf9eaf7a772db16b",
    "rotate2": "4c4394736cf2e1e619e5cdef3a45104b9dddd344d5febff6061d4bd37a877f5c",
    "revoke3": "8fc41f67fcc9b80d7eac1cf16f2e4bb581b753e2c4f3c2a87bc2125247ad3f75",
    "recover-disabled4": "083686890e6a8b2fa969143f74d5a147415aaa125df7917344da9a636fa15f7c",
    "recover-active3": "6d1f7ea55313a4ffd01cd5c2ddb732dcf871b2fe722699779e83b1b0b33453e6",
  ]
  let scenarios: [([String], [[Int]], [[String]])] = [
    (
      ["enroll1", "rotate2", "revoke3", "recover-disabled4"], [[1], [1, 2], [1, 2], [1, 2, 4]],
      [
        ["active"], ["retained", "active"], ["retained", "revoked"],
        ["revoked", "revoked", "active"],
      ]
    ),
    (
      ["enroll1", "rotate2", "recover-active3"], [[1], [1, 2], [1, 2, 3]],
      [["active"], ["retained", "active"], ["revoked", "revoked", "active"]]
    ),
  ]
  for (names, generations, statuses) in scenarios {
    let records = try suppliedHistoryRecords(names)
    for count in 0...records.count {
      let result = try SuppliedRegistryHistory.verify(suppliedRecords: Array(records.prefix(count)))
      #expect(result.suppliedRevision == count)
      if count == 0 {
        #expect(result.suppliedTipSHA256 == String(repeating: "0", count: 64))
        #expect(result.suppliedTipDescriptorSHA256 == nil)
        #expect(result.keys.isEmpty)
        continue
      }
      #expect(result.suppliedTipSHA256 == hashes[names[count - 1]])
      #expect(result.suppliedTipDescriptorSHA256 == String(repeating: "a", count: 64))
      try #require(result.keys.count == generations[count - 1].count)
      for (index, scalar) in generations[count - 1].enumerated() {
        let key = result.keys[index]
        let spki = suppliedHistorySPKI(try suppliedHistoryKey(scalar))
        let id = String(format: "%032x", scalar)
        #expect(key.generation == String(format: "YTAG-%020d", scalar))
        #expect(key.keyID == id)
        #expect(key.keyTag == "io.github.abigotado.youtrack-agent.approval.signing.v1/" + id)
        #expect(key.spki == suppliedHistoryBase64(spki))
        #expect(key.fingerprintSHA256 == suppliedHistoryHash(spki))
        #expect(key.status == statuses[count - 1][index])
      }
    }
  }
}

@Test func suppliedRegistryHistoryApplicableCorpusNegatives() throws {
  let stages: [String: SuppliedRegistryHistoryError] = [
    "encoding-record-missing": .encoding, "encoding-record-duplicate": .encoding,
    "encoding-record-unknown": .encoding, "encoding-record-reordered": .encoding,
    "encoding-record-escaped": .encoding, "encoding-record-whitespace": .encoding,
    "encoding-record-trailing": .encoding, "encoding-record-nonobject": .encoding,
    "size-record-over": .bounds, "size-record-at": .encoding,
    "digest-predecessor": .replay, "signature-old-wrong-domain": .replay,
    "signature-new-wrong-domain": .replay, "signature-missing-old": .replay,
    "signature-missing-new": .replay,
    "state-revoke-all-false": .replay, "state-wrong-target": .replay, "state-key-reuse": .replay,
    "state-revision-gap": .replay, "recovery-invalid-prefix-signature": .replay,
    "prefix-time-reversed": .replay, "prefix-recovery-digest-unexpected": .replay,
    "prefix-recovery-digest-missing": .replay,
    "grammar-record-revision--1": .encoding, "grammar-record-revision-0": .grammar,
    "grammar-record-revision-257": .grammar, "grammar-generation-revision": .grammar,
    "grammar-time-fraction": .grammar, "recovery-evidence-missing": .replay,
    "time-commit-at-expiry": .replay,
  ]
  let corpus = try registryCorpus()
  let applicable = corpus.negatives.filter { stages[$0.id] != nil }
  #expect(Set(applicable.map(\.id)) == Set(stages.keys))
  for vector in applicable {
    let prefix =
      try vector.prefix_records
      ?? vector.prefix.map { id in try #require(corpus.positives.first { $0.id == id }).record }
    let records = (prefix + [vector.transcript.record]).map { Data($0.utf8) }
    let stage = try #require(stages[vector.id])
    #expect(throws: stage, "\(vector.id)") {
      try SuppliedRegistryHistory.verify(suppliedRecords: records)
    }
  }
}

@Test func suppliedRegistryHistoryDoesNotInferMissingTranscriptEvidence() throws {
  let names = Set([
    "digest-request-without-nul", "digest-acceptance-splice", "recovery-lookup-success",
    "recovery-continuity-success", "grammar-schema-negative", "grammar-partial-tuple",
    "grammar-fingerprint", "grammar-spki-der", "grammar-spki-offcurve", "grammar-key-tag",
    "grammar-digest-uppercase", "grammar-spki-padding", "encoding-schema-fraction",
    "grammar-high-s",
  ])
  let corpus = try registryCorpus()
  let cases = corpus.negatives.filter { names.contains($0.id) }
  #expect(Set(cases.map(\.id)) == names)
  for vector in cases {
    let records =
      try vector.prefix.map { id in
        Data(try #require(corpus.positives.first { $0.id == id }).record.utf8)
      } + [Data(vector.transcript.record.utf8)]
    _ = try SuppliedRegistryHistory.verify(suppliedRecords: records)
  }
}

@Test func suppliedRegistryHistoryGlobalPhasesBoundsAndRedaction() throws {
  let base = try suppliedHistoryRecords(["enroll1", "rotate2"])
  let first = try suppliedHistorySign(
    try suppliedHistoryObject(base[0]), fresh: suppliedHistoryKey(2))
  #expect(throws: SuppliedRegistryHistoryError.replay) {
    try SuppliedRegistryHistory.verify(suppliedRecords: [first])
  }
  var later = try suppliedHistoryObject(base[1])
  later["registry_revision"] = "257"
  let cases: [(String, [Data], SuppliedRegistryHistoryError)] = [
    ("later-encoding-first", [first, base[1] + Data([10])], .encoding),
    ("later-grammar-first", [first, try suppliedHistoryEncode(later)], .grammar),
    ("later-bounds-first", [Data("bad".utf8), Data(repeating: 120, count: 4353)], .bounds),
    ("empty-item", [Data()], .bounds),
    ("item-at-cap", [Data(repeating: 120, count: 4352)], .encoding),
    ("count257", Array(repeating: base[0], count: 257), .bounds),
    ("aggregate-at", Array(repeating: Data(repeating: 120, count: 4352), count: 256), .encoding),
    (
      "late-item-over-cap",
      Array(repeating: Data(repeating: 120, count: 4352), count: 255) + [
        Data(repeating: 120, count: 4353)
      ], .bounds
    ),
  ]
  for (name, records, stage) in cases {
    #expect(throws: stage, "\(name)") {
      try SuppliedRegistryHistory.verify(suppliedRecords: records)
    }
  }
  let raw = String(decoding: base[0], as: UTF8.self)
  for supplied in [
    "{\"UNTRUSTED_SENTINEL\":0,\"UNTRUSTED_SENTINEL\":1}",
    raw.replacingOccurrences(
      of: "\"registry_revision\":1", with: "\"registry_revision\":\"UNTRUSTED_SENTINEL\""),
    raw.replacingOccurrences(
      of: "\"registry_revision\":1",
      with: "\"registry_revision\":999999999999999999999999999999999999999999999999"),
  ] {
    do {
      _ = try SuppliedRegistryHistory.verify(suppliedRecords: [Data(supplied.utf8)])
      Issue.record("accepted hostile encoding")
    } catch {
      #expect(error as? SuppliedRegistryHistoryError == .encoding)
      #expect(!String(reflecting: error).contains("UNTRUSTED_SENTINEL"))
      #expect(!String(reflecting: error).contains("999999999"))
    }
  }
  // Positive control: the underlying parser genuinely exposes supplied names.
  var parser = try BoundedJSONParser(
    data: Data("{\"UNTRUSTED_SENTINEL\":0,\"UNTRUSTED_SENTINEL\":1}".utf8), maximumBytes: 4352)
  #expect(throws: ApprovalProtocolError.duplicateField("UNTRUSTED_SENTINEL")) { try parser.parse() }
}

private func suppliedHistoryHighSignature(
  _ object: [String: String], field: String, role: String, scalar: Int
) throws -> Data {
  let encoded = try #require(object[field])
  let low = try P256Signature(derBase64URL: String(encoded.dropFirst().dropLast()))
  let raw = Array(try P256.Signing.ECDSASignature(derRepresentation: low.der).rawRepresentation)
  let order: [UInt8] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
  ]
  var twin = Array(repeating: UInt8(0), count: 32)
  var borrow = 0
  for index in (0..<32).reversed() {
    let difference = Int(order[index]) - Int(raw[index + 32]) - borrow
    twin[index] = UInt8(difference & 255)
    borrow = difference < 0 ? 1 : 0
  }
  func derInteger(_ raw: [UInt8]) -> [UInt8] {
    var scalar = Array(raw.drop(while: { $0 == 0 }))
    if scalar[0] >= 128 { scalar.insert(0, at: 0) }
    return [0x02, UInt8(scalar.count)] + scalar
  }
  let integers = derInteger(Array(raw.prefix(32))) + derInteger(twin)
  let high = Data([0x30, UInt8(integers.count)] + integers)
  let key = try suppliedHistoryKey(scalar)
  let body = try suppliedHistoryEncode(object, body: true)
  var message = Data(("YTA-REGISTRY-RECORD-" + role + "-V1\0").utf8)
  message.append(body)
  #expect(try registrySignatureControl(
    message: message, derSignature: high, x963: key.publicKey.x963Representation))
  return high
}

@Test func suppliedRegistryHistoryRecordCryptoGrammar() throws {
  let base = try suppliedHistoryRecords(["enroll1"])[0]
  let object = try suppliedHistoryObject(base)
  let high = try suppliedHistoryHighSignature(
    object, field: "new_signature", role: "NEW", scalar: 1)
  let cases: [(String, String)] = [
    ("new_signature", suppliedHistoryQuote(suppliedHistoryBase64(high))),
    ("new_signature", suppliedHistoryQuote(suppliedHistoryBase64(Data([0x30, 0])))),
    (
      "new_spki",
      suppliedHistoryQuote(String(try #require(object["new_spki"]).dropFirst().dropLast()) + "=")
    ),
    ("new_spki", suppliedHistoryQuote(suppliedHistoryBase64(Data(repeating: 0, count: 91)))),
    ("new_fingerprint_sha256", suppliedHistoryQuote(String(repeating: "0", count: 64))),
    (
      "new_key_tag",
      suppliedHistoryQuote(
        "io.github.abigotado.youtrack-agent.approval.signing.v1/"
          + String(repeating: "2", count: 32))
    ),
  ]
  for (field, value) in cases {
    var candidate = object
    candidate[field] = value
    let bytes = try suppliedHistoryEncode(candidate)
    #expect(throws: SuppliedRegistryHistoryError.grammar) {
      try SuppliedRegistryHistory.verify(suppliedRecords: [bytes])
    }
  }
}

@Test func suppliedRegistryHistoryCanonicalAndNulls() throws {
  let base = try suppliedHistoryRecords(["enroll1"])[0]
  let raw = String(decoding: base, as: UTF8.self)
  let mutations: [(Data, SuppliedRegistryHistoryError)] = [
    (Data([0xef, 0xbb, 0xbf]) + base, .encoding), (base + Data([0xff]), .encoding),
    (Data([32]) + base, .encoding),
    (Data(raw.replacingOccurrences(of: "\"enroll\"", with: "\"\\u0065nroll\"").utf8), .encoding),
    (
      Data(
        raw.replacingOccurrences(of: "\"registry_revision\":1", with: "\"registry_revision\":1e0")
          .utf8), .encoding
    ),
    (
      Data(
        raw.replacingOccurrences(of: "\"registry_revision\":1", with: "\"registry_revision\":-0")
          .utf8), .encoding
    ),
    (
      Data(
        raw.replacingOccurrences(
          of: "\"record_type\":\"approval_registry_transition\"", with: "\"record_type\":null"
        ).utf8), .grammar
    ),
    (
      Data(
        raw.replacingOccurrences(
          of: "\"target_generation\":null",
          with: "\"target_generation\":\"YTAG-00000000000000000001\""
        ).utf8), .grammar
    ),
    (
      Data(
        raw.replacingOccurrences(
          of: "\"revokes_all_prior\":false", with: "\"revokes_all_prior\":null"
        ).utf8), .grammar
    ),
  ]
  for (bytes, stage) in mutations {
    #expect(throws: stage) { try SuppliedRegistryHistory.verify(suppliedRecords: [bytes]) }
  }
  let object = try suppliedHistoryObject(base)
  for field in suppliedHistoryFields where object[field] == "null" {
    let changed = raw.replacingOccurrences(of: ",\"" + field + "\":null", with: "")
    #expect(changed != raw)
    #expect(throws: SuppliedRegistryHistoryError.encoding) {
      try SuppliedRegistryHistory.verify(suppliedRecords: [Data(changed.utf8)])
    }
  }
}

@Test func suppliedRegistryHistorySignedTimes() throws {
  let base = try suppliedHistoryObject(suppliedHistoryRecords(["enroll1"])[0])
  let key = try suppliedHistoryKey(1)
  let cases: [(String, String, String, String, SuppliedRegistryHistoryError?)] = [
    ("year-zero-leap", "0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", nil),
    ("year-one", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", nil),
    ("year-max", "9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z", nil),
    ("cutover", "1582-10-10T00:00:00Z", "1582-10-10T00:00:01Z", "1582-10-10T00:00:02Z", nil),
    (
      "invalid-century-leap", "1500-02-29T00:00:00Z", "1500-02-29T00:00:00Z",
      "1500-02-29T00:00:00Z", .grammar
    ),
    ("299-seconds", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:04:59Z", nil),
    (
      "300-seconds", "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:05:00Z", .replay
    ),
    (
      "reverse-acceptance", "2000-01-01T00:00:01Z", "2000-01-01T00:00:00Z", "2000-01-01T00:00:02Z",
      .replay
    ),
    (
      "reverse-commit", "2000-01-01T00:00:00Z", "2000-01-01T00:00:02Z", "2000-01-01T00:00:01Z",
      .replay
    ),
    ("full-range", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z", .replay),
  ]
  for (name, requested, accepted, committed, stage) in cases {
    var object = base
    object["requested_at"] = suppliedHistoryQuote(requested)
    object["accepted_at"] = suppliedHistoryQuote(accepted)
    object["committed_at"] = suppliedHistoryQuote(committed)
    let raw = try suppliedHistorySign(object, fresh: key)
    if let stage {
      #expect(throws: stage, "\(name)") {
        try SuppliedRegistryHistory.verify(suppliedRecords: [raw])
      }
    } else {
      _ = try SuppliedRegistryHistory.verify(suppliedRecords: [raw])
    }
  }
}

@Test func suppliedRegistryHistoryHTMLPhase() throws {
  let records = try suppliedHistoryRecords(["enroll1", "rotate2"])
  let earlierGrammar = Data(
    String(decoding: records[0], as: UTF8.self).replacingOccurrences(
      of: "\"registry_revision\":1", with: "\"registry_revision\":257"
    ).utf8)
  for value in ["<", ">", "&"] {
    let laterEncoding = Data(
      String(decoding: records[1], as: UTF8.self).replacingOccurrences(
        of: "\"record_type\":\"approval_registry_transition\"",
        with: "\"record_type\":\"" + value + "\""
      ).utf8)
    #expect(laterEncoding != records[1])
    for supplied in [[laterEncoding], [earlierGrammar, laterEncoding]] {
      #expect(throws: SuppliedRegistryHistoryError.encoding, "raw \(value)") {
        try SuppliedRegistryHistory.verify(suppliedRecords: supplied)
      }
    }
  }
}

@Test func suppliedRegistryHistorySignedRecoveryAndHistoryOrder() throws {
  let records = try suppliedHistoryRecords(["enroll1", "rotate2", "recover-active3"])
  var object = try suppliedHistoryObject(records[2])
  for field in suppliedHistoryFields where field.hasPrefix("target_") { object[field] = "null" }
  let omittedTarget = try suppliedHistorySign(object, fresh: suppliedHistoryKey(3))
  for supplied in [
    [records[0], records[1], omittedTarget], [records[2]], [records[1], records[0]],
    [records[0], records[0]], [records[0], records[2]],
  ] {
    #expect(throws: SuppliedRegistryHistoryError.replay) {
      try SuppliedRegistryHistory.verify(suppliedRecords: supplied)
    }
  }
  var descriptor = try suppliedHistoryObject(records[1])
  descriptor["artifact_descriptor_sha256"] = suppliedHistoryQuote(String(repeating: "b", count: 64))
  let changed = try suppliedHistorySign(
    descriptor, old: suppliedHistoryKey(1), fresh: suppliedHistoryKey(2))
  let result = try SuppliedRegistryHistory.verify(suppliedRecords: [records[0], changed])
  #expect(result.suppliedTipDescriptorSHA256 == String(repeating: "b", count: 64))
  #expect(result.suppliedRevision == 2)
}

@Test func suppliedRegistryHistorySeparatelyRejectsIdentityAndPublicKeyReuse() throws {
  let records = try suppliedHistoryRecords(["enroll1", "rotate2"])
  let previous = try suppliedHistoryObject(records[0])
  let old = try suppliedHistoryKey(1)
  let fresh = try suppliedHistoryKey(2)
  for group in ["identity", "public-key"] {
    var object = try suppliedHistoryObject(records[1])
    let fields =
      group == "identity" ? ["new_key_id", "new_key_tag"] : ["new_spki", "new_fingerprint_sha256"]
    for field in fields {
      let value: String = try #require(previous[field])
      object[field] = value
    }
    let bytes = try suppliedHistorySign(object, old: old, fresh: group == "identity" ? fresh : old)
    #expect(throws: SuppliedRegistryHistoryError.replay, "\(group)") {
      try SuppliedRegistryHistory.verify(suppliedRecords: [records[0], bytes])
    }
  }
}

@Test func suppliedRegistryHistoryGenerationTokenGrammar() throws {
  let records = try suppliedHistoryRecords(["enroll1", "rotate2"])
  let values = [
    ("zero", "YTAG-" + String(repeating: "0", count: 20)),
    ("short", "YTAG-" + String(repeating: "0", count: 18) + "1"),
    ("long", "YTAG-" + String(repeating: "0", count: 20) + "1"),
    ("sign", "YTAG-+" + String(repeating: "0", count: 18) + "1"),
    ("nondigit", "YTAG-" + String(repeating: "0", count: 19) + "x"),
  ]
  for field in ["new_generation", "target_generation"] {
    for (name, value) in values {
      var object = try suppliedHistoryObject(records[1])
      object[field] = suppliedHistoryQuote(value)
      // All other tuple members remain populated; partial-null rejection cannot
      // substitute for the generation token's own width/digit validation.
      let bytes = try suppliedHistoryEncode(object)
      #expect(throws: SuppliedRegistryHistoryError.grammar, "\(field)/\(name)") {
        try SuppliedRegistryHistory.verify(suppliedRecords: [records[0], bytes])
      }
    }
  }
}

@Test func suppliedRegistryHistoryForbiddenSignatureRolesAndRevokeTuple() throws {
  let records = try suppliedHistoryRecords(["enroll1", "rotate2", "revoke3"])
  let one = try suppliedHistoryKey(1)
  let two = try suppliedHistoryKey(2)
  let three = try suppliedHistoryKey(3)
  let enrollOld = try suppliedHistorySign(suppliedHistoryObject(records[0]), old: one, fresh: one)
  let recovery = try suppliedHistoryRecords(["recover-active3"])[0]
  let recoverOld = try suppliedHistorySign(suppliedHistoryObject(recovery), old: two, fresh: three)
  let revokeNew = try suppliedHistorySign(suppliedHistoryObject(records[2]), old: two, fresh: three)
  var tuple = try suppliedHistoryObject(records[2])
  let id = String(format: "%032x", 3)
  let spki = suppliedHistorySPKI(three)
  tuple["new_generation"] = suppliedHistoryQuote(String(format: "YTAG-%020d", 3))
  tuple["new_key_id"] = suppliedHistoryQuote(id)
  tuple["new_key_tag"] = suppliedHistoryQuote(
    "io.github.abigotado.youtrack-agent.approval.signing.v1/" + id)
  tuple["new_spki"] = suppliedHistoryQuote(suppliedHistoryBase64(spki))
  tuple["new_fingerprint_sha256"] = suppliedHistoryQuote(suppliedHistoryHash(spki))
  tuple["new_status"] = suppliedHistoryQuote("active")
  // Generation 3 is valid at revision 3, and the changed body is signed by
  // current old key 2. Only the revoke field combination is forbidden.
  let revokeTuple = try suppliedHistorySign(tuple, old: two, fresh: nil)
  for (name, supplied) in [
    ("enroll-old", [enrollOld]), ("recover-old", [records[0], records[1], recoverOld]),
    ("revoke-new", [records[0], records[1], revokeNew]),
    ("revoke-tuple", [records[0], records[1], revokeTuple]),
  ] {
    #expect(throws: SuppliedRegistryHistoryError.replay, "\(name)") {
      try SuppliedRegistryHistory.verify(suppliedRecords: supplied)
    }
  }
  var oldHigh = try suppliedHistoryObject(records[1])
  let high = try suppliedHistoryHighSignature(
    oldHigh, field: "old_signature", role: "OLD", scalar: 1)
  oldHigh["old_signature"] = suppliedHistoryQuote(suppliedHistoryBase64(high))
  let raw = try suppliedHistoryEncode(oldHigh)
  #expect(throws: SuppliedRegistryHistoryError.grammar) {
    try SuppliedRegistryHistory.verify(suppliedRecords: [records[0], raw])
  }
}

@Test func suppliedRegistryHistoryMaximalLedgerDescriptorUpgradeAndValueCopies() throws {
  let base = try suppliedHistoryObject(suppliedHistoryRecords(["enroll1"])[0])
  var records: [Data] = []
  var previous: [String: String]?
  var old: P256.Signing.PrivateKey?
  for revision in 1...256 {
    let fresh = try suppliedHistoryKey(revision)
    let spki = suppliedHistorySPKI(fresh)
    let id = String(format: "%032x", revision)
    var object = base
    object["registry_revision"] = String(revision)
    object["new_generation"] = suppliedHistoryQuote(String(format: "YTAG-%020d", revision))
    object["new_key_id"] = suppliedHistoryQuote(id)
    object["new_key_tag"] = suppliedHistoryQuote(
      "io.github.abigotado.youtrack-agent.approval.signing.v1/" + id)
    object["new_spki"] = suppliedHistoryQuote(suppliedHistoryBase64(spki))
    object["new_fingerprint_sha256"] = suppliedHistoryQuote(suppliedHistoryHash(spki))
    if let previous {
      object["transition_kind"] = suppliedHistoryQuote("rotate")
      object["previous_record_sha256"] = suppliedHistoryQuote(
        suppliedHistoryHash(try #require(records.last)))
      for suffix in ["generation", "key_id", "key_tag", "spki", "fingerprint_sha256"] {
        let value: String = try #require(previous["new_" + suffix])
        object["target_" + suffix] = value
      }
      object["target_previous_status"] = suppliedHistoryQuote("active")
      object["target_new_status"] = suppliedHistoryQuote("retained")
    }
    if revision == 256 {
      object["artifact_descriptor_sha256"] = suppliedHistoryQuote(String(repeating: "b", count: 64))
    }
    records.append(try suppliedHistorySign(object, old: old, fresh: fresh))
    old = fresh
    previous = object
  }
  let last = try #require(records.last)
  let expectedTip = suppliedHistoryHash(last)
  let result = try SuppliedRegistryHistory.verify(suppliedRecords: records)
  #expect(result.suppliedRevision == 256)
  try #require(result.keys.count == 256)
  #expect(result.suppliedTipSHA256 == expectedTip)
  #expect(result.suppliedTipDescriptorSHA256 == String(repeating: "b", count: 64))
  #expect(result.keys.dropLast().allSatisfy({ $0.status == "retained" }))
  #expect(result.keys.last?.status == "active")
  #expect(result.keys.last?.generation == String(format: "YTAG-%020d", 256))
  #expect(throws: SuppliedRegistryHistoryError.bounds) {
    try SuppliedRegistryHistory.verify(suppliedRecords: records + [last])
  }
  let expectedKeys = result.keys
  var copiedKeys = result.keys
  copiedKeys.removeAll()
  records[0][0] = 120
  records[255][0] = 120
  records.removeLast()
  #expect(copiedKeys.isEmpty)
  #expect(result.keys == expectedKeys)
  #expect(result.suppliedRevision == 256)
  #expect(result.suppliedTipSHA256 == expectedTip)
  #expect(result.suppliedTipDescriptorSHA256 == String(repeating: "b", count: 64))
}
