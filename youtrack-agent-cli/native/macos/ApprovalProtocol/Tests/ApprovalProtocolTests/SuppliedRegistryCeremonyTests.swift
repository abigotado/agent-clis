import CryptoKit
import Foundation
import Testing

@testable import ApprovalProtocol

private func ceremonyInput(_ tr: RegistryTranscript) -> SuppliedRegistryCeremony {
  SuppliedRegistryCeremony(
    request: Data(tr.request.utf8), recoveryEvidence: tr.recovery_evidence.map { Data($0.utf8) },
    unsignedProposal: Data(tr.unsigned_proposal.utf8), signedProposal: Data(tr.proposal.utf8),
    acceptance: Data(tr.acceptance.utf8), finalBody: Data(tr.final_body.utf8),
    record: Data(tr.record.utf8))
}

private func ceremonyPrefix(_ names: [String], _ corpus: RegistryCorpus) throws -> [Data] {
  try names.map { name in Data(try #require(corpus.positives.first { $0.id == name }).record.utf8) }
}

private func ceremonyStage(_ id: String) throws -> SuppliedRegistryCeremonyError {
  if id.hasPrefix("size-") { return id.hasSuffix("-over") ? .bounds : .encoding }
  if id.hasPrefix("encoding-") { return .encoding }
  if ["grammar-record-revision--1", "grammar-request-negative-revision", "grammar-schema-negative"]
    .contains(id)
  {
    return .encoding
  }
  if id.hasPrefix("grammar-") { return .grammar }
  if [
    "recovery-lookup-success", "recovery-continuity-success", "recovery-lookup-canceled",
    "recovery-lookup-auth-failed", "recovery-lookup-interaction", "recovery-lookup-unknown",
  ].contains(id) {
    return .grammar
  }
  if ["digest-", "signature-", "time-", "state-", "recovery-", "prefix-"].contains(where: {
    id.hasPrefix($0)
  }) || id == "acceptance-false" {
    return .verification
  }
  Issue.record("unreviewed negative \(id)")
  throw SuppliedRegistryCeremonyError.verification
}

private func ceremonyFailure(
  _ prefix: [Data], _ input: SuppliedRegistryCeremony, _ stage: SuppliedRegistryCeremonyError
) {
  #expect(throws: stage) {
    try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: input)
  }
  do {
    _ = try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: input)
    Issue.record("invalid ceremony accepted")
  } catch {
    let diagnostic = String(reflecting: error)
    #expect(!diagnostic.contains("UNTRUSTED_SENTINEL"))
    #expect(!diagnostic.contains("999999999"))
  }
}

private func ceremonyReplacing(
  _ input: SuppliedRegistryCeremony, request: Data? = nil,
  recovery: Data? = nil, replaceRecovery: Bool = false, record: Data? = nil
) -> SuppliedRegistryCeremony {
  SuppliedRegistryCeremony(
    request: request ?? input.request,
    recoveryEvidence: replaceRecovery ? recovery : input.recoveryEvidence,
    unsignedProposal: input.unsignedProposal, signedProposal: input.signedProposal,
    acceptance: input.acceptance, finalBody: input.finalBody, record: record ?? input.record)
}

private func ceremonyReplace(_ data: Data, _ old: String, _ new: String) throws -> Data {
  let raw = try #require(String(data: data, encoding: .utf8))
  #expect(raw.components(separatedBy: old).count == 2)
  return Data(raw.replacingOccurrences(of: old, with: new).utf8)
}

@Test func suppliedRegistryCeremonyPinnedPositives() throws {
  let corpus = try registryCorpus()
  let cases: [(String, [String], [String], [String], String)] = [
    (
      "enroll1", [], ["00000000000000000001"], ["active"],
      "c8154cd7d2a72f7e23dcbfa9f52d1b9ca97afad557c6becedf9eaf7a772db16b"
    ),
    (
      "rotate2", ["enroll1"], ["00000000000000000001", "00000000000000000002"],
      ["retained", "active"], "4c4394736cf2e1e619e5cdef3a45104b9dddd344d5febff6061d4bd37a877f5c"
    ),
    (
      "revoke3", ["enroll1", "rotate2"], ["00000000000000000001", "00000000000000000002"],
      ["retained", "revoked"], "8fc41f67fcc9b80d7eac1cf16f2e4bb581b753e2c4f3c2a87bc2125247ad3f75"
    ),
    (
      "recover-disabled4", ["enroll1", "rotate2", "revoke3"],
      ["00000000000000000001", "00000000000000000002", "00000000000000000004"],
      ["revoked", "revoked", "active"],
      "083686890e6a8b2fa969143f74d5a147415aaa125df7917344da9a636fa15f7c"
    ),
    (
      "recover-active3", ["enroll1", "rotate2"],
      ["00000000000000000001", "00000000000000000002", "00000000000000000003"],
      ["revoked", "revoked", "active"],
      "6d1f7ea55313a4ffd01cd5c2ddb732dcf871b2fe722699779e83b1b0b33453e6"
    ),
  ]
  for (id, names, generations, statuses, hash) in cases {
    let positive = try #require(corpus.positives.first { $0.id == id })
    #expect(positive.prefix == names)
    var prefix = try ceremonyPrefix(names, corpus)
    let input = ceremonyInput(positive.transcript)
    let result = try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: input)
    #expect(result.suppliedRevision == names.count + 1)
    #expect(result.suppliedTipSHA256 == hash)
    #expect(result.suppliedTipDescriptorSHA256 == String(repeating: "a", count: 64))
    #expect(result.keys.map(\.generation) == generations.map { "YTAG-" + $0 })
    #expect(result.keys.map(\.status) == statuses)
    for key in result.keys {
      let expected = try #require(corpus.keys.first { $0.generation == key.generation })
      #expect(key.keyID == expected.key_id)
      #expect(key.keyTag == expected.key_tag)
      #expect(key.spki == expected.spki)
      #expect(key.fingerprintSHA256 == expected.fingerprint_sha256)
    }
    var copiedKeys = result.keys
    copiedKeys.removeAll()
    for index in prefix.indices { prefix[index].resetBytes(in: 0..<prefix[index].count) }
    var copiedRecord = input.record
    copiedRecord.resetBytes(in: 0..<copiedRecord.count)
    #expect(result.keys.map(\.generation) == generations.map { "YTAG-" + $0 })
    #expect(result.suppliedTipSHA256 == hash)
    #expect(input.record == Data(positive.record.utf8))
  }
}

@Test func suppliedRegistryCeremonyAllCoreNegatives() throws {
  let corpus = try registryCorpus()
  #expect(corpus.negatives.count == 121)
  for negative in corpus.negatives {
    let prefix =
      try negative.prefix_records.map { $0.map { Data($0.utf8) } }
      ?? ceremonyPrefix(negative.prefix, corpus)
    ceremonyFailure(prefix, ceremonyInput(negative.transcript), try ceremonyStage(negative.id))
  }
}

@Test func suppliedRegistryCeremonySignedSemanticControls() throws {
  let corpus = try registryCorpus()
  let names = [
    "digest-predecessor", "acceptance-false", "state-revoke-all-false", "state-wrong-target",
    "state-key-reuse", "state-revision-gap", "time-proposal-at-expiry",
    "time-acceptance-before-proposal", "time-commit-at-expiry", "time-request-window-over",
    "recovery-lookup-success", "recovery-continuity-success", "recovery-lookup-canceled",
    "recovery-lookup-auth-failed", "recovery-lookup-interaction", "recovery-lookup-unknown",
    "recovery-wrong-eligibility", "recovery-evidence-missing",
  ]
  var seen = 0
  for negative in corpus.negatives where names.contains(negative.id) {
    seen += 1
    let proposal = try #require(
      try JSONSerialization.jsonObject(with: Data(negative.transcript.proposal.utf8))
        as? [String: Any])
    let record = try #require(
      try JSONSerialization.jsonObject(with: Data(negative.transcript.record.utf8))
        as? [String: Any])
    let role = try #require(proposal["proposal_signer_role"] as? String)
    let spki = try #require(proposal[role == "old" ? "target_spki" : "new_spki"] as? String)
    let signature = try #require(proposal["proposal_signature"] as? String)
    try ceremonySignatureControl(
      spki, signature, "YTA-REGISTRY-PROPOSAL-V1\0", negative.transcript.unsigned_proposal)
    for (field, key, domain) in [
      ("old_signature", "target_spki", "YTA-REGISTRY-RECORD-OLD-V1\0"),
      ("new_signature", "new_spki", "YTA-REGISTRY-RECORD-NEW-V1\0"),
    ] {
      if record[field] is NSNull { continue }
      try ceremonySignatureControl(
        try #require(record[key] as? String), try #require(record[field] as? String), domain,
        negative.transcript.final_body)
    }
  }
  #expect(seen == names.count)
}

private func ceremonySignatureControl(
  _ spki: String, _ signature: String, _ domain: String, _ body: String
) throws {
  let raw = try registryBase64(spki, count: 91)
  let x963 = try P256PublicKeyCodec.x963(fromSPKIDER: raw)
  let sig = try P256Signature(derBase64URL: signature)
  let message = Data((domain + body).utf8)
  #expect(
    try registrySignatureControl(
      message: message, derSignature: sig.der, x963: x963))
  #expect(try P256PublicKeyCodec.verify(message: message, derSignature: sig.der, x963: x963))
}

@Test func suppliedRegistryCeremonyPhasesEvidenceAndRedaction() throws {
  let corpus = try registryCorpus()
  let wrong = try #require(corpus.negatives.first { $0.id == "signature-proposal-wrong-key" })
  let first = ceremonyInput(wrong.transcript)
  let prefix = try ceremonyPrefix(wrong.prefix, corpus)
  ceremonyFailure(prefix, first, .verification)
  ceremonyFailure(prefix, ceremonyReplacing(first, record: first.record + Data([10])), .encoding)
  ceremonyFailure(
    prefix,
    ceremonyReplacing(
      first,
      record: try ceremonyReplace(
        first.record, "\"registry_revision\":2", "\"registry_revision\":257")), .grammar)
  ceremonyFailure(
    prefix,
    ceremonyReplacing(first, request: Data("bad".utf8), record: Data(repeating: 120, count: 4353)),
    .bounds)
  ceremonyFailure(
    prefix,
    ceremonyReplacing(
      first,
      request: try ceremonyReplace(first.request, "\"schema_version\":1", "\"schema_version\":0"),
      record: first.record + Data([10])), .encoding)
  let enroll = ceremonyInput(try #require(corpus.positives.first { $0.id == "enroll1" }).transcript)
  let recover = ceremonyInput(
    try #require(corpus.positives.first { $0.id == "recover-active3" }).transcript)
  ceremonyFailure([], ceremonyReplacing(enroll, recovery: Data(), replaceRecovery: true), .bounds)
  ceremonyFailure(
    try ceremonyPrefix(["enroll1", "rotate2"], corpus),
    ceremonyReplacing(recover, replaceRecovery: true), .verification)
  ceremonyFailure(
    [], ceremonyReplacing(enroll, recovery: recover.recoveryEvidence, replaceRecovery: true),
    .verification)
  let hostile = Data("{\"UNTRUSTED_SENTINEL\":0,\"UNTRUSTED_SENTINEL\":1}".utf8)
  var parser = try BoundedJSONParser(data: hostile, maximumBytes: 2048)
  #expect(throws: ApprovalProtocolError.duplicateField("UNTRUSTED_SENTINEL")) { try parser.parse() }
  for raw in [
    hostile,
    try ceremonyReplace(
      enroll.request, "\"expected_registry_revision\":0",
      "\"expected_registry_revision\":\"UNTRUSTED_SENTINEL\""),
    try ceremonyReplace(
      enroll.request, "\"expected_registry_revision\":0",
      "\"expected_registry_revision\":999999999999999999999999999999999999999"),
  ] {
    ceremonyFailure([], ceremonyReplacing(enroll, request: raw), .encoding)
  }
  ceremonyFailure(Array(repeating: Data(), count: 256), enroll, .bounds)
}

// Literal schema construction and unsafe public scalar keys are independent
// of both production encoders and the full transcript verdict oracle.
private let ceremonyRequestFields =
  "schema_version message_type transition_kind recovery_mode challenge expected_registry_revision previous_record_sha256 artifact_descriptor_sha256 target_generation new_generation requested_at expires_at"
private let ceremonyProposalFields =
  "schema_version message_type transition_kind request_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 proposed_at expires_at proposal_signer_role"
private let ceremonyAcceptanceFields =
  "schema_version message_type transition_kind request_sha256 proposal_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 target_generation new_generation accepted_at expires_at accepted"
private let ceremonyEvidenceFields =
  "schema_version message_type request_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 target_generation target_key_tag eligibility key_lookup_result continuity_probe_result probed_at"
private let ceremonyRecordFields =
  "schema_version record_type transition_kind registry_revision previous_record_sha256 request_sha256 proposal_sha256 acceptance_sha256 challenge_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 requested_at accepted_at committed_at target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 target_previous_status target_new_status new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 new_status revokes_all_prior old_signature new_signature"

private func ceremonyQuote(_ value: String) -> String { "\"" + value + "\"" }
private func ceremonyHash(_ bytes: Data) -> String {
  SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
}
private func ceremonyBase64(_ bytes: Data) -> String {
  bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(
    of: "/", with: "_"
  ).replacingOccurrences(of: "=", with: "")
}
private func ceremonyObject(_ bytes: Data) throws -> [String: String] {
  let raw = try #require(try JSONSerialization.jsonObject(with: bytes) as? [String: Any])
  var object: [String: String] = [:]
  for (field, value) in raw {
    if value is NSNull {
      object[field] = "null"
    } else if let text = value as? String {
      object[field] = ceremonyQuote(text)
    } else if let number = value as? NSNumber {
      object[field] =
        ["accepted", "revokes_all_prior"].contains(field)
        ? (number.boolValue ? "true" : "false") : number.stringValue
    } else {
      Issue.record("unexpected fixture primitive")
    }
  }
  return object
}
private func ceremonyEncode(_ object: [String: String], _ fields: String) throws -> Data {
  let pairs = try fields.split(separator: " ").map { field in
    "\"" + field + "\":" + (try #require(object[String(field)]))
  }
  return Data(("{" + pairs.joined(separator: ",") + "}").utf8)
}
private func ceremonyKey(_ revision: Int) throws -> P256.Signing.PrivateKey {
  var scalar = Data(repeating: 0, count: 32)
  scalar[30] = UInt8(revision >> 8)
  scalar[31] = UInt8(revision & 255)
  return try P256.Signing.PrivateKey(rawRepresentation: scalar)
}
private func ceremonyTuple(_ revision: Int, _ key: P256.Signing.PrivateKey) -> [String: String] {
  var spki = Data([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  ])
  spki.append(key.publicKey.x963Representation)
  let id =
    String(repeating: "0", count: 32 - String(revision, radix: 16).count)
    + String(revision, radix: 16)
  return [
    "generation": ceremonyQuote(String(format: "YTAG-%020d", revision)),
    "key_id": ceremonyQuote(id),
    "key_tag": ceremonyQuote("io.github.abigotado.youtrack-agent.approval.signing.v1/" + id),
    "spki": ceremonyQuote(ceremonyBase64(spki)),
    "fingerprint_sha256": ceremonyQuote(ceremonyHash(spki)),
  ]
}
private func ceremonySign(_ message: Data, _ key: P256.Signing.PrivateKey) throws -> String {
  let signature = try key.signature(for: message)
  #expect(try registrySignatureControl(
    message: message, derSignature: signature.derRepresentation,
    x963: key.publicKey.x963Representation))
  let low = try P256Signature.normalizeLowS(der: signature.derRepresentation)
  #expect(try registrySignatureControl(
    message: message, derSignature: low.der, x963: key.publicKey.x963Representation))
  #expect(try P256PublicKeyCodec.verify(
    message: message, derSignature: low.der, x963: key.publicKey.x963Representation))
  return ceremonyQuote(low.base64URL)
}
private func ceremonyRecord(
  _ fields: [String: String], _ old: P256.Signing.PrivateKey?, _ fresh: P256.Signing.PrivateKey?
) throws -> Data {
  var r = fields
  let bodyFields = ceremonyRecordFields.split(separator: " ").prefix(28).joined(separator: " ")
  let body = try ceremonyEncode(r, bodyFields)
  for (field, domain, key) in [
    ("old_signature", "YTA-REGISTRY-RECORD-OLD-V1\0", old),
    ("new_signature", "YTA-REGISTRY-RECORD-NEW-V1\0", fresh),
  ] {
    r[field] = "null"
    if let key { r[field] = try ceremonySign(Data(domain.utf8) + body, key) }
  }
  return try ceremonyEncode(r, ceremonyRecordFields)
}
private func ceremonyRebuild(
  _ original: SuppliedRegistryCeremony, _ q: [String: String], _ proposal: [String: String],
  _ acceptance: [String: String], _ record: [String: String], _ old: P256.Signing.PrivateKey?,
  _ fresh: P256.Signing.PrivateKey
) throws -> SuppliedRegistryCeremony {
  var p = proposal
  var a = acceptance
  var r = record
  for field in [
    "transition_kind", "previous_record_sha256", "artifact_descriptor_sha256", "target_generation",
    "new_generation",
  ] {
    p[field] = q[field]
    a[field] = q[field]
    r[field] = q[field]
  }
  let request = try ceremonyEncode(q, ceremonyRequestFields)
  let challenge = try registryBase64(
    try #require(q["challenge"]).replacingOccurrences(of: "\"", with: ""), count: 32)
  for field in ["request_sha256", "challenge_sha256", "registry_revision"] {
    let value: String?
    switch field {
    case "request_sha256":
      value = ceremonyQuote(ceremonyHash(Data("YTA-REGISTRY-REQUEST-V1\0".utf8) + request))
    case "challenge_sha256": value = ceremonyQuote(ceremonyHash(challenge))
    default: value = r[field]
    }
    p[field] = value
    a[field] = value
    r[field] = value
  }
  p["expires_at"] = q["expires_at"]
  a["expires_at"] = q["expires_at"]
  r["requested_at"] = q["requested_at"]
  r["accepted_at"] = a["accepted_at"]
  for field in ["generation", "key_id", "key_tag", "spki", "fingerprint_sha256"] {
    p["target_" + field] = r["target_" + field]
    p["new_" + field] = r["new_" + field]
  }
  p["proposal_signer_role"] = ceremonyQuote("new")
  let unsigned = try ceremonyEncode(p, ceremonyProposalFields)
  p["proposal_signature"] = try ceremonySign(
    Data("YTA-REGISTRY-PROPOSAL-V1\0".utf8) + unsigned, fresh)
  let signed = try ceremonyEncode(p, ceremonyProposalFields + " proposal_signature")
  let hash = ceremonyQuote(ceremonyHash(Data("YTA-REGISTRY-PROPOSAL-DIGEST-V1\0".utf8) + signed))
  a["proposal_sha256"] = hash
  r["proposal_sha256"] = hash
  let accepted = try ceremonyEncode(a, ceremonyAcceptanceFields)
  r["acceptance_sha256"] = ceremonyQuote(
    ceremonyHash(Data("YTA-REGISTRY-ACCEPTANCE-V1\0".utf8) + accepted))
  return SuppliedRegistryCeremony(
    request: request, recoveryEvidence: original.recoveryEvidence, unsignedProposal: unsigned,
    signedProposal: signed, acceptance: accepted,
    finalBody: try ceremonyEncode(
      r, ceremonyRecordFields.split(separator: " ").prefix(28).joined(separator: " ")),
    record: try ceremonyRecord(r, old, fresh))
}

@Test func suppliedRegistryCeremonyMaximalCandidateAndDescriptorUpgrade() throws {
  let corpus = try registryCorpus()
  let enroll = ceremonyInput(try #require(corpus.positives.first { $0.id == "enroll1" }).transcript)
  let base = try ceremonyObject(enroll.record)
  var prefix: [Data] = []
  var old: P256.Signing.PrivateKey?
  var previous: [String: String] = [:]
  for revision in 1...255 {
    let fresh = try ceremonyKey(revision)
    let tuple = ceremonyTuple(revision, fresh)
    var r = base
    r["registry_revision"] = String(revision)
    for (field, value) in tuple { r["new_" + field] = value }
    if revision > 1 {
      r["transition_kind"] = ceremonyQuote("rotate")
      r["previous_record_sha256"] = ceremonyQuote(ceremonyHash(try #require(prefix.last)))
      for (field, value) in previous { r["target_" + field] = value }
      r["target_previous_status"] = ceremonyQuote("active")
      r["target_new_status"] = ceremonyQuote("retained")
    }
    prefix.append(try ceremonyRecord(r, old, fresh))
    old = fresh
    previous = tuple
  }
  let original = ceremonyInput(
    try #require(corpus.positives.first { $0.id == "rotate2" }).transcript)
  let fresh = try ceremonyKey(256)
  let tuple = ceremonyTuple(256, fresh)
  var q = try ceremonyObject(original.request)
  var r = try ceremonyObject(original.record)
  q["expected_registry_revision"] = "255"
  r["registry_revision"] = "256"
  q["previous_record_sha256"] = ceremonyQuote(ceremonyHash(prefix[254]))
  q["target_generation"] = previous["generation"]
  q["new_generation"] = tuple["generation"]
  q["artifact_descriptor_sha256"] = ceremonyQuote(String(repeating: "b", count: 64))
  for (field, value) in previous { r["target_" + field] = value }
  for (field, value) in tuple { r["new_" + field] = value }
  let candidate = try ceremonyRebuild(
    original, q, ceremonyObject(original.signedProposal), ceremonyObject(original.acceptance), r,
    old, fresh)
  let result = try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: candidate)
  #expect(result.suppliedRevision == 256)
  #expect(result.suppliedTipSHA256 == ceremonyHash(candidate.record))
  #expect(result.suppliedTipDescriptorSHA256 == String(repeating: "b", count: 64))
  #expect(result.keys.count == 256)
  #expect(result.keys.prefix(255).allSatisfy { $0.status == "retained" })
  #expect(result.keys.last?.status == "active")
  ceremonyFailure(prefix + [candidate.record], candidate, .bounds)
  var a = try ceremonyObject(candidate.acceptance)
  a["artifact_descriptor_sha256"] = ceremonyQuote(String(repeating: "c", count: 64))
  let accepted = try ceremonyEncode(a, ceremonyAcceptanceFields)
  r = try ceremonyObject(candidate.record)
  r["acceptance_sha256"] = ceremonyQuote(
    ceremonyHash(Data("YTA-REGISTRY-ACCEPTANCE-V1\0".utf8) + accepted))
  let mismatch = SuppliedRegistryCeremony(
    request: candidate.request, recoveryEvidence: nil, unsignedProposal: candidate.unsignedProposal,
    signedProposal: candidate.signedProposal, acceptance: accepted,
    finalBody: try ceremonyEncode(
      r, ceremonyRecordFields.split(separator: " ").prefix(28).joined(separator: " ")),
    record: try ceremonyRecord(r, old, fresh))
  ceremonyFailure(prefix, mismatch, .verification)
}

@Test func suppliedRegistryCeremonySignedCalendarAndExpiry() throws {
  let corpus = try registryCorpus()
  let original = ceremonyInput(
    try #require(corpus.positives.first { $0.id == "enroll1" }).transcript)
  let key = try ceremonyKey(1)
  let cases: [(String, String, String, SuppliedRegistryCeremonyError?)] = [
    ("0000-02-29T12:00:00Z", "0000-02-29T12:00:00Z", "0000-02-29T12:00:01Z", nil),
    ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "0001-01-01T00:00:01Z", nil),
    ("9999-12-31T23:59:58Z", "9999-12-31T23:59:58Z", "9999-12-31T23:59:59Z", nil),
    ("2000-01-01T00:00:00Z", "2000-01-01T00:04:59Z", "2000-01-01T00:05:00Z", nil),
    ("2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "2000-01-01T00:05:01Z", .verification),
    ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z", .verification),
    ("1500-02-29T00:00:00Z", "1500-02-29T00:00:00Z", "1500-02-29T00:00:01Z", .grammar),
  ]
  for (requested, committed, expires, stage) in cases {
    var q = try ceremonyObject(original.request)
    var p = try ceremonyObject(original.signedProposal)
    var a = try ceremonyObject(original.acceptance)
    var r = try ceremonyObject(original.record)
    q["requested_at"] = ceremonyQuote(requested)
    q["expires_at"] = ceremonyQuote(expires)
    p["proposed_at"] = ceremonyQuote(requested)
    a["accepted_at"] = ceremonyQuote(requested)
    r["committed_at"] = ceremonyQuote(committed)
    let candidate = try ceremonyRebuild(original, q, p, a, r, nil, key)
    if let stage {
      ceremonyFailure([], candidate, stage)
    } else {
      let result = try SuppliedRegistryCeremony.verify(prefixRecords: [], ceremony: candidate)
      #expect(result.suppliedRevision == 1)
      #expect(result.suppliedTipSHA256 == ceremonyHash(candidate.record))
    }
  }
}

@Test func suppliedRegistryCeremonyUnsignedProjectionEquality() throws {
  let corpus = try registryCorpus()
  let positive = try #require(corpus.positives.first { $0.id == "enroll1" })
  let original = ceremonyInput(positive.transcript)
  let key = try ceremonyKey(1)
  var unsigned = try ceremonyObject(original.unsignedProposal)
  unsigned["proposed_at"] = ceremonyQuote("2026-09-01T12:00:02Z")
  let suppliedUnsigned = try ceremonyEncode(unsigned, ceremonyProposalFields)
  var proposal = try ceremonyObject(original.signedProposal)
  proposal["proposal_signature"] = try ceremonySign(
    Data("YTA-REGISTRY-PROPOSAL-V1\0".utf8) + suppliedUnsigned, key)
  let signedProposal = try ceremonyEncode(proposal, ceremonyProposalFields + " proposal_signature")
  let rawSignature = try #require(proposal["proposal_signature"]).replacingOccurrences(
    of: "\"", with: "")
  let signature = try P256Signature(derBase64URL: rawSignature).der
  #expect(
    try registrySignatureControl(
      message: Data("YTA-REGISTRY-PROPOSAL-V1\0".utf8) + suppliedUnsigned,
      derSignature: signature, x963: key.publicKey.x963Representation))
  #expect(try P256PublicKeyCodec.verify(
    message: Data("YTA-REGISTRY-PROPOSAL-V1\0".utf8) + suppliedUnsigned,
    derSignature: signature, x963: key.publicKey.x963Representation))
  #expect(
    try !registrySignatureControl(
      message: Data("YTA-REGISTRY-PROPOSAL-V1\0".utf8) + original.unsignedProposal,
      derSignature: signature, x963: key.publicKey.x963Representation))
  #expect(try !P256PublicKeyCodec.verify(
    message: Data("YTA-REGISTRY-PROPOSAL-V1\0".utf8) + original.unsignedProposal,
    derSignature: signature, x963: key.publicKey.x963Representation))
  var acceptance = try ceremonyObject(original.acceptance)
  var record = try ceremonyObject(original.record)
  let digest = ceremonyQuote(
    ceremonyHash(Data("YTA-REGISTRY-PROPOSAL-DIGEST-V1\0".utf8) + signedProposal))
  acceptance["proposal_sha256"] = digest
  record["proposal_sha256"] = digest
  let accepted = try ceremonyEncode(acceptance, ceremonyAcceptanceFields)
  record["acceptance_sha256"] = ceremonyQuote(
    ceremonyHash(Data("YTA-REGISTRY-ACCEPTANCE-V1\0".utf8) + accepted))
  let candidate = SuppliedRegistryCeremony(
    request: original.request, recoveryEvidence: nil, unsignedProposal: suppliedUnsigned,
    signedProposal: signedProposal, acceptance: accepted,
    finalBody: try ceremonyEncode(
      record, ceremonyRecordFields.split(separator: " ").prefix(28).joined(separator: " ")),
    record: try ceremonyRecord(record, nil, key))
  // Do not use ceremonyRebuild: it would resynchronize the projection under test.
  ceremonyFailure([], candidate, .verification)
}

@Test func suppliedRegistryCeremonyFinalBodyProjectionEquality() throws {
  let corpus = try registryCorpus()
  let original = ceremonyInput(
    try #require(corpus.positives.first { $0.id == "enroll1" }).transcript)
  _ = try SuppliedRegistryCeremony.verify(prefixRecords: [], ceremony: original)
  let changedBody = try ceremonyReplace(
    original.finalBody, "\"revokes_all_prior\":false", "\"revokes_all_prior\":true")
  let candidate = SuppliedRegistryCeremony(
    request: original.request, recoveryEvidence: nil, unsignedProposal: original.unsignedProposal,
    signedProposal: original.signedProposal, acceptance: original.acceptance,
    finalBody: changedBody, record: original.record)
  // Preserve the original full record, signatures, and digest bindings.
  ceremonyFailure([], candidate, .verification)
}

private enum CeremonyBindingStage {
  case request, evidence, proposal, acceptance, body
}

private struct CeremonyBindingFault {
  let id: String
  let fixture: String
  let stage: CeremonyBindingStage
  let field: String
  let value: String
}

// Repair only computed dependencies, in wire order. Literal binding fields stay
// independent so repairing a digest or signature cannot erase the tested fault.
private func ceremonyBindingBuild(
  _ original: SuppliedRegistryCeremony, fault: CeremonyBindingFault? = nil
) throws -> SuppliedRegistryCeremony {
  var q = try ceremonyObject(original.request)
  let e = try original.recoveryEvidence.map(ceremonyObject)
  var p = try ceremonyObject(original.signedProposal)
  var a = try ceremonyObject(original.acceptance)
  var r = try ceremonyObject(original.record)
  func mutate(_ object: inout [String: String], _ stage: CeremonyBindingStage) {
    if let fault, fault.stage == stage { object[fault.field] = fault.value }
  }
  func key(_ generation: String?) throws -> P256.Signing.PrivateKey {
    let generation = try #require(generation)
    let revision = try #require(Int(generation.replacingOccurrences(of: "\"", with: "").dropFirst(5)))
    return try ceremonyKey(revision)
  }
  let old = try r["old_signature"] == "null" ? nil : key(r["target_generation"])
  let fresh = try r["new_signature"] == "null" ? nil : key(r["new_generation"])
  let signer = try #require(p["proposal_signer_role"] == ceremonyQuote("old") ? old : fresh)
  mutate(&q, .request)
  let request = try ceremonyEncode(q, ceremonyRequestFields)
  let requestHash = ceremonyQuote(ceremonyHash(Data("YTA-REGISTRY-REQUEST-V1\0".utf8) + request))
  p["request_sha256"] = requestHash
  a["request_sha256"] = requestHash
  r["request_sha256"] = requestHash
  var evidence: Data?
  if var fields = e {
    fields["request_sha256"] = requestHash
    mutate(&fields, .evidence)
    evidence = try ceremonyEncode(fields, ceremonyEvidenceFields)
  }
  let evidenceHash = evidence.map {
    ceremonyQuote(ceremonyHash(Data("YTA-REGISTRY-RECOVERY-EVIDENCE-V1\0".utf8) + $0))
  } ?? "null"
  p["recovery_evidence_sha256"] = evidenceHash
  a["recovery_evidence_sha256"] = evidenceHash
  r["recovery_evidence_sha256"] = evidenceHash
  mutate(&p, .proposal)
  let unsigned = try ceremonyEncode(p, ceremonyProposalFields)
  p["proposal_signature"] = try ceremonySign(
    Data("YTA-REGISTRY-PROPOSAL-V1\0".utf8) + unsigned, signer)
  let signed = try ceremonyEncode(p, ceremonyProposalFields + " proposal_signature")
  let proposalHash = ceremonyQuote(
    ceremonyHash(Data("YTA-REGISTRY-PROPOSAL-DIGEST-V1\0".utf8) + signed))
  a["proposal_sha256"] = proposalHash
  r["proposal_sha256"] = proposalHash
  mutate(&a, .acceptance)
  let acceptance = try ceremonyEncode(a, ceremonyAcceptanceFields)
  r["acceptance_sha256"] = ceremonyQuote(
    ceremonyHash(Data("YTA-REGISTRY-ACCEPTANCE-V1\0".utf8) + acceptance))
  mutate(&r, .body)
  let bodyFields = ceremonyRecordFields.split(separator: " ").prefix(28).joined(separator: " ")
  return SuppliedRegistryCeremony(
    request: request, recoveryEvidence: evidence, unsignedProposal: unsigned, signedProposal: signed,
    acceptance: acceptance, finalBody: try ceremonyEncode(r, bodyFields),
    record: try ceremonyRecord(r, old, fresh))
}

private func ceremonyBindingSignatures(_ input: SuppliedRegistryCeremony) throws {
  let p = try ceremonyObject(input.signedProposal)
  let r = try ceremonyObject(input.record)
  func text(_ value: String?) throws -> String {
    try #require(value).replacingOccurrences(of: "\"", with: "")
  }
  let role = p["proposal_signer_role"] == ceremonyQuote("old") ? "target" : "new"
  try ceremonySignatureControl(
    text(p[role + "_spki"]), text(p["proposal_signature"]), "YTA-REGISTRY-PROPOSAL-V1\0",
    #require(String(data: input.unsignedProposal, encoding: .utf8)))
  for (field, tuple, domain) in [
    ("old_signature", "target", "YTA-REGISTRY-RECORD-OLD-V1\0"),
    ("new_signature", "new", "YTA-REGISTRY-RECORD-NEW-V1\0"),
  ] where r[field] != "null" {
    try ceremonySignatureControl(
      text(r[tuple + "_spki"]), text(r[field]), domain,
      #require(String(data: input.finalBody, encoding: .utf8)))
  }
}

private func ceremonyBindingBytes(
  _ input: SuppliedRegistryCeremony, _ stage: CeremonyBindingStage
) throws -> Data {
  switch stage {
  case .request: return input.request
  case .evidence: return try #require(input.recoveryEvidence)
  case .proposal: return input.unsignedProposal
  case .acceptance: return input.acceptance
  case .body: return input.finalBody
  }
}

private func ceremonyBindingFaults() -> [CeremonyBindingFault] {
  let digest = ceremonyQuote(String(repeating: "b", count: 64))
  let generation = ceremonyQuote("YTAG-00000000000000000001")
  let tag = ceremonyQuote("io.github.abigotado.youtrack-agent.approval.signing.v1/" + String(repeating: "0", count: 31) + "1")
  var cases: [CeremonyBindingFault] = []
  func add(_ fixture: String, _ stage: CeremonyBindingStage, _ rows: [(String, String, String)]) {
    for (id, field, value) in rows {
      cases.append(CeremonyBindingFault(id: id, fixture: fixture, stage: stage, field: field, value: value))
    }
  }
  add("recover-active3", .evidence, [
    ("recovery-request-digest", "request_sha256", digest),
    ("recovery-challenge-digest", "challenge_sha256", digest),
    ("recovery-revision", "registry_revision", "1"),
    ("recovery-predecessor", "previous_record_sha256", digest),
    ("recovery-descriptor", "artifact_descriptor_sha256", digest),
    ("recovery-active-target-generation", "target_generation", generation),
    ("recovery-active-target-tag", "target_key_tag", tag),
    ("recovery-active-eligibility", "eligibility", ceremonyQuote("registry_disabled")),
    ("recovery-active-lookup", "key_lookup_result", ceremonyQuote("not_attempted:registry_disabled")),
    ("recovery-active-continuity", "continuity_probe_result", ceremonyQuote("not_attempted:no_active_generation")),
    ("recovery-probe-before-request", "probed_at", ceremonyQuote("2026-09-01T11:59:59Z")),
    ("recovery-probe-after-proposal", "probed_at", ceremonyQuote("2026-09-01T12:00:02Z")),
  ])
  add("recover-disabled4", .evidence, [
    ("recovery-disabled-target-generation", "target_generation", generation),
    ("recovery-disabled-target-tag", "target_key_tag", tag),
    ("recovery-disabled-eligibility", "eligibility", ceremonyQuote("active_key_item_not_found")),
    ("recovery-disabled-lookup", "key_lookup_result", ceremonyQuote("errSecItemNotFound:-25300")),
    ("recovery-disabled-continuity", "continuity_probe_result", ceremonyQuote("not_attempted:no_key")),
  ])
  add("rotate2", .acceptance, [
    ("acceptance-kind", "transition_kind", ceremonyQuote("enroll")),
    ("acceptance-request-digest", "request_sha256", digest),
    ("acceptance-challenge", "challenge_sha256", digest),
    ("acceptance-revision", "registry_revision", "1"),
    ("acceptance-predecessor", "previous_record_sha256", digest),
    ("acceptance-target-generation", "target_generation", "null"),
    ("acceptance-new-generation", "new_generation", "null"),
    ("acceptance-proposal-digest", "proposal_sha256", digest),
    ("acceptance-expiry", "expires_at", ceremonyQuote("2026-09-01T12:04:59Z")),
  ])
  add("rotate2", .proposal, [
    ("proposal-kind", "transition_kind", ceremonyQuote("enroll")),
    ("proposal-challenge", "challenge_sha256", digest),
    ("proposal-expiry", "expires_at", ceremonyQuote("2026-09-01T12:04:59Z")),
  ])
  // Revoke has no fresh tuple whose generation would impose a grammar failure.
  add("revoke3", .proposal, [("proposal-revision", "registry_revision", "1")])
  add("rotate2", .body, [
    ("body-challenge", "challenge_sha256", digest),
    ("body-proposal-digest", "proposal_sha256", digest),
    ("body-requested-at", "requested_at", ceremonyQuote("2026-09-01T12:00:01Z")),
    ("body-accepted-at", "accepted_at", ceremonyQuote("2026-09-01T12:00:03Z")),
  ])
  for (id, stage) in [
    ("proposal-recovery-digest", CeremonyBindingStage.proposal),
    ("acceptance-recovery-digest", .acceptance), ("body-recovery-digest", .body),
  ] {
    add("recover-active3", stage, [(id, "recovery_evidence_sha256", digest)])
  }
  add("rotate2", .request, [
    ("request-revision", "expected_registry_revision", "0"),
    ("request-predecessor", "previous_record_sha256", digest),
  ])
  return cases
}

@Test func suppliedRegistryCeremonyBindingRebuildControls() throws {
  let corpus = try registryCorpus()
  for id in ["enroll1", "rotate2", "revoke3", "recover-active3", "recover-disabled4"] {
    let positive = try #require(corpus.positives.first { $0.id == id })
    let prefix = try ceremonyPrefix(positive.prefix, corpus)
    let original = ceremonyInput(positive.transcript)
    let expected = try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: original)
    let rebuilt = try ceremonyBindingBuild(original)
    try ceremonyBindingSignatures(rebuilt)
    let result = try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: rebuilt)
    #expect(result.suppliedRevision == expected.suppliedRevision, "\(id)")
    #expect(result.keys == expected.keys, "\(id)")
    #expect(result.suppliedTipDescriptorSHA256 == expected.suppliedTipDescriptorSHA256, "\(id)")
    #expect(result.suppliedTipSHA256 == ceremonyHash(rebuilt.record), "\(id)")
  }
  let positive = try #require(corpus.positives.first { $0.id == "recover-active3" })
  let prefix = try ceremonyPrefix(positive.prefix, corpus)
  let original = ceremonyInput(positive.transcript)
  let expected = try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: original)
  for (id, timestamp) in [
    ("recovery-probe-at-request", "2026-09-01T12:00:00Z"),
    ("recovery-probe-at-proposal", "2026-09-01T12:00:01Z"),
  ] {
    let fault = CeremonyBindingFault(
      id: id, fixture: positive.id, stage: .evidence, field: "probed_at", value: ceremonyQuote(timestamp))
    let rebuilt = try ceremonyBindingBuild(original, fault: fault)
    #expect(try ceremonyObject(#require(rebuilt.recoveryEvidence))[fault.field] == fault.value, "\(id)")
    try ceremonyBindingSignatures(rebuilt)
    let result = try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: rebuilt)
    #expect(result.suppliedRevision == expected.suppliedRevision, "\(id)")
    #expect(result.keys == expected.keys, "\(id)")
    #expect(result.suppliedTipDescriptorSHA256 == expected.suppliedTipDescriptorSHA256, "\(id)")
    #expect(result.suppliedTipSHA256 == ceremonyHash(rebuilt.record), "\(id)")
  }
}

@Test func suppliedRegistryCeremonySignedBindingMismatches() throws {
  let corpus = try registryCorpus()
  let faults = ceremonyBindingFaults()
  #expect(faults.count == 39)
  #expect(Set(faults.map(\.id)).count == faults.count)
  for fault in faults {
    let positive = try #require(corpus.positives.first { $0.id == fault.fixture })
    let prefix = try ceremonyPrefix(positive.prefix, corpus)
    let original = ceremonyInput(positive.transcript)
    #expect(try ceremonyObject(ceremonyBindingBytes(original, fault.stage))[fault.field] != fault.value, "\(fault.id)")
    let candidate = try ceremonyBindingBuild(original, fault: fault)
    #expect(try ceremonyObject(ceremonyBindingBytes(candidate, fault.stage))[fault.field] == fault.value, "\(fault.id)")
    if fault.stage == .proposal {
      #expect(try ceremonyObject(candidate.signedProposal)[fault.field] == fault.value, "\(fault.id)")
    }
    if fault.stage == .body {
      #expect(try ceremonyObject(candidate.record)[fault.field] == fault.value, "\(fault.id)")
    }
    try ceremonyBindingSignatures(candidate)
    if fault.stage == .request {
      let replay = try SuppliedRegistryHistory.verify(suppliedRecords: prefix + [candidate.record])
      let expected = try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: original)
      #expect(replay.keys == expected.keys, "\(fault.id)")
      #expect(replay.suppliedRevision == expected.suppliedRevision, "\(fault.id)")
      #expect(replay.suppliedTipSHA256 == ceremonyHash(candidate.record), "\(fault.id)")
    }
    #expect(throws: SuppliedRegistryCeremonyError.verification, "\(fault.id)") {
      try SuppliedRegistryCeremony.verify(prefixRecords: prefix, ceremony: candidate)
    }
  }
}
