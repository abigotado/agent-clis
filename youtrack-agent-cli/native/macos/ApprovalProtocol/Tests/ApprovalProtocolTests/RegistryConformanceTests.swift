import Foundation
import Testing
@testable import ApprovalProtocol

@Test func sharedRegistryCeremonyCorpus() throws {
    let corpus = try registryCorpus()
    let ids = ["enroll1", "rotate2", "revoke3", "recover-disabled4", "recover-active3"]
    try #require(corpus.positives.map(\.id) == ids)
    let expectedPrefixes = [[], ["enroll1"], ["enroll1", "rotate2"], ["enroll1", "rotate2", "revoke3"], ["enroll1", "rotate2"]]
    let expectedStatuses = [["active"], ["retained", "active"], ["retained", "revoked"], ["revoked", "revoked", "active"], ["revoked", "revoked", "active"]]
    let expectedGenerations = [[1], [1, 2], [1, 2], [1, 2, 4], [1, 2, 3]]
    for (index, vector) in corpus.positives.enumerated() {
        #expect(vector.prefix == expectedPrefixes[index])
        var ledger = try registryPrefix(vector.prefix, corpus: corpus)
        try ledger.validate(vector.transcript)
        let expected = zip(expectedGenerations[index], expectedStatuses[index]).map { RegistryCorpus.State(generation: String(format: "YTAG-%020d", $0.0), status: $0.1) }
        let derived = ledger.entries.map { RegistryCorpus.State(generation: $0.generation, status: ledger.statuses[$0.generation]!) }
        #expect(derived == expected)
        #expect(vector.expected_state == expected)
        // Exercise record-only replay separately: full transcripts must not mask
        // weaker stored-record validation when recovery receives a raw prefix.
        var recordOnly = RegistryLedger()
        for id in vector.prefix + [vector.id] {
            let event = try #require(corpus.positives.first { $0.id == id })
            try recordOnly.append(event.record)
        }
        let recordState = recordOnly.entries.map { RegistryCorpus.State(generation: $0.generation, status: recordOnly.statuses[$0.generation]!) }
        #expect(recordState == expected)
        #expect(recordOnly.revision == vector.prefix.count + 1)
        #expect(recordOnly.previous == registryHash(vector.record))
        var inputs: [String: String] = [
            "request_digest": "YTA-REGISTRY-REQUEST-V1\0" + vector.request,
            "proposal_signature": "YTA-REGISTRY-PROPOSAL-V1\0" + vector.unsigned_proposal,
            "proposal_digest": "YTA-REGISTRY-PROPOSAL-DIGEST-V1\0" + vector.proposal,
            "acceptance_digest": "YTA-REGISTRY-ACCEPTANCE-V1\0" + vector.acceptance,
            "record_digest": "YTA-REGISTRY-COMMIT-V1\0" + vector.record,
            "predecessor_digest": vector.record,
        ]
        if let evidence = vector.recovery_evidence { inputs["recovery_evidence_digest"] = "YTA-REGISTRY-RECOVERY-EVIDENCE-V1\0" + evidence }
        let record = try RegistryObject(vector.record, keys: registryBodyKeys + ["old_signature", "new_signature"], cap: 4352)
        if record.string("old_signature") != nil { inputs["old_signature"] = "YTA-REGISTRY-RECORD-OLD-V1\0" + vector.final_body }
        if record.string("new_signature") != nil { inputs["new_signature"] = "YTA-REGISTRY-RECORD-NEW-V1\0" + vector.final_body }
        try #require(Set(vector.manifest.map(\.purpose)) == Set(inputs.keys))
        try #require(vector.manifest.count == inputs.count)
        for manifest in vector.manifest {
            let raw = try #require(inputs[manifest.purpose])
            #expect(manifest.input_hex == raw.utf8.map { String(format: "%02x", $0) }.joined())
            #expect(manifest.sha256 == registryHash(raw))
        }
    }
    // Independently parse the synthetic public roster, never any private material.
    try #require(corpus.keys.count == 4)
    try #require(Set(corpus.keys.map(\.generation)).count == corpus.keys.count)
    var roster: [RegistryTuple] = []
    for key in corpus.keys {
        let raw = "{\"schema_version\":1,\"new_generation\":\"\(key.generation)\",\"new_key_id\":\"\(key.key_id)\",\"new_key_tag\":\"\(key.key_tag)\",\"new_spki\":\"\(key.spki)\",\"new_fingerprint_sha256\":\"\(key.fingerprint_sha256)\"}"
        let object = try RegistryObject(raw, keys: ["schema_version", "new_generation", "new_key_id", "new_key_tag", "new_spki", "new_fingerprint_sha256"], cap: 2048)
        roster.append(try #require(try RegistryTuple.read(object, prefix: "new")))
    }
    for vector in corpus.positives {
        let object = try RegistryObject(vector.proposal, keys: registryProposalKeys, cap: 4096)
        for prefix in ["target", "new"] {
            if let tuple = try RegistryTuple.read(object, prefix: prefix) { #expect(roster.contains(tuple)) }
        }
    }
}

@Test func sharedRegistryNegativeCorpus() throws {
    let corpus = try registryCorpus()
    try #require(!corpus.negatives.isEmpty)
    try #require(Set(corpus.negatives.map(\.id)).count == corpus.negatives.count)
    var requiredIDs = Set<String>()
    for object in ["request", "recovery_evidence", "unsigned_proposal", "proposal", "acceptance", "final_body", "record"] {
        for change in ["missing", "duplicate", "unknown", "reordered", "escaped", "whitespace", "trailing", "nonobject"] { requiredIDs.insert("encoding-\(object)-\(change)") }
        for boundary in ["over", "at"] { requiredIDs.insert("size-\(object)-\(boundary)") }
    }
    requiredIDs.formUnion("digest-request-without-nul digest-request-splice digest-acceptance-splice digest-predecessor signature-proposal-domain signature-proposal-domain-without-nul signature-proposal-wrong-key signature-old-wrong-domain signature-new-wrong-domain signature-missing-old signature-missing-new grammar-high-s time-proposal-at-expiry time-acceptance-before-proposal time-commit-at-expiry time-request-window-over acceptance-false state-revoke-all-false state-wrong-target state-key-reuse state-revision-gap recovery-lookup-success recovery-continuity-success recovery-lookup-canceled recovery-lookup-auth-failed recovery-lookup-interaction recovery-lookup-unknown recovery-wrong-eligibility recovery-evidence-missing recovery-invalid-prefix-signature grammar-record-revision--1 grammar-record-revision-0 grammar-record-revision-257 grammar-request-negative-revision grammar-schema-negative grammar-generation-revision grammar-partial-tuple grammar-fingerprint grammar-challenge-padding grammar-time-fraction".split(separator: " ").map(String.init))
    requiredIDs.formUnion("grammar-signature-der grammar-signature-nonminimal-der grammar-spki-der grammar-spki-offcurve grammar-key-tag grammar-digest-uppercase grammar-spki-padding encoding-schema-fraction".split(separator: " ").map(String.init))
    requiredIDs.formUnion(["prefix-time-reversed", "prefix-recovery-digest-unexpected", "prefix-recovery-digest-missing"])
    try #require(requiredIDs == Set(corpus.negatives.map(\.id)))
    for vector in corpus.negatives {
        let expected = try #require(RegistryReason(rawValue: vector.reason_class))
        // Reviewed case families pin taxonomy independently of the generated label.
        if requiredIDs.contains(vector.id) {
            let pinned: RegistryReason
            switch vector.id {
            case "recovery-invalid-prefix-signature": pinned = .signature
            case "acceptance-false": pinned = .stateTransition
            case "prefix-time-reversed": pinned = .temporal
            case "prefix-recovery-digest-unexpected", "prefix-recovery-digest-missing": pinned = .recoveryEligibility
            default:
                if vector.id.hasPrefix("encoding-") || (vector.id.hasPrefix("size-") && vector.id.hasSuffix("-at")) { pinned = .canonicalEncoding }
                else if vector.id.hasPrefix("grammar-") || vector.id.hasPrefix("size-") { pinned = .boundsGrammar }
                else if vector.id.hasPrefix("digest-") { pinned = .digestDomain }
                else if vector.id.hasPrefix("signature-") { pinned = .signature }
                else if vector.id.hasPrefix("time-") { pinned = .temporal }
                else if vector.id.hasPrefix("recovery-") { pinned = .recoveryEligibility }
                else { pinned = .stateTransition }
            }
            #expect(expected == pinned)
        }
        let base = try #require(corpus.positives.first { $0.id == vector.base })
        let t = vector.transcript
        let baseRecords = try base.prefix.map { id in try #require(corpus.positives.first { $0.id == id }).record }
        let candidateRecords = try vector.prefix_records ?? vector.prefix.map { id in try #require(corpus.positives.first { $0.id == id }).record }
        #expect(t.request != base.request || t.recovery_evidence != base.recovery_evidence || t.unsigned_proposal != base.unsigned_proposal || t.proposal != base.proposal || t.acceptance != base.acceptance || t.final_body != base.final_body || t.record != base.record || candidateRecords != baseRecords)
        var verdict: RegistryReason?
        do {
            _ = try t.parsed()
            var ledger: RegistryLedger
            if let records = vector.prefix_records {
                ledger = RegistryLedger()
                guard records.count <= 256, records.reduce(0, { $0 + $1.utf8.count }) <= 1_114_112 else { throw RegistryReason.boundsGrammar }
                for record in records { try ledger.append(record) }
            } else { ledger = try registryPrefix(vector.prefix, corpus: corpus) }
            try ledger.validate(t)
        } catch let reason as RegistryReason { verdict = reason }
        catch { Issue.record("unclassified registry failure: \(vector.id)") }
        #expect(verdict == expected, "\(vector.id): expected \(expected.rawValue), got \(verdict?.rawValue ?? "accepted")")
    }
}

@Test func registryCompoundFaultPrecedence() throws {
    let corpus = try registryCorpus()
    let base = try #require(corpus.positives.first { $0.id == "recover-active3" })
    let t = base.transcript
    let request = try RegistryObject(t.request, keys: registryRequestKeys, cap: 2048)
    let previous = try #require(request.string("previous_record_sha256"))
    let badRequest = t.request.replacingOccurrences(of: previous, with: String(repeating: "0", count: 64))
    let missing = RegistryTranscript(request: badRequest, recovery_evidence: nil, unsigned_proposal: t.unsigned_proposal, proposal: t.proposal, acceptance: t.acceptance, final_body: t.final_body, record: t.record)
    var ledger = try registryPrefix(base.prefix, corpus: corpus)
    #expect(throws: RegistryReason.recoveryEligibility) { try ledger.validate(missing) }

    let badPrefix = try #require(corpus.negatives.first { $0.id == "recovery-invalid-prefix-signature" }).prefix_records
    let records = try #require(badPrefix)
    #expect(throws: RegistryReason.signature) {
        _ = try missing.parsed()
        var invalidLedger = RegistryLedger()
        for record in records { try invalidLedger.append(record) }
        try invalidLedger.validate(missing)
    }

    // This signed vector has present, structurally valid but ineligible evidence.
    // Substituting another valid DER signature must fail before eligibility.
    let ineligible = try #require(corpus.negatives.first { $0.id == "recovery-continuity-success" }).transcript
    let record = try RegistryObject(ineligible.record, keys: registryBodyKeys + ["old_signature", "new_signature"], cap: 4352)
    let other = try RegistryObject(t.record, keys: registryBodyKeys + ["old_signature", "new_signature"], cap: 4352)
    let originalSignature = try #require(record.string("new_signature"))
    let wrongSignature = try #require(other.string("new_signature"))
    try #require(originalSignature != wrongSignature)
    let badRecord = ineligible.record.replacingOccurrences(of: originalSignature, with: wrongSignature)
    let badSignature = RegistryTranscript(request: ineligible.request, recovery_evidence: ineligible.recovery_evidence, unsigned_proposal: ineligible.unsigned_proposal, proposal: ineligible.proposal, acceptance: ineligible.acceptance, final_body: ineligible.final_body, record: badRecord)
    #expect(throws: RegistryReason.signature) { try ledger.validate(badSignature) }
}

private func registryOSStatus(_ raw: String) throws -> Int32 {
    guard raw.utf8.count <= 11, raw.range(of: "^(0|[1-9][0-9]*|-[1-9][0-9]*)$", options: .regularExpression) != nil,
          let value = Int64(raw), let narrowed = Int32(exactly: value) else { throw RegistryReason.boundsGrammar }
    return narrowed
}

// Fixture consistency only: this local parser does not exercise a production
// Security.framework OSStatus projection, which remains outside this tranche.
@Test func sharedRegistryOSStatusFixtureConsistency() throws {
    let vectors = try registryCorpus().osstatus
    let positives = Set(["-2147483648", "-25300", "-1", "0", "1", "2147483647"])
    let negatives = Set(["-2147483649", "2147483648", "-0", "+1", "01", "-01", "1.0", "1e0", "\"-25300\"", "null"])
    #expect(Set(vectors.filter(\.accepted).map(\.raw)) == positives)
    #expect(negatives.isSubset(of: Set(vectors.filter { !$0.accepted }.map(\.raw))))
    for vector in vectors {
        if vector.accepted { #expect(try String(registryOSStatus(vector.raw)) == vector.raw) }
        else { #expect(throws: RegistryReason.boundsGrammar) { _ = try registryOSStatus(vector.raw) } }
    }
}
