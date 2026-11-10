import struct Foundation.Data

/// Static phase failures only; supplied text and crypto/parser diagnostics are redacted.
public enum SuppliedRegistryCeremonyError: Error, Equatable, Sendable {
    case bounds
    case encoding
    case grammar
    case verification
}

/// Exact supplied historical transcript bytes, not a live authenticated ceremony.
/// Nil recovery evidence means absent; a non-nil empty object is invalid.
public struct SuppliedRegistryCeremony: Equatable, Sendable {
    public let request: Data
    public let recoveryEvidence: Data?
    public let unsignedProposal: Data
    public let signedProposal: Data
    public let acceptance: Data
    public let finalBody: Data
    public let record: Data

    public init(
        request: Data, recoveryEvidence: Data?, unsignedProposal: Data,
        signedProposal: Data, acceptance: Data, finalBody: Data, record: Data
    ) {
        self.request = request
        self.recoveryEvidence = recoveryEvidence
        self.unsignedProposal = unsignedProposal
        self.signedProposal = signedProposal
        self.acceptance = acceptance
        self.finalBody = finalBody
        self.record = record
    }

    /// Verifies consistency with a supplied genesis prefix, never protected-tip
    /// completeness, freshness, native recovery eligibility, or authorization.
    /// Success must not seed receipt binding, signing, confirmation, or commit.
    public static func verify(prefixRecords: [Data], ceremony: Self) throws -> SuppliedRegistryHistory {
        guard prefixRecords.count < SuppliedRegistryBounds.maximumRecords
        else { throw SuppliedRegistryCeremonyError.bounds }
        for bytes in prefixRecords {
            guard !bytes.isEmpty, bytes.count <= SuppliedRegistryBounds.maximumRecordBytes
            else { throw SuppliedRegistryCeremonyError.bounds }
        }
        let inputs: [(Data, [String], Int, [String])] = [
            (ceremony.request, CeremonyFields.request, 2_048, []),
            (ceremony.unsignedProposal, Array(CeremonyFields.proposal.dropLast()), 4_096, []),
            (ceremony.signedProposal, CeremonyFields.proposal, 4_096, ["proposal_signature"]),
            (ceremony.acceptance, CeremonyFields.acceptance, 2_048, []),
            (ceremony.finalBody, Array(SuppliedRegistryCanonicalObject.fieldNames.dropLast(2)), 4_096, []),
            (ceremony.record, SuppliedRegistryCanonicalObject.fieldNames, SuppliedRegistryBounds.maximumRecordBytes, ["old_signature", "new_signature"]),
        ]
        for (bytes, _, cap, _) in inputs {
            guard !bytes.isEmpty, bytes.count <= cap else { throw SuppliedRegistryCeremonyError.bounds }
        }
        if let evidence = ceremony.recoveryEvidence {
            guard !evidence.isEmpty, evidence.count <= 2_048 else { throw SuppliedRegistryCeremonyError.bounds }
        }
        // Prefix plus candidate shares the frozen 256 * 4,352 aggregate bound.
        // All raw bounds above precede owned copies, parsing, hashes, and crypto.
        let ownedPrefix = prefixRecords.map { Data(Array($0)) }
        let ownedInputs = inputs.map { (Data(Array($0.0)), $0.1, $0.2, $0.3) }
        let ownedEvidence = ceremony.recoveryEvidence.map { Data(Array($0)) }
        var prefixObjects: [SuppliedRegistryCanonicalObject] = []
        var objects: [SuppliedRegistryCanonicalObject] = []
        var evidence: SuppliedRegistryCanonicalObject?
        do {
            for bytes in ownedPrefix { prefixObjects.append(try SuppliedRegistryCanonicalObject(bytes: bytes)) }
            for (bytes, fields, cap, suffix) in ownedInputs {
                objects.append(try SuppliedRegistryCanonicalObject(bytes: bytes, fieldNames: fields, maximumBytes: cap, signatureFields: suffix))
            }
            if let ownedEvidence {
                evidence = try SuppliedRegistryCanonicalObject(bytes: ownedEvidence, fieldNames: CeremonyFields.evidence, maximumBytes: 2_048, signatureFields: [])
            }
        } catch { throw SuppliedRegistryCeremonyError.encoding }

        var prefix: [SuppliedRegistryRecord] = []
        let candidate: SuppliedRegistryRecord
        do {
            for object in prefixObjects { prefix.append(try SuppliedRegistryRecord(object: object)) }
            for object in objects { try CeremonyFields.validatePrimitives(object) }
            if let evidence { try CeremonyFields.validatePrimitives(evidence) }
            candidate = try SuppliedRegistryRecord(object: objects[5])
        } catch { throw SuppliedRegistryCeremonyError.grammar }

        do {
            return try SuppliedRegistryHistory.verifyParsedRecords(prefix + [candidate], validateBeforeFinalRecord: { history in
                try validateTranscript(objects: objects, evidence: evidence, prefix: history, candidate: candidate)
            })
        } catch { throw SuppliedRegistryCeremonyError.verification }
    }

    private static func validateTranscript(
        objects: [SuppliedRegistryCanonicalObject], evidence: SuppliedRegistryCanonicalObject?,
        prefix: SuppliedRegistryHistory, candidate: SuppliedRegistryRecord
    ) throws {
        let request = objects[0], unsigned = objects[1], proposal = objects[2]
        let acceptance = objects[3], body = objects[4], record = objects[5]
        let kind = try request.string("transition_kind")
        let requestDigest = domainHash("YTA-REGISTRY-REQUEST-V1", bytes: request.bytes)
        let proposalDigest = domainHash("YTA-REGISTRY-PROPOSAL-DIGEST-V1", bytes: proposal.bytes)
        let acceptanceDigest = domainHash("YTA-REGISTRY-ACCEPTANCE-V1", bytes: acceptance.bytes)
        let evidenceDigest = evidence.map { domainHash("YTA-REGISTRY-RECOVERY-EVIDENCE-V1", bytes: $0.bytes) }
        let challengeDigest = ProtocolGrammar.sha256(try CeremonyFields.base64URL(try request.string("challenge"), byteCount: ApprovalIPCChallenge.byteCount))
        guard proposal.body == unsigned.bytes, record.body == body.bytes,
              request.fields["expected_registry_revision"]?.uint64 == UInt64(prefix.suppliedRevision),
              try request.string("previous_record_sha256") == prefix.suppliedTipSHA256,
              (evidence != nil) == (kind == "recover")
        else { throw SuppliedRegistryCeremonyError.verification }

        let target = try SuppliedRegistryTuple.decodeTuple(object: proposal, prefix: "target")
        let new = try SuppliedRegistryTuple.decodeTuple(object: proposal, prefix: "new")
        guard target == candidate.target, new == candidate.new,
              try request.optionalString("target_generation") == target?.generation,
              try request.optionalString("new_generation") == new?.generation,
              proposal.fields["registry_revision"]?.uint64 == UInt64(prefix.suppliedRevision + 1),
              case .boolean(true)? = acceptance.fields["accepted"]
        else { throw SuppliedRegistryCeremonyError.verification }
        for object in [proposal, acceptance, body] {
            guard try object.string("transition_kind") == kind,
                  try object.string("request_sha256") == requestDigest,
                  try object.string("challenge_sha256") == challengeDigest,
                  try object.string("artifact_descriptor_sha256") == request.string("artifact_descriptor_sha256"),
                  try object.string("previous_record_sha256") == request.string("previous_record_sha256"),
                  try object.optionalString("recovery_evidence_sha256") == evidenceDigest,
                  object.fields["registry_revision"]?.uint64 == proposal.fields["registry_revision"]?.uint64,
                  try object.optionalString("target_generation") == request.optionalString("target_generation"),
                  try object.optionalString("new_generation") == request.optionalString("new_generation")
            else { throw SuppliedRegistryCeremonyError.verification }
        }
        guard try acceptance.string("proposal_sha256") == proposalDigest,
              try body.string("proposal_sha256") == proposalDigest,
              try body.string("acceptance_sha256") == acceptanceDigest,
              try body.string("requested_at") == request.string("requested_at"),
              try body.string("accepted_at") == acceptance.string("accepted_at")
        else { throw SuppliedRegistryCeremonyError.verification }

        let role = kind == "revoke" ? "old" : "new"
        guard try proposal.string("proposal_signer_role") == role,
              let signer = role == "old" ? target : new
        else { throw SuppliedRegistryCeremonyError.verification }
        try signer.verify(signature: P256Signature(derBase64URL: proposal.string("proposal_signature")), body: unsigned.bytes, domain: "YTA-REGISTRY-PROPOSAL-V1")

        let requested = try CeremonyFields.time(request, name: "requested_at")
        let expiry = try CeremonyFields.time(request, name: "expires_at")
        let proposed = try CeremonyFields.time(proposal, name: "proposed_at")
        let accepted = try CeremonyFields.time(acceptance, name: "accepted_at")
        let committed = try CeremonyFields.time(body, name: "committed_at")
        guard expiry > requested, expiry - requested <= 300,
              proposed >= requested, accepted >= proposed, committed >= accepted,
              proposed < expiry, accepted < expiry, committed < expiry,
              try proposal.string("expires_at") == request.string("expires_at"),
              try acceptance.string("expires_at") == request.string("expires_at")
        else { throw SuppliedRegistryCeremonyError.verification }

        if let evidence {
            guard try request.optionalString("recovery_mode") == "missing_key_item_or_disabled_registry",
                  try evidence.string("request_sha256") == requestDigest,
                  try evidence.string("challenge_sha256") == challengeDigest,
                  try evidence.string("previous_record_sha256") == request.string("previous_record_sha256"),
                  try evidence.string("artifact_descriptor_sha256") == request.string("artifact_descriptor_sha256"),
                  evidence.fields["registry_revision"]?.uint64 == request.fields["expected_registry_revision"]?.uint64
            else { throw SuppliedRegistryCeremonyError.verification }
            let probed = try CeremonyFields.time(evidence, name: "probed_at")
            guard probed >= requested, probed <= proposed, probed < expiry
            else { throw SuppliedRegistryCeremonyError.verification }
            // Check only signed declarations against the supplied active tuple;
            // no supplied lookup string establishes native key absence.
            if let active = prefix.keys.first(where: { $0.status == "active" }) {
                guard try evidence.optionalString("target_generation") == active.generation,
                      try evidence.optionalString("target_key_tag") == active.keyTag,
                      try evidence.string("eligibility") == "active_key_item_not_found",
                      try evidence.string("key_lookup_result") == "errSecItemNotFound:-25300",
                      try evidence.string("continuity_probe_result") == "not_attempted:no_key"
                else { throw SuppliedRegistryCeremonyError.verification }
            } else {
                guard try evidence.optionalString("target_generation") == nil,
                      try evidence.optionalString("target_key_tag") == nil,
                      try evidence.string("eligibility") == "registry_disabled",
                      try evidence.string("key_lookup_result") == "not_attempted:registry_disabled",
                      try evidence.string("continuity_probe_result") == "not_attempted:no_active_generation"
                else { throw SuppliedRegistryCeremonyError.verification }
            }
        } else {
            guard try request.optionalString("recovery_mode") == nil
            else { throw SuppliedRegistryCeremonyError.verification }
        }
    }

    private static func domainHash(_ domain: String, bytes: Data) -> String {
        var input = Data(domain.utf8)
        input.append(0)
        input.append(bytes)
        return ProtocolGrammar.sha256(input)
    }
}

private enum CeremonyFields {
    static let request = [
        "schema_version", "message_type", "transition_kind", "recovery_mode", "challenge",
        "expected_registry_revision", "previous_record_sha256", "artifact_descriptor_sha256",
        "target_generation", "new_generation", "requested_at", "expires_at",
    ]
    static let evidence = [
        "schema_version", "message_type", "request_sha256", "challenge_sha256", "registry_revision",
        "previous_record_sha256", "artifact_descriptor_sha256", "target_generation", "target_key_tag",
        "eligibility", "key_lookup_result", "continuity_probe_result", "probed_at",
    ]
    static let proposal = [
        "schema_version", "message_type", "transition_kind", "request_sha256", "challenge_sha256",
        "registry_revision", "previous_record_sha256", "artifact_descriptor_sha256", "recovery_evidence_sha256",
        "target_generation", "target_key_id", "target_key_tag", "target_spki", "target_fingerprint_sha256",
        "new_generation", "new_key_id", "new_key_tag", "new_spki", "new_fingerprint_sha256",
        "proposed_at", "expires_at", "proposal_signer_role", "proposal_signature",
    ]
    static let acceptance = [
        "schema_version", "message_type", "transition_kind", "request_sha256", "proposal_sha256", "challenge_sha256",
        "registry_revision", "previous_record_sha256", "artifact_descriptor_sha256", "recovery_evidence_sha256",
        "target_generation", "new_generation", "accepted_at", "expires_at", "accepted",
    ]

    static func validatePrimitives(_ object: SuppliedRegistryCanonicalObject) throws {
        guard object.fields["schema_version"]?.uint64 == 1 else { throw SuppliedRegistryCeremonyError.grammar }
        let nullable = [
            "recovery_mode", "recovery_evidence_sha256", "target_generation", "target_key_id", "target_key_tag",
            "target_spki", "target_fingerprint_sha256", "target_previous_status", "target_new_status",
            "new_generation", "new_key_id", "new_key_tag", "new_spki", "new_fingerprint_sha256",
            "new_status", "old_signature", "new_signature",
        ]
        let isEvidence = object.fields["message_type"]?.string == "registry_recovery_evidence"
        for (name, node) in object.fields {
            if case .null = node {
                guard nullable.contains(name) else { throw SuppliedRegistryCeremonyError.grammar }
                continue
            }
            if name == "schema_version" { continue }
            if name == "registry_revision" || name == "expected_registry_revision" {
                let minimum = isEvidence || name == "expected_registry_revision" ? UInt64(0) : UInt64(1)
                guard let revision = node.uint64, (minimum...UInt64(SuppliedRegistryBounds.maximumRecords)).contains(revision)
                else { throw SuppliedRegistryCeremonyError.grammar }
                continue
            }
            if name == "accepted" || name == "revokes_all_prior" {
                guard case .boolean = node else { throw SuppliedRegistryCeremonyError.grammar }
                continue
            }
            guard let value = node.string else { throw SuppliedRegistryCeremonyError.grammar }
            if name.hasSuffix("sha256"), !ProtocolGrammar.isDigest(value) { throw SuppliedRegistryCeremonyError.grammar }
            if name.hasSuffix("generation"), !ProtocolGrammar.isKeyGeneration(value) { throw SuppliedRegistryCeremonyError.grammar }
            if name.hasSuffix("_at") { _ = try time(object, name: name) }
            if name.hasSuffix("signature") { _ = try P256Signature(derBase64URL: value) }
            let allowed: [String]?
            switch name {
            case "transition_kind": allowed = ["enroll", "rotate", "revoke", "recover"]
            case "recovery_mode": allowed = ["missing_key_item_or_disabled_registry"]
            case "record_type": allowed = ["approval_registry_transition"]
            case "proposal_signer_role": allowed = ["old", "new"]
            case "target_previous_status", "target_new_status", "new_status": allowed = ["active", "retained", "revoked"]
            case "eligibility": allowed = ["active_key_item_not_found", "registry_disabled"]
            case "key_lookup_result": allowed = ["errSecItemNotFound:-25300", "not_attempted:registry_disabled"]
            case "continuity_probe_result": allowed = ["not_attempted:no_key", "not_attempted:no_active_generation"]
            default: allowed = nil
            }
            if let allowed, !allowed.contains(value) { throw SuppliedRegistryCeremonyError.grammar }
        }
        if let message = object.fields["message_type"] {
            let expected: String
            switch object.fields.keys.count {
            case request.count: expected = "registry_request"
            case evidence.count: expected = "registry_recovery_evidence"
            case acceptance.count: expected = "registry_acceptance"
            default: expected = "registry_proposal"
            }
            guard message.string == expected else { throw SuppliedRegistryCeremonyError.grammar }
        }
        if object.fields["challenge"] != nil { _ = try base64URL(object.string("challenge"), byteCount: ApprovalIPCChallenge.byteCount) }
        if object.fields["target_spki"] != nil { _ = try SuppliedRegistryTuple.decodeTuple(object: object, prefix: "target") }
        if object.fields["new_spki"] != nil {
            if let new = try SuppliedRegistryTuple.decodeTuple(object: object, prefix: "new") {
                guard ProtocolGrammar.keyGenerationRevision(new.generation).map(UInt64.init) == object.fields["registry_revision"]?.uint64
                else { throw SuppliedRegistryCeremonyError.grammar }
            }
        }
        if isEvidence, let tag = try object.optionalString("target_key_tag") {
            let prefix = "io.github.abigotado.youtrack-agent.approval.signing.v1/"
            let suffix = tag.dropFirst(prefix.count)
            guard tag.hasPrefix(prefix), suffix.utf8.count == 32,
                  suffix.utf8.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) })
            else { throw SuppliedRegistryCeremonyError.grammar }
        }
    }

    static func time(_ object: SuppliedRegistryCanonicalObject, name: String) throws -> Int64 {
        guard let result = SuppliedRegistryCalendar.seconds(try object.string(name))
        else { throw SuppliedRegistryCeremonyError.grammar }
        return result
    }

    static func base64URL(_ value: String, byteCount: Int) throws -> Data {
        guard value.utf8.count == (byteCount * 8 + 5) / 6,
              value.utf8.allSatisfy({ ProtocolGrammar.isASCIIAlphanumeric($0) || $0 == 0x2D || $0 == 0x5F })
        else { throw SuppliedRegistryCeremonyError.grammar }
        let padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") +
            String(repeating: "=", count: (4 - value.utf8.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded), decoded.count == byteCount,
              decoded.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == value
        else { throw SuppliedRegistryCeremonyError.grammar }
        return decoded
    }
}
