import CryptoKit
import Foundation
@testable import ApprovalProtocol

// Test-only transcript oracle. It grants no native or runtime authority.
enum RegistryReason: String, Error {
    case canonicalEncoding = "canonical_encoding"
    case boundsGrammar = "bounds_grammar"
    case digestDomain = "digest_domain"
    case signature
    case temporal
    case recoveryEligibility = "recovery_eligibility"
    case stateTransition = "state_transition"
}

// Test-only registry timestamps use a four-digit proleptic Gregorian calendar,
// including year zero, without Foundation's historical calendar normalization.
func registryWholeSecondUTCSeconds(_ value: String) -> Int64? {
    guard value.utf8.count == 20 else { return nil }
    let bytes = Array(value.utf8)
    guard bytes[4] == 45, bytes[7] == 45, bytes[10] == 84,
          bytes[13] == 58, bytes[16] == 58, bytes[19] == 90 else { return nil }
    func number(_ start: Int, _ end: Int) -> Int64? {
        var value: Int64 = 0
        for byte in bytes[start..<end] {
            guard byte >= 48 && byte <= 57 else { return nil }
            value = value * 10 + Int64(byte - 48)
        }
        return value
    }
    guard let year = number(0, 4), let month = number(5, 7),
          let day = number(8, 10), let hour = number(11, 13),
          let minute = number(14, 16), let second = number(17, 19),
          (1...12).contains(month), hour <= 23, minute <= 59, second <= 59 else { return nil }
    let leap = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)
    let monthDays: [Int64] = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    guard (1...monthDays[Int(month) - 1]).contains(day) else { return nil }
    // Count from year zero with nonnegative operands, avoiding negative-era division.
    let daysBeforeYear = 365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400
    let daysBeforeMonth = monthDays.prefix(Int(month) - 1).reduce(0, +)
    let unixDays = daysBeforeYear + daysBeforeMonth + day - 1 - 719528
    return unixDays * 86400 + hour * 3600 + minute * 60 + second
}

struct RegistryObject {
    let fields: [(String, String)]
    var bytes: String { "{" + fields.map { "\"\($0.0)\":\($0.1)" }.joined(separator: ",") + "}" }
    subscript(_ key: String) -> String { fields.first { $0.0 == key }!.1 }
    func string(_ key: String) -> String? {
        let value = self[key]
        return value.first == "\"" && value.last == "\"" ? String(value.dropFirst().dropLast()) : nil
    }
    func integer(_ key: String) throws -> Int {
        let token = self[key]
        guard token.range(of: "^(0|[1-9][0-9]*)$", options: .regularExpression) != nil,
              let result = Int(token) else { throw RegistryReason.boundsGrammar }
        return result
    }
    func removingLast(_ count: Int) -> RegistryObject { RegistryObject(fields: Array(fields.dropLast(count))) }
    init(fields: [(String, String)]) { self.fields = fields }
    init(_ raw: String, keys: [String], cap: Int, checkGrammar: Bool = true) throws {
        guard raw.utf8.count <= cap else { throw RegistryReason.boundsGrammar }
        let bytes = Array(raw.utf8)
        var index = 0
        func consume(_ byte: UInt8) throws {
            guard index < bytes.count, bytes[index] == byte else { throw RegistryReason.canonicalEncoding }
            index += 1
        }
        func quoted() throws -> String {
            try consume(34)
            let start = index
            while index < bytes.count, bytes[index] != 34 {
                guard (32...126).contains(bytes[index]), bytes[index] != 92 else { throw RegistryReason.canonicalEncoding }
                index += 1
            }
            let text = String(decoding: bytes[start..<index], as: UTF8.self)
            try consume(34)
            return text
        }
        try consume(123)
        var result: [(String, String)] = []
        for (ordinal, key) in keys.enumerated() {
            if ordinal > 0 { try consume(44) }
            guard try quoted() == key else { throw RegistryReason.canonicalEncoding }
            try consume(58)
            let start = index
            if index < bytes.count, bytes[index] == 34 { _ = try quoted() }
            else {
                while index < bytes.count, bytes[index] != 44, bytes[index] != 125 { index += 1 }
                let token = String(decoding: bytes[start..<index], as: UTF8.self)
                guard ["null", "true", "false"].contains(token) || token.range(of: "^(0|[1-9][0-9]*|-[1-9][0-9]*)$", options: .regularExpression) != nil else {
                    throw RegistryReason.canonicalEncoding
                }
            }
            result.append((key, String(decoding: bytes[start..<index], as: UTF8.self)))
        }
        try consume(125)
        guard index == bytes.count else { throw RegistryReason.canonicalEncoding }
        fields = result
        guard self.bytes == raw else { throw RegistryReason.canonicalEncoding }
        if checkGrammar { try grammar() }
    }
    func grammar() throws {
        let keys = fields.map(\.0)
        guard try integer("schema_version") == 1 else { throw RegistryReason.boundsGrammar }
        for (key, token) in fields {
            if key == "schema_version" || key.hasSuffix("registry_revision") { _ = try integer(key); continue }
            if key == "accepted" || key == "revokes_all_prior" {
                guard token == "true" || token == "false" else { throw RegistryReason.boundsGrammar }
                continue
            }
            if token == "null" {
                guard key.hasPrefix("target_") || key.hasPrefix("new_") || ["old_signature", "recovery_mode", "recovery_evidence_sha256"].contains(key) else { throw RegistryReason.boundsGrammar }
            } else { guard string(key) != nil else { throw RegistryReason.boundsGrammar } }
        }
        for (key, token) in fields where token != "null" {
            if key.hasSuffix("sha256") {
                guard let value = string(key), Self.hex(value, count: 64) else { throw RegistryReason.boundsGrammar }
            }
            if key.hasSuffix("generation") {
                guard let value = string(key), value.hasPrefix("YTAG-"), value.utf8.count == 25,
                      value.dropFirst(5).allSatisfy({ $0 >= "0" && $0 <= "9" }),
                      let revision = Int(value.dropFirst(5)), (1...256).contains(revision) else { throw RegistryReason.boundsGrammar }
            }
            if key.hasSuffix("registry_revision") {
                let minimum = key == "expected_registry_revision" ? 0 : 1
                guard try (minimum...256).contains(integer(key)) else { throw RegistryReason.boundsGrammar }
            }
            if key.hasSuffix("_at") { _ = try time(key) }
            if key.hasSuffix("signature") {
                do { _ = try P256Signature(derBase64URL: string(key) ?? "") }
                catch { throw RegistryReason.boundsGrammar }
            }
        }
        if keys.contains("new_generation"), let generation = string("new_generation"), keys.contains("registry_revision") {
            guard generation == String(format: "YTAG-%020d", try integer("registry_revision")) else { throw RegistryReason.boundsGrammar }
        }
    }
    static func hex(_ text: String, count: Int) -> Bool {
        text.utf8.count == count && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    func time(_ key: String) throws -> Date {
        guard let text = string(key), let seconds = registryWholeSecondUTCSeconds(text) else { throw RegistryReason.boundsGrammar }
        // The supported whole-second range fits exactly in Double (well below 2^53).
        return Date(timeIntervalSince1970: Double(seconds))
    }
}

let registryRequestKeys = "schema_version message_type transition_kind recovery_mode challenge expected_registry_revision previous_record_sha256 artifact_descriptor_sha256 target_generation new_generation requested_at expires_at".split(separator: " ").map(String.init)
let registryEvidenceKeys = "schema_version message_type request_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 target_generation target_key_tag eligibility key_lookup_result continuity_probe_result probed_at".split(separator: " ").map(String.init)
let registryProposalKeys = "schema_version message_type transition_kind request_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 proposed_at expires_at proposal_signer_role proposal_signature".split(separator: " ").map(String.init)
let registryAcceptanceKeys = "schema_version message_type transition_kind request_sha256 proposal_sha256 challenge_sha256 registry_revision previous_record_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 target_generation new_generation accepted_at expires_at accepted".split(separator: " ").map(String.init)
let registryBodyKeys = "schema_version record_type transition_kind registry_revision previous_record_sha256 request_sha256 proposal_sha256 acceptance_sha256 challenge_sha256 artifact_descriptor_sha256 recovery_evidence_sha256 requested_at accepted_at committed_at target_generation target_key_id target_key_tag target_spki target_fingerprint_sha256 target_previous_status target_new_status new_generation new_key_id new_key_tag new_spki new_fingerprint_sha256 new_status revokes_all_prior".split(separator: " ").map(String.init)

func registryHash(_ raw: String, domain: String = "") -> String {
    SHA256.hash(data: Data((domain.isEmpty ? raw : domain + "\0" + raw).utf8)).map { String(format: "%02x", $0) }.joined()
}

func registryBase64(_ raw: String, count: Int) throws -> Data {
    guard raw.utf8.count == (count * 8 + 5) / 6, raw.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { throw RegistryReason.boundsGrammar }
    let padded = raw.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - raw.utf8.count % 4) % 4)
    guard let data = Data(base64Encoded: padded), data.count == count,
          data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == raw else { throw RegistryReason.boundsGrammar }
    return data
}

struct RegistryTuple: Equatable {
    let generation: String
    let id: String
    let tag: String
    let spki: String
    let fingerprint: String
    static func read(_ object: RegistryObject, prefix: String) throws -> RegistryTuple? {
        let keys = ["generation", "key_id", "key_tag", "spki", "fingerprint_sha256"].map { prefix + "_" + $0 }
        let values = keys.map { object.string($0) }
        if values.allSatisfy({ $0 == nil }) { return nil }
        guard values.allSatisfy({ $0 != nil }) else { throw RegistryReason.boundsGrammar }
        let tuple = RegistryTuple(generation: values[0]!, id: values[1]!, tag: values[2]!, spki: values[3]!, fingerprint: values[4]!)
        guard RegistryObject.hex(tuple.id, count: 32), tuple.tag == "io.github.abigotado.youtrack-agent.approval.signing.v1/" + tuple.id else { throw RegistryReason.boundsGrammar }
        let der = try registryBase64(tuple.spki, count: 91)
        do { _ = try P256PublicKeyCodec.x963(fromSPKIDER: der) } catch { throw RegistryReason.boundsGrammar }
        guard SHA256.hash(data: der).map({ String(format: "%02x", $0) }).joined() == tuple.fingerprint else { throw RegistryReason.boundsGrammar }
        return tuple
    }
    func verify(_ signature: String?, body: String, domain: String) throws {
        guard let signature else { throw RegistryReason.signature }
        do {
            let sig = try P256Signature(derBase64URL: signature)
            let key = try P256PublicKeyCodec.x963(fromSPKIDER: registryBase64(spki, count: 91))
            guard try P256PublicKeyCodec.verify(message: Data((domain + "\0" + body).utf8), derSignature: sig.der, x963: key) else { throw RegistryReason.signature }
        } catch { throw RegistryReason.signature }
    }
}

struct RegistryTranscript: Decodable {
    let request: String
    let recovery_evidence: String?
    let unsigned_proposal: String
    let proposal: String
    let acceptance: String
    let final_body: String
    let record: String
    func parsed() throws -> [String: RegistryObject] {
        var raw: [(String, String, [String], Int)] = [
            ("request", request, registryRequestKeys, 2048),
            ("unsigned", unsigned_proposal, Array(registryProposalKeys.dropLast()), 4096),
            ("proposal", proposal, registryProposalKeys, 4096),
            ("acceptance", acceptance, registryAcceptanceKeys, 2048),
            ("body", final_body, registryBodyKeys, 4096),
            ("record", record, registryBodyKeys + ["old_signature", "new_signature"], 4352),
        ]
        if let recovery_evidence { raw.append(("evidence", recovery_evidence, registryEvidenceKeys, 2048)) }
        guard raw.allSatisfy({ $0.1.utf8.count <= $0.3 }) else { throw RegistryReason.boundsGrammar }
        var result: [String: RegistryObject] = [:]
        for (name, bytes, keys, cap) in raw { result[name] = try RegistryObject(bytes, keys: keys, cap: cap, checkGrammar: false) }
        // Finish all canonical checks before any grammar or cryptographic work.
        for (name, _, keys, _) in raw {
            let object = result[name]!
            try object.grammar()
            if keys.contains("target_spki") { _ = try RegistryTuple.read(object, prefix: "target") }
            if keys.contains("new_spki") { _ = try RegistryTuple.read(object, prefix: "new") }
        }
        _ = try registryBase64(result["request"]!.string("challenge") ?? "", count: 32)
        return result
    }
}

struct RegistryLedger {
    var revision = 0
    var previous = String(repeating: "0", count: 64)
    var entries: [RegistryTuple] = []
    var statuses: [String: String] = [:]
    var active: RegistryTuple? { entries.first { statuses[$0.generation] == "active" } }

    // Replay is independent of corpus expected_state and never trusts a snapshot.
    mutating func append(_ raw: String) throws {
        let record = try RegistryObject(raw, keys: registryBodyKeys + ["old_signature", "new_signature"], cap: 4352)
        let body = record.removingLast(2)
        let target = try RegistryTuple.read(record, prefix: "target")
        let new = try RegistryTuple.read(record, prefix: "new")
        if let sig = record.string("old_signature") {
            guard let target else { throw RegistryReason.signature }
            try target.verify(sig, body: body.bytes, domain: "YTA-REGISTRY-RECORD-OLD-V1")
        }
        if let sig = record.string("new_signature") {
            guard let new else { throw RegistryReason.signature }
            try new.verify(sig, body: body.bytes, domain: "YTA-REGISTRY-RECORD-NEW-V1")
        }
        let requested = try record.time("requested_at")
        let accepted = try record.time("accepted_at")
        let committed = try record.time("committed_at")
        guard requested <= accepted, accepted <= committed else { throw RegistryReason.temporal }
        guard (record.string("recovery_evidence_sha256") != nil) == (record.string("transition_kind") == "recover") else { throw RegistryReason.recoveryEligibility }
        guard record.string("previous_record_sha256") == previous else { throw RegistryReason.digestDomain }
        guard record.string("record_type") == "approval_registry_transition",
              try record.integer("registry_revision") == revision + 1,
              revision < 256 else { throw RegistryReason.stateTransition }
        if let new {
            guard new.generation == String(format: "YTAG-%020d", revision + 1),
                  entries.allSatisfy({ $0.generation != new.generation && $0.id != new.id && $0.tag != new.tag && $0.spki != new.spki && $0.fingerprint != new.fingerprint }) else { throw RegistryReason.stateTransition }
        }
        let kind = record.string("transition_kind")
        let oldRequired = kind == "rotate" || kind == "revoke"
        let newRequired = kind != "revoke"
        guard (record.string("old_signature") != nil) == oldRequired,
              (record.string("new_signature") != nil) == newRequired else { throw RegistryReason.signature }
        guard target == active, record.string("target_previous_status") == (target == nil ? nil : "active"),
              record.string("new_status") == (new == nil ? nil : "active") else { throw RegistryReason.stateTransition }
        switch kind {
        case "enroll":
            guard revision == 0, target == nil, new != nil, record.string("target_new_status") == nil, record["revokes_all_prior"] == "false" else { throw RegistryReason.stateTransition }
        case "rotate", "revoke":
            let nextStatus = kind == "rotate" ? "retained" : "revoked"
            guard target != nil, (new != nil) == (kind == "rotate"), record.string("target_new_status") == nextStatus, record["revokes_all_prior"] == "false" else { throw RegistryReason.stateTransition }
            statuses[target!.generation] = nextStatus
        case "recover":
            guard revision > 0, new != nil, record["revokes_all_prior"] == "true", record.string("target_new_status") == (target == nil ? nil : "revoked") else { throw RegistryReason.stateTransition }
            for key in statuses.keys { statuses[key] = "revoked" }
        default: throw RegistryReason.boundsGrammar
        }
        if let new { entries.append(new); statuses[new.generation] = "active" }
        revision += 1
        previous = registryHash(raw)
    }

    mutating func validate(_ t: RegistryTranscript) throws {
        let objects = try t.parsed()
        let request = objects["request"]!, unsigned = objects["unsigned"]!, proposal = objects["proposal"]!
        let acceptance = objects["acceptance"]!, body = objects["body"]!, record = objects["record"]!, evidence = objects["evidence"]
        guard request.string("message_type") == "registry_request", proposal.string("message_type") == "registry_proposal",
              acceptance.string("message_type") == "registry_acceptance", body.string("record_type") == "approval_registry_transition",
              ["enroll", "rotate", "revoke", "recover"].contains(request.string("transition_kind") ?? ""),
              evidence == nil || evidence?.string("message_type") == "registry_recovery_evidence" else { throw RegistryReason.boundsGrammar }
        let target = try RegistryTuple.read(proposal, prefix: "target")
        let new = try RegistryTuple.read(proposal, prefix: "new")
        let bodyTarget = try RegistryTuple.read(body, prefix: "target")
        let bodyNew = try RegistryTuple.read(body, prefix: "new")
        // Prefix validation belongs to the caller and precedes this candidate.
        // Missing required evidence is structural; present evidence eligibility
        // remains after digest, signature, and temporal validation below.
        guard request.string("transition_kind") != "recover" || evidence != nil else { throw RegistryReason.recoveryEligibility }
        let challenge = try registryBase64(request.string("challenge") ?? "", count: 32)
        let challengeDigest = SHA256.hash(data: challenge).map { String(format: "%02x", $0) }.joined()
        let requestDigest = registryHash(t.request, domain: "YTA-REGISTRY-REQUEST-V1")
        let proposalDigest = registryHash(t.proposal, domain: "YTA-REGISTRY-PROPOSAL-DIGEST-V1")
        let acceptanceDigest = registryHash(t.acceptance, domain: "YTA-REGISTRY-ACCEPTANCE-V1")
        let recoveryDigest = t.recovery_evidence.map { registryHash($0, domain: "YTA-REGISTRY-RECOVERY-EVIDENCE-V1") }
        guard request.string("previous_record_sha256") == previous else { throw RegistryReason.digestDomain }
        guard unsigned.bytes == proposal.removingLast(1).bytes, body.bytes == record.removingLast(2).bytes else { throw RegistryReason.digestDomain }
        for object in [proposal, acceptance, body] {
            guard object.string("transition_kind") == request.string("transition_kind"),
                  object.string("request_sha256") == requestDigest,
                  object.string("challenge_sha256") == challengeDigest,
                  object.string("artifact_descriptor_sha256") == request.string("artifact_descriptor_sha256"),
                  object.string("previous_record_sha256") == request.string("previous_record_sha256"),
                  object.string("recovery_evidence_sha256") == recoveryDigest,
                  object["registry_revision"] == proposal["registry_revision"],
                  object.string("target_generation") == request.string("target_generation"),
                  object.string("new_generation") == request.string("new_generation") else { throw RegistryReason.digestDomain }
        }
        guard acceptance.string("proposal_sha256") == proposalDigest, body.string("proposal_sha256") == proposalDigest,
              body.string("acceptance_sha256") == acceptanceDigest, bodyTarget == target, bodyNew == new,
              body["requested_at"] == request["requested_at"], body["accepted_at"] == acceptance["accepted_at"] else { throw RegistryReason.digestDomain }
        if let evidence {
            guard evidence.string("request_sha256") == requestDigest, evidence.string("challenge_sha256") == challengeDigest,
                  evidence.string("previous_record_sha256") == request.string("previous_record_sha256"),
                  evidence.string("artifact_descriptor_sha256") == request.string("artifact_descriptor_sha256"),
                  evidence["registry_revision"] == request["expected_registry_revision"] else { throw RegistryReason.digestDomain }
        }
        let kind = request.string("transition_kind")!
        let role = kind == "revoke" ? "old" : "new"
        guard proposal.string("proposal_signer_role") == role, let signer = role == "old" ? target : new else { throw RegistryReason.signature }
        try signer.verify(proposal.string("proposal_signature"), body: unsigned.bytes, domain: "YTA-REGISTRY-PROPOSAL-V1")
        if kind == "rotate" || kind == "revoke" {
            guard let target else { throw RegistryReason.signature }
            try target.verify(record.string("old_signature"), body: body.bytes, domain: "YTA-REGISTRY-RECORD-OLD-V1")
        } else if record.string("old_signature") != nil { throw RegistryReason.signature }
        if kind != "revoke" {
            guard let new else { throw RegistryReason.signature }
            try new.verify(record.string("new_signature"), body: body.bytes, domain: "YTA-REGISTRY-RECORD-NEW-V1")
        } else if record.string("new_signature") != nil { throw RegistryReason.signature }
        let start = try request.time("requested_at"), expiry = try request.time("expires_at")
        let proposed = try proposal.time("proposed_at"), accepted = try acceptance.time("accepted_at"), committed = try body.time("committed_at")
        guard expiry > start, expiry.timeIntervalSince(start) <= 300,
              proposed >= start, proposed < expiry, accepted >= proposed, accepted < expiry,
              committed >= accepted, committed < expiry, proposal["expires_at"] == request["expires_at"],
              acceptance["expires_at"] == request["expires_at"] else { throw RegistryReason.temporal }
        if let evidence {
            let probed = try evidence.time("probed_at")
            guard probed >= start, probed <= proposed, probed < expiry else { throw RegistryReason.temporal }
        }
        if kind == "recover" {
            guard request.string("recovery_mode") == "missing_key_item_or_disabled_registry", let evidence else { throw RegistryReason.recoveryEligibility }
            if let active {
                guard evidence.string("target_generation") == active.generation, evidence.string("target_key_tag") == active.tag,
                      evidence.string("eligibility") == "active_key_item_not_found", evidence.string("key_lookup_result") == "errSecItemNotFound:-25300",
                      evidence.string("continuity_probe_result") == "not_attempted:no_key" else { throw RegistryReason.recoveryEligibility }
            } else {
                guard evidence.string("target_generation") == nil, evidence.string("target_key_tag") == nil,
                      evidence.string("eligibility") == "registry_disabled", evidence.string("key_lookup_result") == "not_attempted:registry_disabled",
                      evidence.string("continuity_probe_result") == "not_attempted:no_active_generation" else { throw RegistryReason.recoveryEligibility }
            }
        } else {
            guard evidence == nil, request.string("recovery_mode") == nil else { throw RegistryReason.recoveryEligibility }
        }
        guard try request.integer("expected_registry_revision") == revision,
              request.string("previous_record_sha256") == previous,
              try proposal.integer("registry_revision") == revision + 1,
              acceptance["accepted"] == "true" else { throw RegistryReason.stateTransition }
        try append(t.record)
    }
}
