import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

// Partial offline oracle: supplied retained candidates only, never owner or outcome proof.
private enum ClosedFailure: String, Error {
    case canonical = "canonical_encoding"
    case bounds = "bounds_grammar"
    case digest = "digest_domain"
    case binding = "closed_binding"
}

private enum ClosedFixtureError: Error { case unknownActive, invalidActive }
private enum ClosedScopeError: Error { case unsupportedBranch }

private struct ClosedCorpus: Decodable {
    struct Positive: Decodable {
        let id: String; let active_id: String; let raw_hex: String
        let signing_input_hex: String; let sha256: String
    }
    struct Negative: Decodable {
        let id: String; let base: String; let active_id: String
        let raw_hex: String; let sha256: String; let reason_class: String
    }
    let schema_version: Int; let scope: String; let sources: [IntentCorpus.Source]
    let positives: [Positive]; let negatives: [Negative]
}

private func closedDigest(_ bytes: Data) -> String {
    intentHex(Data(SHA256.hash(data: Data("YTA-APPLY-COORDINATOR-CLOSED-V1\0".utf8) + bytes)))
}

private func validateRetainedCandidateClosed(_ bytes: Data, digest: String, activeID: String, actives: ActiveCorpus, intents: IntentCorpus, core: RegistryCorpus) throws -> RegistryObject {
    guard let supplied = actives.positives.first(where: { $0.id == activeID }) else { throw ClosedFixtureError.unknownActive }
    let active: RegistryObject
    let candidate: String
    do {
        active = try validateActive(intentBytes(supplied.raw_hex), digest: supplied.sha256, intentID: supplied.intent_id, intents: intents, core: core)
        guard let intent = intents.positives.first(where: { $0.id == supplied.intent_id }),
              let coreID = intent.core_id, let transcript = core.positives.first(where: { $0.id == coreID }) else { throw ClosedFixtureError.invalidActive }
        // validateActive already validated this exact intent, signed core, and prefix.
        candidate = registryHash(transcript.record, domain: "YTA-REGISTRY-COMMIT-V1")
    } catch { throw ClosedFixtureError.invalidActive }
    guard bytes.count <= 4096 else { throw ClosedFailure.bounds }
    guard let raw = String(data: bytes, encoding: .utf8), Data(raw.utf8) == bytes else { throw ClosedFailure.canonical }
    let closed: RegistryObject
    do {
        closed = try RegistryObject(raw, keys: "schema_version record_type lease_id active_sha256 permit_sha256 receipt_sha256 operation_kind terminal_outcome journal_revision registry_record_sha256 closed_at close_mode".split(separator: " ").map(String.init), cap: 4096, checkGrammar: false)
        guard closed["schema_version"].range(of: "^(0|[1-9][0-9]*|-[1-9][0-9]*)$", options: .regularExpression) != nil else { throw ClosedFailure.canonical }
        for key in ["record_type", "lease_id", "active_sha256", "operation_kind", "terminal_outcome", "closed_at", "close_mode"] {
            guard closed.string(key) != nil else { throw ClosedFailure.canonical }
        }
        guard closed["registry_record_sha256"] == "null" || closed.string("registry_record_sha256") != nil else { throw ClosedFailure.canonical }
        guard try closed.integer("schema_version") == 1,
              closed.string("record_type") == "apply_coordinator_closed",
              closed.string("close_mode") == "normal" else { throw ClosedFailure.bounds }
        // These protocol branches need different evidence; this oracle makes no verdict about them.
        if closed.string("operation_kind") == "apply" { throw ClosedScopeError.unsupportedBranch }
        guard closed.string("operation_kind") == "registry_commit" else { throw ClosedFailure.bounds }
        if ["ambiguous", "applied", "failed_before_mutation"].contains(closed.string("terminal_outcome") ?? "") { throw ClosedScopeError.unsupportedBranch }
        guard ["registry_committed", "registry_not_committed"].contains(closed.string("terminal_outcome") ?? "") else { throw ClosedFailure.bounds }
        if closed["registry_record_sha256"] == "null" {
            guard closed.string("terminal_outcome") == "registry_not_committed" else { throw ClosedFailure.bounds }
            throw ClosedScopeError.unsupportedBranch
        }
        guard ProtocolGrammar.isCanonicalBase32ID(closed.string("lease_id") ?? "", prefix: "YTAL-") else { throw ClosedFailure.bounds }
        for key in ["active_sha256", "registry_record_sha256"] {
            guard let value = closed.string(key), RegistryObject.hex(value, count: 64) else { throw ClosedFailure.bounds }
        }
        for key in ["permit_sha256", "receipt_sha256", "journal_revision"] {
            guard closed[key] == "null" else { throw ClosedFailure.bounds }
        }
        guard registryWholeSecondUTCSeconds(closed.string("closed_at") ?? "") != nil else { throw ClosedFailure.bounds }
    } catch RegistryReason.canonicalEncoding { throw ClosedFailure.canonical }
    catch RegistryReason.boundsGrammar { throw ClosedFailure.bounds }
    guard digest == closedDigest(bytes) else { throw ClosedFailure.digest }
    guard closed.string("lease_id") == active.string("lease_id"),
          closed.string("active_sha256") == supplied.sha256,
          closed.string("registry_record_sha256") == candidate else { throw ClosedFailure.binding }
    return closed
}

@Test func registryClosedSharedCorpus() throws {
    let corpus = try JSONDecoder().decode(ClosedCorpus.self, from: intentFixtureData("testdata/gate1a-registry-closed/corpus.json"))
    let actives = try JSONDecoder().decode(ActiveCorpus.self, from: intentFixtureData("testdata/gate1a-registry-active/corpus.json"))
    let intents = try JSONDecoder().decode(IntentCorpus.self, from: intentFixtureData("testdata/gate1a-registry-intent/corpus.json"))
    let core = try registryCorpus()
    #expect(corpus.schema_version == 1)
    #expect(corpus.scope == "registry-closed-retained-candidate-binding")
    try #require(corpus.sources.map(\.path) == ["testdata/gate1a-registry/corpus.json", "testdata/gate1a-registry-intent/corpus.json", "testdata/gate1a-registry-active/corpus.json"])
    #expect(corpus.sources.map(\.sha256) == ["b0fbce184a136c8b20689d51bb9eae0a46ecf510447c78a45728f8f4d88fde61", "ef65c0ae8132a37a0d6a04be2ba742537fa56ac78f32d4ce537f94c363557a05", "5fbe731e9ffa05c340586d0210d2a07ee7778e49c0d157d8d277cc029cb828c0"])
    for source in corpus.sources {
        #expect(source.sha256 == intentHex(Data(SHA256.hash(data: try intentFixtureData(source.path)))))
    }
    // Independently fixed exact bytes, candidate-domain hashes, and closed hashes.
    let pinned: [(String, String, String, String, String)] = [
        ("enroll1", "caf9ff28abe86dc19df7774563ad8c296c004038cbbf092056860abe82b11942", "f86e37d14900784636e841daa65e31d16d39e0b7c5be24f07c84e95d825ba9b9", "862b4c9b20628832198090aa3082c10a1bd9ca52f4ab15bd75e7a1af0c2f8986", "1c1c35708d77a8a956ae1e2aa20bc2f3172b7809c6e2df8595e819da7e21eefb"),
        ("rotate2", "c8212115dbfedbcc7e4f62a95b507d1f06eba6646029f0fb3bb70e44af8e5188", "85a529ae814b7df9bd079efa80105bb3ff88d016e0666777e8e9b9a59c1252e6", "5f54cb81201abe1d6306eed060fdff599bd8c6d279a8efa143e0a46f32468f29", "ad21d8367f65a5b96a827e0f8c79b6ea8b41074da38c018e9520149a3def6c4a"),
        ("revoke3", "3501fae949ef93dbac4c8fa779eb79f63e71f8f564439188bbd0ecf450d0651b", "4e79377de06250b3f7beb7bff3d6ecee8ddec8010cdae1b16735f97b3b72a8c4", "74af1573fe30eea94c59f065aa19cadef85df665264986c5ebfbc3636e932a3f", "86e7f921d60a17bd5ec3ed1e7d9abbe9b3efcabc91c1bbcb3bb8d888ecfa019c"),
        ("recover-disabled4", "2a80ebbe805fef70364c30ab4ceca1aa420fc0aadb45fbd4aa32ac97d33a8116", "b009d402b328c95af51abd92b84555e4d42cb66a39f73b6b8642f2638eb9ae8c", "0b397898c96502e8da09496147a64b4f22f7604737ed3e3d06e29e159e58bf30", "d3a12fb30d66fe2b58b2c44076f662fbcf2d77344673b3b3031b59f39341eb95"),
        ("recover-active3", "fcd9911c103141b81e6319ca67898f298f3e3efa5a6ba101c127ccfe2ee86905", "60d954ac63dd2d4fa7a83b389f97f9352cab52b4285c4ad08c70008ed60d4797", "c1980fba695ea5f1ab25ab333676f9b0f6dc298ee3f930fd4a64a3bba56de847", "0c16b9285a6ffb792295f3bebae550d3fd2b218e977a7aacae8e20c0890d3323"),
    ]
    // Grammar-only fixtures: these dates do not establish valid historical close chronology.
    let datePins: [(String, String, String)] = [
        ("date-grammar-year-zero", "0000-01-01T00:00:00Z", "13a0fdbda3f28cf415fbf39db457773bbace1e04249bca66d3e38d44545d45e7"),
        ("date-grammar-year-one", "0001-01-01T00:00:00Z", "10fae6f87684b87ef066a3123a137644bbb2fcbaa82b74f6f41943e164e6ae21"),
        ("date-grammar-year-max", "9999-12-31T23:59:59Z", "3c6aca19e8f8284c539673a20908657d7a5bbab42552ab382ab3c5a25fe30e54"),
        ("date-grammar-year-zero-leap", "0000-02-29T12:00:00Z", "b24c73a9463e57994632d19920bd3c176b150f7d332d04c9180c91ab60775bcb"),
        ("date-grammar-century-leap", "2000-02-29T12:00:00Z", "f5e8eea4ef783fceb9e684dd5a976a2901a800d17aa8582645fab6d3f73be8ff"),
        ("date-grammar-gregorian-cutover", "1582-10-10T12:00:00Z", "13a3e41224954cc7d898bbb71aa4ac684eb0680e1356c2545df4b2fbb6cd667c"),
    ]
    let expectedIDs = pinned.flatMap { ["closed-" + $0.0 + "-committed", "closed-" + $0.0 + "-not-committed"] } + datePins.map { $0.0 }
    try #require(corpus.positives.map(\.id) == expectedIDs)
    for (index, vector) in corpus.positives.prefix(pinned.count * 2).enumerated() {
        let pin = pinned[index / 2]
        let outcome = index % 2 == 0 ? "registry_committed" : "registry_not_committed"
        let hash = index % 2 == 0 ? pin.3 : pin.4
        let literal = #"{"schema_version":1,"record_type":"apply_coordinator_closed","lease_id":"YTAL-EEQSCIJBEEQSCIJBEEQSCIJBEE","active_sha256":"\#(pin.1)","permit_sha256":null,"receipt_sha256":null,"operation_kind":"registry_commit","terminal_outcome":"\#(outcome)","journal_revision":null,"registry_record_sha256":"\#(pin.2)","closed_at":"2026-09-01T12:00:04Z","close_mode":"normal"}"#
        let bytes = try intentBytes(vector.raw_hex)
        #expect(bytes == Data(literal.utf8))
        #expect(vector.active_id == "active-" + pin.0)
        #expect(vector.sha256 == hash)
        #expect(closedDigest(bytes) == hash)
        #expect(vector.signing_input_hex == intentHex(Data("YTA-APPLY-COORDINATOR-CLOSED-V1\0".utf8) + Data(literal.utf8)))
        let record = try #require(core.positives.first { $0.id == pin.0 }).record
        #expect(registryHash(record, domain: "YTA-REGISTRY-COMMIT-V1") == pin.2)
        do { _ = try validateRetainedCandidateClosed(bytes, digest: hash, activeID: vector.active_id, actives: actives, intents: intents, core: core) }
        catch { Issue.record("positive \(vector.id): unexpected \(error)") }
    }
    let families: [(ClosedFailure, String)] = [
        (.canonical, "canonical-empty canonical-malformed canonical-bom canonical-unknown canonical-duplicate canonical-missing canonical-reordered canonical-whitespace canonical-trailing-lf canonical-trailing-token canonical-escaped-key canonical-escaped-value canonical-invalid-utf8 canonical-schema-string canonical-schema-bool canonical-null canonical-array canonical-object canonical-schema-fraction canonical-schema-exponent canonical-schema-leading-zero canonical-schema-plus canonical-schema-negative-zero canonical-size-4096 canonical-active_sha256-null canonical-permit_sha256-array canonical-permit_sha256-object canonical-receipt_sha256-array canonical-receipt_sha256-object canonical-journal_revision-array canonical-journal_revision-object"),
        (.bounds, "bounds-size-4097 schema-version field-record-type field-operation-kind field-terminal-outcome field-close-mode field-lease-prefix field-lease-case field-lease-alphabet field-lease-15-bytes field-lease-17-bytes field-lease-padding field-lease-pad-bits field-active_sha256-empty field-active_sha256-short field-active_sha256-long field-active_sha256-uppercase field-active_sha256-nonhex field-registry_record_sha256-empty field-registry_record_sha256-short field-registry_record_sha256-long field-registry_record_sha256-uppercase field-registry_record_sha256-nonhex field-forbidden-permit_sha256 field-forbidden-receipt_sha256 field-forbidden-journal_revision field-closed_at-offset field-closed_at-fraction field-closed_at-invalid field-closed_at-century-nonleap field-closed_at-year-zero-invalid-day"),
        (.digest, "digest-wrong digest-no-nul digest-wrong-domain digest-plain-hash digest-lf-hash"),
        (.binding, "binding-lease binding-active binding-candidate binding-candidate-plain-hash binding-candidate-intent"),
    ]
    let candidatePrimitives = [("true", "true"), ("false", "false"), ("integer", "0"), ("fraction", "1.0"), ("array", "[]"), ("object", "{}")]
    var reasons = Dictionary(uniqueKeysWithValues: families.flatMap { reason, ids in ids.split(separator: " ").map { (String($0), reason) } })
    for (name, _) in candidatePrimitives {
        for suffix in ["", "-apply", "-close-mode"] { reasons["canonical-candidate-" + name + suffix] = .canonical }
    }
    reasons["field-candidate-committed-null"] = .bounds
    try #require(Set(corpus.negatives.map(\.id)) == Set(reasons.keys))
    try #require(corpus.negatives.count == reasons.count)
    let base = try #require(corpus.positives.first)
    let baseRaw = try #require(String(data: intentBytes(base.raw_hex), encoding: .utf8))
    for (id, date, hash) in datePins {
        let vector = try #require(corpus.positives.first { $0.id == id })
        let literal = baseRaw.replacingOccurrences(of: "2026-09-01T12:00:04Z", with: date)
        let bytes = try intentBytes(vector.raw_hex)
        #expect(bytes == Data(literal.utf8))
        #expect(vector.active_id == "active-enroll1")
        #expect(vector.sha256 == hash)
        #expect(closedDigest(bytes) == hash)
        #expect(vector.signing_input_hex == intentHex(Data("YTA-APPLY-COORDINATOR-CLOSED-V1\0".utf8) + Data(literal.utf8)))
        do { _ = try validateRetainedCandidateClosed(bytes, digest: hash, activeID: vector.active_id, actives: actives, intents: intents, core: core) }
        catch { Issue.record("positive \(id): unexpected \(error)") }
    }
    let invalidDates: [String: (String, String)] = [
        "field-closed_at-century-nonleap": ("1900-02-29T12:00:00Z", "b04bf7a78452a85c87d9df1f3542ba349cd09518a814b5b23dbdfbe8fcf65d57"),
        "field-closed_at-year-zero-invalid-day": ("0000-02-30T12:00:00Z", "89739181ca2de095ea4c101feecf577ccc8c30a89e8c1096205f7a6acac05b3b"),
    ]
    for vector in corpus.negatives {
        let reason = try #require(reasons[vector.id])
        #expect(vector.reason_class == reason.rawValue)
        #expect(vector.base == "closed-enroll1-committed")
        #expect(vector.active_id == "active-enroll1")
        #expect(vector.raw_hex != base.raw_hex || vector.sha256 != base.sha256)
        let bytes = try intentBytes(vector.raw_hex)
        if reason != .digest { #expect(vector.sha256 == closedDigest(bytes)) }
        if vector.id == "canonical-bom" { #expect(vector.raw_hex == "efbbbf" + base.raw_hex) }
        if vector.id == "field-lease-case" {
            #expect(bytes == Data(baseRaw.replacingOccurrences(of: "YTAL-EEQSCIJBEEQSCIJBEEQSCIJBEE", with: "YTAL-eeqscijbeeqscijbeeqscijbee").utf8))
        }
        if vector.id == "canonical-size-4096" { #expect(bytes.count == 4096) }
        if vector.id == "bounds-size-4097" { #expect(bytes.count == 4097) }
        for (name, primitive) in candidatePrimitives {
            let literal = baseRaw.replacingOccurrences(of: "\"" + pinned[0].2 + "\"", with: primitive)
            if vector.id == "canonical-candidate-" + name { #expect(bytes == Data(literal.utf8)) }
            if vector.id == "canonical-candidate-" + name + "-apply" {
                #expect(bytes == Data(literal.replacingOccurrences(of: "\"operation_kind\":\"registry_commit\"", with: "\"operation_kind\":\"apply\"").utf8))
            }
            if vector.id == "canonical-candidate-" + name + "-close-mode" {
                #expect(bytes == Data(literal.replacingOccurrences(of: "\"close_mode\":\"normal\"", with: "\"close_mode\":\"unknown\"").utf8))
            }
        }
        if vector.id == "field-candidate-committed-null" {
            #expect(bytes == Data(baseRaw.replacingOccurrences(of: "\"" + pinned[0].2 + "\"", with: "null").utf8))
        }
        if let (date, hash) = invalidDates[vector.id] {
            #expect(bytes == Data(baseRaw.replacingOccurrences(of: "2026-09-01T12:00:04Z", with: date).utf8))
            #expect(vector.sha256 == hash)
        }
        if vector.id == "binding-candidate-plain-hash" || vector.id == "binding-candidate-intent" {
            let replacement = vector.id == "binding-candidate-plain-hash" ? "c8154cd7d2a72f7e23dcbfa9f52d1b9ca97afad557c6becedf9eaf7a772db16b" : "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67"
            #expect(bytes == Data(baseRaw.replacingOccurrences(of: pinned[0].2, with: replacement).utf8))
        }
        #expect(throws: reason, "\(vector.id)") {
            _ = try validateRetainedCandidateClosed(bytes, digest: vector.sha256, activeID: vector.active_id, actives: actives, intents: intents, core: core)
        }
    }
    // Scope is not a claim of protocol invalidity, and timestamps are grammar-only here.
    for (old, replacement) in [("registry_commit\"", "apply\""), ("registry_committed", "ambiguous"), ("registry_committed", "applied"), ("registry_committed", "failed_before_mutation")] {
        let bytes = Data(baseRaw.replacingOccurrences(of: old, with: replacement).utf8)
        #expect(throws: ClosedScopeError.unsupportedBranch) {
            _ = try validateRetainedCandidateClosed(bytes, digest: closedDigest(bytes), activeID: base.active_id, actives: actives, intents: intents, core: core)
        }
    }
    for outcome in ["registry_not_committed", "ambiguous", "applied", "failed_before_mutation"] {
        let bytes = Data(baseRaw.replacingOccurrences(of: "registry_committed", with: outcome).replacingOccurrences(of: "\"" + pinned[0].2 + "\"", with: "null").utf8)
        #expect(throws: ClosedScopeError.unsupportedBranch, "null candidate with \(outcome)") {
            _ = try validateRetainedCandidateClosed(bytes, digest: closedDigest(bytes), activeID: base.active_id, actives: actives, intents: intents, core: core)
        }
    }
    for date in ["2026-08-01T00:00:00Z", "2026-10-01T00:00:00Z"] {
        let bytes = Data(baseRaw.replacingOccurrences(of: "2026-09-01T12:00:04Z", with: date).utf8)
        _ = try validateRetainedCandidateClosed(bytes, digest: closedDigest(bytes), activeID: base.active_id, actives: actives, intents: intents, core: core)
    }
}

@Test func registryClosedFixtureIntegrityPrecedesClosedValidation() throws {
    let activeData = try intentFixtureData("testdata/gate1a-registry-active/corpus.json")
    let intentData = try intentFixtureData("testdata/gate1a-registry-intent/corpus.json")
    let coreData = try intentFixtureData("testdata/gate1a-registry/corpus.json")
    let actives = try JSONDecoder().decode(ActiveCorpus.self, from: activeData)
    let intents = try JSONDecoder().decode(IntentCorpus.self, from: intentData)
    let core = try registryCorpus()
    #expect(throws: ClosedFixtureError.unknownActive) {
        _ = try validateRetainedCandidateClosed(Data(), digest: "", activeID: "missing", actives: actives, intents: intents, core: core)
    }
    func corrupted(_ data: Data, field: String, value: Any) throws -> Data {
        var document = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        var positives = try #require(document["positives"] as? [[String: Any]])
        positives[0][field] = value
        document["positives"] = positives
        return try JSONSerialization.data(withJSONObject: document)
    }
    // Deliberately invalid target bytes must not conceal any broken upstream fixture.
    for field in ["raw_hex", "sha256", "intent_id"] {
        let broken = try JSONDecoder().decode(ActiveCorpus.self, from: corrupted(activeData, field: field, value: "UNTRUSTED_SENTINEL"))
        #expect(throws: ClosedFixtureError.invalidActive, "active \(field)") {
            _ = try validateRetainedCandidateClosed(Data(), digest: "", activeID: "active-enroll1", actives: broken, intents: intents, core: core)
        }
    }
    for field in ["raw_hex", "sha256", "core_id"] {
        let broken = try JSONDecoder().decode(IntentCorpus.self, from: corrupted(intentData, field: field, value: "UNTRUSTED_SENTINEL"))
        #expect(throws: ClosedFixtureError.invalidActive, "intent \(field)") {
            _ = try validateRetainedCandidateClosed(Data(), digest: "", activeID: "active-enroll1", actives: actives, intents: broken, core: core)
        }
    }
    for field in ["request", "record", "prefix"] {
        let broken = try JSONDecoder().decode(RegistryCorpus.self, from: corrupted(coreData, field: field, value: field == "prefix" ? ["UNTRUSTED_SENTINEL"] : "UNTRUSTED_SENTINEL"))
        for id in field == "prefix" ? ["active-enroll1"] : ["active-enroll1", "active-rotate2"] {
            #expect(throws: ClosedFixtureError.invalidActive, "core \(field) \(id)") {
                _ = try validateRetainedCandidateClosed(Data(), digest: "", activeID: id, actives: actives, intents: intents, core: broken)
            }
        }
    }
}
