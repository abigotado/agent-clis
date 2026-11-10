import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

@Test func registryActiveSharedCorpus() throws {
    let corpus = try JSONDecoder().decode(ActiveCorpus.self, from: intentFixtureData("testdata/gate1a-registry-active/corpus.json"))
    let intents = try JSONDecoder().decode(IntentCorpus.self, from: intentFixtureData("testdata/gate1a-registry-intent/corpus.json"))
    let core = try registryCorpus()
    #expect(corpus.schema_version == 1)
    #expect(corpus.scope == "registry-active-intent-binding")
    let paths = ["testdata/gate1a-registry/corpus.json", "testdata/gate1a-registry-intent/corpus.json"]
    try #require(corpus.sources.map(\.path) == paths)
    for source in corpus.sources {
        #expect(source.sha256 == intentHex(Data(SHA256.hash(data: try intentFixtureData(source.path)))))
    }
    // Independent literal bytes and digests, not expectations copied at test time from the generator.
    let expected: [(String, String, String, String)] = [
        ("active-enroll1", "intent-enroll1", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67", "caf9ff28abe86dc19df7774563ad8c296c004038cbbf092056860abe82b11942"),
        ("active-rotate2", "intent-rotate2", "e122718b57b090b792ad13ecbb347a0d3181d9e3c1217bd590d061af0cc56c87", "c8212115dbfedbcc7e4f62a95b507d1f06eba6646029f0fb3bb70e44af8e5188"),
        ("active-revoke3", "intent-revoke3", "713452b672826409337bbd53668ab09157a265cfe2db5ce2884d33adbb5b387f", "3501fae949ef93dbac4c8fa779eb79f63e71f8f564439188bbd0ecf450d0651b"),
        ("active-recover-disabled4", "intent-recover-disabled4", "8ccd7960f14afea3c3efbb4605f4e01c537f39facf4ac7403da19b8b03442612", "2a80ebbe805fef70364c30ab4ceca1aa420fc0aadb45fbd4aa32ac97d33a8116"),
        ("active-recover-active3", "intent-recover-active3", "de2c3928d468b22ed606840441758ccfadcae491a17493dc93f8adf8065f51f9", "fcd9911c103141b81e6319ca67898f298f3e3efa5a6ba101c127ccfe2ee86905"),
        ("ttl-1s", "intent-enroll1", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67", "04c41ff1321d8b32ec08aac7efaf1e4eb693c1d348b5fc3a6e198af5b589c16e"),
        ("ttl-600s", "intent-enroll1", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67", "caf9ff28abe86dc19df7774563ad8c296c004038cbbf092056860abe82b11942"),
    ]
    try #require(corpus.positives.map(\.id) == expected.map(\.0))
    for (vector, pinned) in zip(corpus.positives, expected) {
        let expiry = vector.id == "ttl-1s" ? "2026-09-01T12:00:01Z" : "2026-09-01T12:10:00Z"
        let literal = #"{"schema_version":1,"record_type":"apply_coordinator_active","lease_id":"YTAL-EEQSCIJBEEQSCIJBEEQSCIJBEE","operation_kind":"registry_commit","coordinator_session_id":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","cli_audit_token_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","artifact_descriptor_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authorization_context_sha256":null,"registry_revision":null,"plan_id":null,"journal_revision":null,"receipt_sha256":null,"registry_intent_sha256":"\#(pinned.2)","created_at":"2026-09-01T12:00:00Z","expires_at":"\#(expiry)"}"#
        let bytes = try intentBytes(vector.raw_hex)
        #expect(bytes == Data(literal.utf8))
        #expect(vector.intent_id == pinned.1)
        #expect(vector.sha256 == pinned.3)
        #expect(activeDigest(bytes) == pinned.3)
        #expect(vector.signing_input_hex == intentHex(Data("YTA-APPLY-COORDINATOR-ACTIVE-V1\0".utf8) + Data(literal.utf8)))
        let active: RegistryObject
        do { active = try validateActive(bytes, digest: pinned.3, intentID: pinned.1, intents: intents, core: core) }
        catch {
            Issue.record("positive \(vector.id): unexpected \(error)")
            continue
        }
        #expect(try active.time("expires_at").timeIntervalSince(active.time("created_at")) == (vector.id == "ttl-1s" ? 1 : 600))
        // Lease expiry deliberately differs from the intent: no extra equality binding.
        #expect(active.string("expires_at") != "2026-09-01T12:05:00Z")
    }
    let families: [(ActiveFailure, String)] = [
        (.canonical, "canonical-empty canonical-malformed canonical-bom canonical-unknown canonical-duplicate canonical-missing canonical-reordered canonical-whitespace canonical-trailing-lf canonical-trailing-token canonical-escaped-key canonical-escaped-value canonical-invalid-utf8 canonical-schema-string canonical-schema-bool canonical-null canonical-array canonical-object canonical-schema-fraction canonical-schema-exponent canonical-schema-leading-zero canonical-schema-plus canonical-schema-negative-zero canonical-size-4096 canonical-cli_audit_token_sha256-null canonical-artifact_descriptor_sha256-null canonical-registry_intent_sha256-null canonical-forbidden-array canonical-forbidden-object"),
        (.bounds, "bounds-size-4097 schema-version field-record-type field-operation-kind field-lease-prefix field-lease-case field-lease-alphabet field-lease-15-bytes field-lease-17-bytes field-lease-padding field-lease-pad-bits field-session-31-bytes field-session-33-bytes field-session-alphabet field-session-padding field-session-pad-bits field-cli_audit_token_sha256-empty field-cli_audit_token_sha256-short field-cli_audit_token_sha256-long field-cli_audit_token_sha256-uppercase field-cli_audit_token_sha256-nonhex field-artifact_descriptor_sha256-empty field-artifact_descriptor_sha256-short field-artifact_descriptor_sha256-long field-artifact_descriptor_sha256-uppercase field-artifact_descriptor_sha256-nonhex field-registry_intent_sha256-empty field-registry_intent_sha256-short field-registry_intent_sha256-long field-registry_intent_sha256-uppercase field-registry_intent_sha256-nonhex field-forbidden-authorization_context_sha256 field-forbidden-registry_revision field-forbidden-plan_id field-forbidden-journal_revision field-forbidden-receipt_sha256 field-created_at-offset field-created_at-fraction field-created_at-invalid field-expires_at-offset field-expires_at-fraction field-expires_at-invalid"),
        (.temporal, "temporal-zero temporal-negative temporal-601s"),
        (.digest, "digest-wrong digest-no-nul digest-wrong-domain digest-plain-hash digest-lf-hash"),
        (.binding, "binding-intent binding-candidate-record binding-descriptor"),
    ]
    let reasons = Dictionary(uniqueKeysWithValues: families.flatMap { reason, ids in ids.split(separator: " ").map { (String($0), reason) } })
    try #require(Set(corpus.negatives.map(\.id)) == Set(reasons.keys))
    try #require(corpus.negatives.count == reasons.count)
    let base = try #require(corpus.positives.first)
    for vector in corpus.negatives {
        let reason = try #require(reasons[vector.id])
        #expect(vector.reason_class == reason.rawValue)
        #expect(vector.base == "active-enroll1")
        #expect(vector.intent_id == "intent-enroll1")
        #expect(vector.raw_hex != base.raw_hex || vector.sha256 != base.sha256)
        let bytes = try intentBytes(vector.raw_hex)
        if reason != .digest { #expect(vector.sha256 == activeDigest(bytes)) }
        if vector.id == "canonical-bom" { #expect(vector.raw_hex == "efbbbf" + base.raw_hex) }
        if vector.id == "field-lease-case" {
            let baseRaw = try #require(String(data: intentBytes(base.raw_hex), encoding: .utf8))
            let expectedRaw = baseRaw.replacingOccurrences(of: #""lease_id":"YTAL-EEQSCIJBEEQSCIJBEEQSCIJBEE""#, with: #""lease_id":"YTAL-eeqscijbeeqscijbeeqscijbee""#)
            #expect(bytes == Data(expectedRaw.utf8))
        }
        if vector.id == "canonical-size-4096" { #expect(bytes.count == 4096) }
        if vector.id == "bounds-size-4097" { #expect(bytes.count == 4097) }
        if vector.id == "binding-candidate-record" {
            _ = try validatedIntentCore("enroll1", corpus: core)
            let record = try #require(core.positives.first { $0.id == "enroll1" }).record
            let candidateDigest = registryHash(record, domain: "YTA-REGISTRY-COMMIT-V1")
            #expect(candidateDigest == "f86e37d14900784636e841daa65e31d16d39e0b7c5be24f07c84e95d825ba9b9")
            let baseRaw = try #require(String(data: intentBytes(base.raw_hex), encoding: .utf8))
            let expectedRaw = baseRaw.replacingOccurrences(of: expected[0].2, with: candidateDigest)
            #expect(bytes == Data(expectedRaw.utf8))
        }
        #expect(throws: reason, "\(vector.id)") {
            _ = try validateActive(bytes, digest: vector.sha256, intentID: vector.intent_id, intents: intents, core: core)
        }
    }
}

@Test func registryActiveFixtureIntegrityPrecedesActiveValidation() throws {
    let intentData = try intentFixtureData("testdata/gate1a-registry-intent/corpus.json")
    let intents = try JSONDecoder().decode(IntentCorpus.self, from: intentData)
    let core = try registryCorpus()
    #expect(throws: ActiveFixtureError.unknownIntent) {
        _ = try validateActive(Data(), digest: "", intentID: "missing", intents: intents, core: core)
    }
    #expect(throws: ActiveFixtureError.missingCore) {
        _ = try validateActive(Data(), digest: "", intentID: "ttl-1s", intents: intents, core: core)
    }
    for change in ["raw_hex", "sha256", "core_id"] {
        var document = try #require(JSONSerialization.jsonObject(with: intentData) as? [String: Any])
        var positives = try #require(document["positives"] as? [[String: Any]])
        positives[0][change] = change == "raw_hex" ? "7b7d" : "missing"
        document["positives"] = positives
        let corrupted = try JSONDecoder().decode(IntentCorpus.self, from: JSONSerialization.data(withJSONObject: document))
        #expect(throws: ActiveFixtureError.invalidIntent, "\(change)") {
            _ = try validateActive(Data(), digest: "", intentID: "intent-enroll1", intents: corrupted, core: core)
        }
    }
    let coreData = try intentFixtureData("testdata/gate1a-registry/corpus.json")
    for change in ["request", "prefix"] {
        var document = try #require(JSONSerialization.jsonObject(with: coreData) as? [String: Any])
        var positives = try #require(document["positives"] as? [[String: Any]])
        if change == "request" { positives[0][change] = "{}" }
        else { positives[0][change] = ["missing"] }
        document["positives"] = positives
        let corrupted = try JSONDecoder().decode(RegistryCorpus.self, from: JSONSerialization.data(withJSONObject: document))
        let ids = change == "request" ? ["intent-enroll1", "intent-rotate2"] : ["intent-enroll1"]
        for id in ids {
            #expect(throws: ActiveFixtureError.invalidIntent, "\(change) \(id)") {
                _ = try validateActive(Data(), digest: "", intentID: id, intents: intents, core: corrupted)
            }
        }
    }
}
