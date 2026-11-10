import Foundation
import Testing
@testable import ApprovalProtocol

struct RegistryCorpus: Decodable {
    struct State: Decodable, Equatable { let generation: String; let status: String }
    struct Manifest: Decodable { let purpose: String; let input_hex: String; let sha256: String }
    struct Positive: Decodable {
        let id: String
        let prefix: [String]
        let request: String
        let recovery_evidence: String?
        let unsigned_proposal: String
        let proposal: String
        let acceptance: String
        let final_body: String
        let record: String
        let manifest: [Manifest]
        let expected_state: [State]
        var transcript: RegistryTranscript {
            RegistryTranscript(request: request, recovery_evidence: recovery_evidence, unsigned_proposal: unsigned_proposal, proposal: proposal, acceptance: acceptance, final_body: final_body, record: record)
        }
    }
    struct Negative: Decodable {
        let id: String
        let base: String
        let change: String
        let reason_class: String
        let prefix: [String]
        let transcript: RegistryTranscript
        let prefix_records: [String]?
    }
    struct Status: Decodable { let id: String; let raw: String; let accepted: Bool }
    struct Key: Decodable { let generation: String; let key_id: String; let key_tag: String; let spki: String; let fingerprint_sha256: String }
    let schema_version: Int
    let scope: String
    let keys: [Key]
    let positives: [Positive]
    let negatives: [Negative]
    let osstatus: [Status]
}

func registryCorpus() throws -> RegistryCorpus {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<6 { root.deleteLastPathComponent() }
    let corpus = try JSONDecoder().decode(RegistryCorpus.self, from: Data(contentsOf: root.appendingPathComponent("testdata/gate1a-registry/corpus.json")))
    try #require(corpus.schema_version == 1)
    try #require(corpus.scope == "registry-transcript-core")
    return corpus
}

func registryPrefix(_ ids: [String], corpus: RegistryCorpus) throws -> RegistryLedger {
    var ledger = RegistryLedger()
    try #require(ids.count <= 256)
    var total = 0
    for id in ids {
        let positive = try #require(corpus.positives.first { $0.id == id })
        total += positive.record.utf8.count
        try #require(total <= 1_114_112)
        try ledger.validate(positive.transcript)
    }
    return ledger
}
