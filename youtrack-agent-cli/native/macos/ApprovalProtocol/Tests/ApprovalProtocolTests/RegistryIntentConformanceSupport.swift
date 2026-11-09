import CryptoKit
import Foundation
import Testing

// Offline fixture oracle only; no coordinator, native authority, or runtime API.
enum IntentFailure: String, Error {
    case canonical = "canonical_encoding"
    case bounds = "bounds_grammar"
    case temporal
    case digest = "digest_domain"
    case binding = "intent_binding"
}

enum IntentFixtureError: Error { case malformedHex, unknownCore, invalidCore }

struct IntentCorpus: Decodable {
    struct Source: Decodable { let path: String; let sha256: String }
    struct Positive: Decodable {
        let id: String; let core_id: String?; let raw_hex: String
        let signing_input_hex: String; let sha256: String
    }
    struct Negative: Decodable {
        let id: String; let base: String; let core_id: String?
        let raw_hex: String; let sha256: String; let reason_class: String
    }
    let schema_version: Int; let scope: String; let source: Source
    let positives: [Positive]; let negatives: [Negative]
}

func intentFixtureData(_ path: String) throws -> Data {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<6 { root.deleteLastPathComponent() }
    return try Data(contentsOf: root.appendingPathComponent(path))
}

func intentHex(_ bytes: Data) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func intentBytes(_ hex: String) throws -> Data {
    guard hex.utf8.count % 2 == 0, hex.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
        throw IntentFixtureError.malformedHex
    }
    let characters = Array(hex.utf8)
    return Data(stride(from: 0, to: characters.count, by: 2).map {
        UInt8(String(decoding: characters[$0..<$0 + 2], as: UTF8.self), radix: 16)!
    })
}

func intentInput(_ bytes: Data) -> Data {
    Data("YTA-REGISTRY-INTENT-V1\0".utf8) + bytes
}

func intentDigest(_ bytes: Data) -> String { intentHex(Data(SHA256.hash(data: intentInput(bytes)))) }

func validatedIntentCore(_ id: String?, corpus: RegistryCorpus) throws -> RegistryObject? {
    guard let id else { return nil }
    guard let core = corpus.positives.first(where: { $0.id == id }),
          core.prefix.allSatisfy({ reference in corpus.positives.contains { $0.id == reference } }) else {
        throw IntentFixtureError.unknownCore
    }
    do {
        var ledger = try registryPrefix(core.prefix, corpus: corpus)
        try ledger.validate(core.transcript)
        return try RegistryObject(core.request, keys: registryRequestKeys, cap: 2048)
    } catch { throw IntentFixtureError.invalidCore }
}

func validateIntent(_ bytes: Data, digest: String, coreID: String?, corpus: RegistryCorpus) throws -> RegistryObject {
    // Broken references and invalid signed transcripts are fixture defects,
    // never a successful negative intent verdict. Replay the full core first.
    let request = try validatedIntentCore(coreID, corpus: corpus)
    guard bytes.count <= 1024 else { throw IntentFailure.bounds }
    // Foundation can strip a leading BOM; canonical validation must preserve every input byte.
    guard let raw = String(data: bytes, encoding: .utf8), Data(raw.utf8) == bytes else {
        throw IntentFailure.canonical
    }
    let intent: RegistryObject
    do {
        intent = try RegistryObject(raw, keys: ["schema_version", "intent_type", "transition_kind", "artifact_descriptor_sha256", "ceremony_nonce", "requested_at", "expires_at"], cap: 1024, checkGrammar: false)
        guard intent["schema_version"].range(of: "^(0|[1-9][0-9]*|-[1-9][0-9]*)$", options: .regularExpression) != nil,
              intent.fields.dropFirst().allSatisfy({ intent.string($0.0) != nil }) else { throw IntentFailure.canonical }
        try intent.grammar()
        guard intent.string("intent_type") == "registry_commit",
              ["enroll", "rotate", "revoke", "recover"].contains(intent.string("transition_kind") ?? "") else { throw IntentFailure.bounds }
        _ = try registryBase64(intent.string("ceremony_nonce") ?? "", count: 32)
    } catch RegistryReason.canonicalEncoding { throw IntentFailure.canonical }
    catch let error as RegistryReason {
        guard error == .boundsGrammar else { throw error }
        throw IntentFailure.bounds
    }
    let duration = try intent.time("expires_at").timeIntervalSince(intent.time("requested_at"))
    guard duration >= 1, duration <= 300 else { throw IntentFailure.temporal }
    guard digest == intentDigest(bytes) else { throw IntentFailure.digest }
    if let request {
        guard intent.string("transition_kind") == request.string("transition_kind"),
              intent.string("artifact_descriptor_sha256") == request.string("artifact_descriptor_sha256"),
              try registryBase64(intent.string("ceremony_nonce")!, count: 32) == registryBase64(request.string("challenge")!, count: 32),
              intent.string("expires_at") == request.string("expires_at") else { throw IntentFailure.binding }
    }
    return intent
}
