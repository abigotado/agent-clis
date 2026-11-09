import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

// Offline supplied-fixture consistency only: no acquisition, owner, or runtime authority.
enum ActiveFailure: String, Error {
    case canonical = "canonical_encoding"
    case bounds = "bounds_grammar"
    case temporal
    case digest = "digest_domain"
    case binding = "active_binding"
}

enum ActiveFixtureError: Error { case unknownIntent, missingCore, invalidIntent }

struct ActiveCorpus: Decodable {
    struct Positive: Decodable {
        let id: String; let intent_id: String; let raw_hex: String
        let signing_input_hex: String; let sha256: String
    }
    struct Negative: Decodable {
        let id: String; let base: String; let intent_id: String
        let raw_hex: String; let sha256: String; let reason_class: String
    }
    let schema_version: Int; let scope: String; let sources: [IntentCorpus.Source]
    let positives: [Positive]; let negatives: [Negative]
}

func activeInput(_ bytes: Data) -> Data {
    Data("YTA-APPLY-COORDINATOR-ACTIVE-V1\0".utf8) + bytes
}

func activeDigest(_ bytes: Data) -> String { intentHex(Data(SHA256.hash(data: activeInput(bytes)))) }

func validateActive(_ bytes: Data, digest: String, intentID: String, intents: IntentCorpus, core: RegistryCorpus) throws -> RegistryObject {
    guard let supplied = intents.positives.first(where: { $0.id == intentID }) else { throw ActiveFixtureError.unknownIntent }
    guard let coreID = supplied.core_id else { throw ActiveFixtureError.missingCore }
    let intent: RegistryObject
    do {
        intent = try validateIntent(intentBytes(supplied.raw_hex), digest: supplied.sha256, coreID: coreID, corpus: core)
    } catch { throw ActiveFixtureError.invalidIntent }
    // Validate referenced signed core and intent before considering active bytes.
    guard bytes.count <= 4096 else { throw ActiveFailure.bounds }
    guard let raw = String(data: bytes, encoding: .utf8), Data(raw.utf8) == bytes else { throw ActiveFailure.canonical }
    let active: RegistryObject
    do {
        active = try RegistryObject(raw, keys: "schema_version record_type lease_id operation_kind coordinator_session_id cli_audit_token_sha256 artifact_descriptor_sha256 authorization_context_sha256 registry_revision plan_id journal_revision receipt_sha256 registry_intent_sha256 created_at expires_at".split(separator: " ").map(String.init), cap: 4096, checkGrammar: false)
        guard active["schema_version"].range(of: "^(0|[1-9][0-9]*|-[1-9][0-9]*)$", options: .regularExpression) != nil else { throw ActiveFailure.canonical }
        for key in ["record_type", "lease_id", "operation_kind", "coordinator_session_id", "cli_audit_token_sha256", "artifact_descriptor_sha256", "registry_intent_sha256", "created_at", "expires_at"] {
            guard active.string(key) != nil else { throw ActiveFailure.canonical }
        }
        guard try active.integer("schema_version") == 1,
              active.string("record_type") == "apply_coordinator_active",
              active.string("operation_kind") == "registry_commit",
              ProtocolGrammar.isCanonicalBase32ID(active.string("lease_id") ?? "", prefix: "YTAL-") else { throw ActiveFailure.bounds }
        _ = try registryBase64(active.string("coordinator_session_id") ?? "", count: 32)
        for key in ["cli_audit_token_sha256", "artifact_descriptor_sha256", "registry_intent_sha256"] {
            guard let value = active.string(key), RegistryObject.hex(value, count: 64) else { throw ActiveFailure.bounds }
        }
        for key in ["authorization_context_sha256", "registry_revision", "plan_id", "journal_revision", "receipt_sha256"] {
            guard active[key] == "null" else { throw ActiveFailure.bounds }
        }
        let duration = try active.time("expires_at").timeIntervalSince(active.time("created_at"))
        guard duration >= 1, duration <= 600 else { throw ActiveFailure.temporal }
    } catch RegistryReason.canonicalEncoding { throw ActiveFailure.canonical }
    catch RegistryReason.boundsGrammar { throw ActiveFailure.bounds }
    guard digest == activeDigest(bytes) else { throw ActiveFailure.digest }
    guard active.string("registry_intent_sha256") == supplied.sha256,
          active.string("artifact_descriptor_sha256") == intent.string("artifact_descriptor_sha256") else { throw ActiveFailure.binding }
    return active
}
