import struct Foundation.Data

enum SuppliedRegistryBounds {
    static let maximumRecords = 256
    static let maximumRecordBytes = 4_352
    static let maximumBodyBytes = 4_096
}

/// Static phase failures. Untrusted record text and parser diagnostics never escape.
public enum SuppliedRegistryHistoryError: Error, Equatable, Sendable {
    case bounds
    case encoding
    case grammar
    case replay
}

/// One introduced key and its status derived solely from the supplied prefix.
public struct SuppliedRegistryKey: Equatable, Sendable {
    public let generation: String
    public let keyID: String
    public let keyTag: String
    public let spki: String
    public let fingerprintSHA256: String
    public let status: String

    fileprivate init(tuple: SuppliedRegistryTuple, status: String) {
        generation = tuple.generation
        keyID = tuple.keyID
        keyTag = tuple.keyTag
        spki = tuple.spki
        fingerprintSHA256 = tuple.fingerprintSHA256
        self.status = status
    }
}

/// Cryptographic consistency of a caller-supplied, genesis-based prefix only.
/// This is not a current protected tip, proof of completeness, native recovery
/// eligibility, or an authorization capability. Historical descriptor claims
/// may differ; the returned descriptor is only the supplied tip's signed claim.
public struct SuppliedRegistryHistory: Equatable, Sendable {
    public let suppliedRevision: Int
    public let suppliedTipSHA256: String
    public let suppliedTipDescriptorSHA256: String?
    public let keys: [SuppliedRegistryKey]

    private init(revision: Int, tip: String, descriptor: String?, keys: [SuppliedRegistryKey]) {
        suppliedRevision = revision
        suppliedTipSHA256 = tip
        suppliedTipDescriptorSHA256 = descriptor
        self.keys = keys
    }

    public static func verify(suppliedRecords: [Data]) throws -> Self {
        // Complete all bounds before copying, parsing, hashing, or cryptography.
        guard suppliedRecords.count <= SuppliedRegistryBounds.maximumRecords else { throw SuppliedRegistryHistoryError.bounds }
        for bytes in suppliedRecords {
            guard !bytes.isEmpty, bytes.count <= SuppliedRegistryBounds.maximumRecordBytes
            else { throw SuppliedRegistryHistoryError.bounds }
        }
        // These bounds imply the frozen 1,114,112-byte aggregate cap
        // (256 * 4,352), without summing untrusted lengths.
        // Data has value semantics. The private snapshot never borrows mutable
        // caller storage and is retained unchanged for hashes and signatures.
        let snapshot = suppliedRecords.map { Data(Array($0)) }
        var canonical: [SuppliedRegistryCanonicalObject] = []
        do {
            for bytes in snapshot { canonical.append(try SuppliedRegistryCanonicalObject(bytes: bytes)) }
        } catch { throw SuppliedRegistryHistoryError.encoding }

        var records: [SuppliedRegistryRecord] = []
        do {
            for object in canonical { records.append(try SuppliedRegistryRecord(object: object)) }
        } catch { throw SuppliedRegistryHistoryError.grammar }

        return try verifyParsedRecords(records)
    }

    // Package-internal replay accepts only globally parsed/validated records.
    // It does not skip the supplied-only trust boundary or produce live authority.
    static func verifyParsedRecords(
        _ records: [SuppliedRegistryRecord],
        validateBeforeFinalRecord: ((Self) throws -> Void)? = nil
    ) throws -> Self {
        // No prefix result escapes if any signature, predecessor, or event fails.
        do {
            var introduced: [SuppliedRegistryTuple] = []
            var statuses: [String] = []
            var tip = String(repeating: "0", count: 64)
            var descriptor: String?
            for (index, record) in records.enumerated() {
                if index == records.count - 1, let validateBeforeFinalRecord {
                    let prefixKeys = zip(introduced, statuses).map { SuppliedRegistryKey(tuple: $0.0, status: $0.1) }
                    try validateBeforeFinalRecord(Self(revision: index, tip: tip, descriptor: descriptor, keys: prefixKeys))
                }
                guard record.revision == index + 1, record.previous == tip,
                      record.requested <= record.accepted, record.accepted <= record.committed,
                      record.committed - record.requested < 300,
                      (record.recoveryDigest != nil) == (record.kind == "recover")
                else { throw SuppliedRegistryHistoryError.replay }

                guard statuses.lazy.filter({ $0 == "active" }).count <= 1
                else { throw SuppliedRegistryHistoryError.replay }
                let activeIndex = statuses.firstIndex(of: "active")
                let active = activeIndex.map { introduced[$0] }
                guard record.target == active,
                      record.targetPreviousStatus == (active == nil ? nil : "active"),
                      record.newStatus == (record.new == nil ? nil : "active")
                else { throw SuppliedRegistryHistoryError.replay }

                if let new = record.new {
                    guard introduced.allSatisfy({
                        $0.generation != new.generation && $0.keyID != new.keyID &&
                            $0.keyTag != new.keyTag && $0.spki != new.spki &&
                            $0.fingerprintSHA256 != new.fingerprintSHA256
                    }) else { throw SuppliedRegistryHistoryError.replay }
                }

                let oldRequired = record.kind == "rotate" || record.kind == "revoke"
                let newRequired = record.kind != "revoke"
                guard (record.oldSignature != nil) == oldRequired,
                      (record.newSignature != nil) == newRequired
                else { throw SuppliedRegistryHistoryError.replay }

                switch record.kind {
                case "enroll":
                    guard index == 0, record.target == nil, record.new != nil,
                          record.targetNewStatus == nil, !record.revokesAll
                    else { throw SuppliedRegistryHistoryError.replay }
                case "rotate", "revoke":
                    let next = record.kind == "rotate" ? "retained" : "revoked"
                    guard let activeIndex, (record.new != nil) == (record.kind == "rotate"),
                          record.targetNewStatus == next, !record.revokesAll
                    else { throw SuppliedRegistryHistoryError.replay }
                    statuses[activeIndex] = next
                case "recover":
                    // A signed recovery declaration does not prove native
                    // Keychain absence or the live ceremony's eligibility.
                    guard index > 0, record.new != nil, record.revokesAll,
                          record.targetNewStatus == (active == nil ? nil : "revoked")
                    else { throw SuppliedRegistryHistoryError.replay }
                    statuses = statuses.map { _ in "revoked" }
                default: throw SuppliedRegistryHistoryError.replay
                }

                if let signature = record.oldSignature {
                    guard let target = record.target else { throw SuppliedRegistryHistoryError.replay }
                    try target.verify(signature: signature, body: record.body, domain: "YTA-REGISTRY-RECORD-OLD-V1")
                }
                if let signature = record.newSignature {
                    guard let new = record.new else { throw SuppliedRegistryHistoryError.replay }
                    try new.verify(signature: signature, body: record.body, domain: "YTA-REGISTRY-RECORD-NEW-V1")
                }
                if let new = record.new { introduced.append(new); statuses.append("active") }
                tip = ProtocolGrammar.sha256(record.bytes)
                descriptor = record.descriptor
            }
            let keys = zip(introduced, statuses).map { SuppliedRegistryKey(tuple: $0.0, status: $0.1) }
            return Self(revision: records.count, tip: tip, descriptor: descriptor, keys: keys)
        } catch { throw SuppliedRegistryHistoryError.replay }
    }
}

struct SuppliedRegistryCanonicalObject {
    static let fieldNames = [
        "schema_version", "record_type", "transition_kind", "registry_revision",
        "previous_record_sha256", "request_sha256", "proposal_sha256", "acceptance_sha256",
        "challenge_sha256", "artifact_descriptor_sha256", "recovery_evidence_sha256",
        "requested_at", "accepted_at", "committed_at", "target_generation", "target_key_id",
        "target_key_tag", "target_spki", "target_fingerprint_sha256", "target_previous_status",
        "target_new_status", "new_generation", "new_key_id", "new_key_tag", "new_spki",
        "new_fingerprint_sha256", "new_status", "revokes_all_prior", "old_signature", "new_signature",
    ]

    let bytes: Data
    let body: Data
    let fields: [String: JSONNode]

    init(
        bytes: Data,
        fieldNames: [String] = Self.fieldNames,
        maximumBytes: Int = SuppliedRegistryBounds.maximumRecordBytes,
        signatureFields: [String] = ["old_signature", "new_signature"]
    ) throws {
        guard bytes.allSatisfy({ (0x20...0x7E).contains($0) && $0 != 0x5C })
        else { throw SuppliedRegistryHistoryError.encoding }
        var parser = try BoundedJSONParser(data: bytes, maximumBytes: maximumBytes)
        let node = try parser.parse()
        let fields = try node.exactObject(fieldNames)
        guard JSONCanonicalEncoder.encode(node) == bytes, case let .object(members) = node
        else { throw SuppliedRegistryHistoryError.encoding }
        for member in members {
            switch (member.name, member.value) {
            case (_, .null): break
            case ("schema_version", .unsigned), ("registry_revision", .unsigned), ("expected_registry_revision", .unsigned): break
            case ("revokes_all_prior", .boolean), ("accepted", .boolean): break
            case (let name, .string) where !["schema_version", "registry_revision", "expected_registry_revision", "revokes_all_prior", "accepted"].contains(name): break
            default: throw SuppliedRegistryHistoryError.encoding
            }
        }
        self.bytes = bytes
        // exactObject pins the full order; keep the signed-body extraction's
        // signature-suffix assumption explicit at the point of use.
        guard members.suffix(signatureFields.count).map(\.name) == signatureFields
        else { throw SuppliedRegistryHistoryError.encoding }
        body = JSONCanonicalEncoder.encode(.object(Array(members.dropLast(signatureFields.count))))
        self.fields = fields
    }

    func string(_ name: String) throws -> String {
        guard let result = fields[name]?.string else { throw SuppliedRegistryHistoryError.grammar }
        return result
    }

    func optionalString(_ name: String) throws -> String? {
        if case .null? = fields[name] { return nil }
        return try string(name)
    }

    func digest(_ name: String, optional: Bool = false) throws -> String? {
        let value = try optional ? optionalString(name) : string(name)
        guard value.map(ProtocolGrammar.isDigest) ?? optional else { throw SuppliedRegistryHistoryError.grammar }
        return value
    }
}

struct SuppliedRegistryRecord {
    let bytes: Data
    let body: Data
    let kind: String
    let revision: Int
    let previous: String
    let descriptor: String
    let recoveryDigest: String?
    let requested: Int64
    let accepted: Int64
    let committed: Int64
    let target: SuppliedRegistryTuple?
    let new: SuppliedRegistryTuple?
    let targetPreviousStatus: String?
    let targetNewStatus: String?
    let newStatus: String?
    let revokesAll: Bool
    let oldSignature: P256Signature?
    let newSignature: P256Signature?

    init(object: SuppliedRegistryCanonicalObject) throws {
        guard object.body.count <= SuppliedRegistryBounds.maximumBodyBytes, object.fields["schema_version"]?.uint64 == 1,
              try object.string("record_type") == "approval_registry_transition",
              let revision = object.fields["registry_revision"]?.uint64,
              (1...UInt64(SuppliedRegistryBounds.maximumRecords)).contains(revision),
              case let .boolean(revokesAll)? = object.fields["revokes_all_prior"]
        else { throw SuppliedRegistryHistoryError.grammar }
        let kind = try object.string("transition_kind")
        guard ["enroll", "rotate", "revoke", "recover"].contains(kind) else { throw SuppliedRegistryHistoryError.grammar }
        for name in ["previous_record_sha256", "request_sha256", "proposal_sha256", "acceptance_sha256", "challenge_sha256", "artifact_descriptor_sha256"] {
            _ = try object.digest(name)
        }
        func time(_ name: String) throws -> Int64 {
            guard let seconds = SuppliedRegistryCalendar.seconds(try object.string(name))
            else { throw SuppliedRegistryHistoryError.grammar }
            return seconds
        }
        func status(_ name: String) throws -> String? {
            let value = try object.optionalString(name)
            guard value == nil || ["active", "retained", "revoked"].contains(value!)
            else { throw SuppliedRegistryHistoryError.grammar }
            return value
        }
        func signature(_ name: String) throws -> P256Signature? {
            guard let value = try object.optionalString(name) else { return nil }
            return try P256Signature(derBase64URL: value)
        }
        let new = try SuppliedRegistryTuple.decodeTuple(object: object, prefix: "new")
        guard new == nil || ProtocolGrammar.keyGenerationRevision(new!.generation) == Int(revision)
        else { throw SuppliedRegistryHistoryError.grammar }
        bytes = object.bytes
        body = object.body
        self.kind = kind
        self.revision = Int(revision)
        previous = try object.string("previous_record_sha256")
        descriptor = try object.string("artifact_descriptor_sha256")
        recoveryDigest = try object.digest("recovery_evidence_sha256", optional: true)
        requested = try time("requested_at")
        accepted = try time("accepted_at")
        committed = try time("committed_at")
        target = try SuppliedRegistryTuple.decodeTuple(object: object, prefix: "target")
        self.new = new
        targetPreviousStatus = try status("target_previous_status")
        targetNewStatus = try status("target_new_status")
        newStatus = try status("new_status")
        self.revokesAll = revokesAll
        oldSignature = try signature("old_signature")
        newSignature = try signature("new_signature")
    }
}

struct SuppliedRegistryTuple: Equatable {
    private static let spkiBase64URLByteCount = (P256PublicKeyCodec.spkiByteCount * 8 + 5) / 6

    let generation: String
    let keyID: String
    let keyTag: String
    let spki: String
    let fingerprintSHA256: String
    private let x963: Data

    static func decodeTuple(object: SuppliedRegistryCanonicalObject, prefix: String) throws -> Self? {
        let names = ["generation", "key_id", "key_tag", "spki", "fingerprint_sha256"]
        let values = try names.map { try object.optionalString(prefix + "_" + $0) }
        if values.allSatisfy({ $0 == nil }) { return nil }
        guard values.allSatisfy({ $0 != nil }) else { throw SuppliedRegistryHistoryError.grammar }
        let generation = values[0]!, keyID = values[1]!, keyTag = values[2]!, spki = values[3]!, fingerprint = values[4]!
        guard ProtocolGrammar.isKeyGeneration(generation), keyID.utf8.count == 32,
              keyID.utf8.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }),
              keyTag == "io.github.abigotado.youtrack-agent.approval.signing.v1/" + keyID,
              ProtocolGrammar.isDigest(fingerprint), spki.utf8.count == Self.spkiBase64URLByteCount,
              spki.utf8.allSatisfy({ ProtocolGrammar.isASCIIAlphanumeric($0) || $0 == 0x2D || $0 == 0x5F })
        else { throw SuppliedRegistryHistoryError.grammar }
        let padded = spki.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") +
            String(repeating: "=", count: (4 - Self.spkiBase64URLByteCount % 4) % 4)
        guard let der = Data(base64Encoded: padded), der.count == P256PublicKeyCodec.spkiByteCount,
              der.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == spki,
              ProtocolGrammar.sha256(der) == fingerprint
        else { throw SuppliedRegistryHistoryError.grammar }
        return Self(generation: generation, keyID: keyID, keyTag: keyTag, spki: spki,
                    fingerprintSHA256: fingerprint, x963: try P256PublicKeyCodec.x963(fromSPKIDER: der))
    }

    func verify(signature: P256Signature, body: Data, domain: String) throws {
        var message = Data(domain.utf8)
        message.append(0)
        message.append(body)
        guard try P256PublicKeyCodec.verify(message: message, derSignature: signature.der, x963: x963)
        else { throw SuppliedRegistryHistoryError.replay }
    }
}

/// Registry-only four-digit proleptic Gregorian whole-second UTC grammar.
/// Year zero is valid here; receipt calendars intentionally have another range.
enum SuppliedRegistryCalendar {
    static func seconds(_ value: String) -> Int64? {
        let bytes = Array(value.utf8)
        guard bytes.count == 20, bytes[4] == 45, bytes[7] == 45, bytes[10] == 84,
              bytes[13] == 58, bytes[16] == 58, bytes[19] == 90 else { return nil }
        func number(_ start: Int, _ end: Int) -> Int64? {
            var result: Int64 = 0
            for byte in bytes[start..<end] {
                guard (48...57).contains(byte) else { return nil }
                result = result * 10 + Int64(byte - 48)
            }
            return result
        }
        guard let year = number(0, 4), let month = number(5, 7), let day = number(8, 10),
              let hour = number(11, 13), let minute = number(14, 16), let second = number(17, 19),
              (1...12).contains(month), hour <= 23, minute <= 59, second <= 59 else { return nil }
        let leap = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)
        let monthDays: [Int64] = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard (1...monthDays[Int(month) - 1]).contains(day) else { return nil }
        // Nonnegative year arithmetic also handles year zero without a negative
        // division convention or Foundation's historical calendar normalization.
        let daysBeforeYear = 365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400
        let daysBeforeMonth = monthDays.prefix(Int(month) - 1).reduce(0, +)
        return (daysBeforeYear + daysBeforeMonth + day - 1 - 719_528) * 86_400 + hour * 3_600 + minute * 60 + second
    }
}
