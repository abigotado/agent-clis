import struct Foundation.Data

/// Immutable canonical syntax and bounded count domains only. Counts and hashes
/// do not prove relationships, compiled trees, reference closure, files or authority.
public struct IsolatedSegmentContract: Equatable, Sendable {
    public static let schemaVersion = 1
    public static let objectType = "gate1b_isolated_segment_contract_v1"
    public static let maximumBytes = 4_096

    public let segmentOrdinal: Int
    public let mode: String
    public let commandContractSHA256: String
    public let fixtureSetSHA256: String
    public let assertionSetSHA256: String
    public let transcriptSetSHA256: String
    public let operationCount: Int
    public let observationCount: Int
    public let transcriptCount: Int
    public let assertionCount: Int
    public let fileCount: Int
    public let maximumEvidenceBytes: Int

    public init(canonicalBytes: Data) throws {
        var parser = try StrictJSONObjectParser(data: canonicalBytes, maximumBytes: Self.maximumBytes)
        var fields: [String: StrictJSONValue]
        do {
            fields = try parser.parse()
        } catch {
            // The shared parser can include an attacker-controlled duplicate key.
            throw ApprovalProtocolError.malformedJSON
        }

        func takeString(_ name: String) throws -> String {
            guard let value = fields.removeValue(forKey: name) else {
                throw ApprovalProtocolError.missingField(name)
            }
            guard case let .string(string) = value else {
                throw ApprovalProtocolError.invalidField(name)
            }
            return string
        }

        func takeInteger(_ name: String, range: ClosedRange<Int>) throws -> Int {
            guard let value = fields.removeValue(forKey: name) else {
                throw ApprovalProtocolError.missingField(name)
            }
            guard case let .integer(integer) = value, range.contains(integer) else {
                throw ApprovalProtocolError.invalidField(name)
            }
            return integer
        }

        guard fields.removeValue(forKey: "schema_version") == .integer(Self.schemaVersion) else {
            throw ApprovalProtocolError.invalidField("schema_version")
        }
        guard try takeString("object_type") == Self.objectType else {
            throw ApprovalProtocolError.invalidField("object_type")
        }
        segmentOrdinal = try takeInteger("segment_ordinal", range: 1...2)
        mode = try takeString("mode")
        commandContractSHA256 = try takeString("command_contract_sha256")
        fixtureSetSHA256 = try takeString("fixture_set_sha256")
        assertionSetSHA256 = try takeString("assertion_set_sha256")
        transcriptSetSHA256 = try takeString("transcript_set_sha256")
        operationCount = try takeInteger("operation_count", range: 1...128)
        observationCount = try takeInteger("observation_count", range: 1...256)
        transcriptCount = try takeInteger("transcript_count", range: 1...2_048)
        assertionCount = try takeInteger("assertion_count", range: 1...256)
        fileCount = try takeInteger("file_count", range: 1...4_096)
        maximumEvidenceBytes = try takeInteger("maximum_evidence_bytes", range: 1...268_435_456)
        guard fields.isEmpty else { throw ApprovalProtocolError.malformedJSON }
        guard (segmentOrdinal == 1 && mode == "scenario") ||
              (segmentOrdinal == 2 && mode == "reboot_observer")
        else { throw ApprovalProtocolError.invalidField("segment_ordinal/mode") }
        guard [commandContractSHA256, fixtureSetSHA256, assertionSetSHA256, transcriptSetSHA256]
            .allSatisfy(ProtocolGrammar.isDigest)
        else { throw ApprovalProtocolError.invalidField("segment contract digest") }
        guard encodedCanonicalBytes() == canonicalBytes else {
            throw ApprovalProtocolError.nonCanonicalEncoding
        }
    }

    /// Returns exact canonical bytes; all stored strings use fixed ASCII grammars.
    public func encodedCanonicalBytes() -> Data {
        Data(("{\"schema_version\":1,\"object_type\":\"\(Self.objectType)\"," +
            "\"segment_ordinal\":\(segmentOrdinal),\"mode\":\"\(mode)\"," +
            "\"command_contract_sha256\":\"\(commandContractSHA256)\"," +
            "\"fixture_set_sha256\":\"\(fixtureSetSHA256)\"," +
            "\"assertion_set_sha256\":\"\(assertionSetSHA256)\"," +
            "\"transcript_set_sha256\":\"\(transcriptSetSHA256)\"," +
            "\"operation_count\":\(operationCount),\"observation_count\":\(observationCount)," +
            "\"transcript_count\":\(transcriptCount),\"assertion_count\":\(assertionCount)," +
            "\"file_count\":\(fileCount),\"maximum_evidence_bytes\":\(maximumEvidenceBytes)}").utf8)
    }

    /// Plain SHA-256 over exact canonical bytes, not an authority verdict.
    public var segmentContractSHA256: String {
        ProtocolGrammar.sha256(encodedCanonicalBytes())
    }
}
