import struct Foundation.Data

/// Local canonical syntax only. References are not resolved or authenticated;
/// neither this value nor its digest grants authority or proves host isolation.
public struct IsolatedBinding: Equatable, Sendable {
    public static let schemaVersion = 1
    public static let objectType = "gate1b_isolated_binding_v1"
    public static let maximumBytes = 4_096

    public let descriptorSHA256: String
    public let coverageInventorySHA256: String
    public let unitDefinitionSHA256: String
    public let pass: String
    public let architecture: String
    public let hostInventorySHA256: String
    public let targetAllocationSHA256: String
    public let gateTargetSHA256: String

    public init(canonicalBytes: Data) throws {
        var parser = try StrictJSONObjectParser(data: canonicalBytes, maximumBytes: Self.maximumBytes)
        var fields: [String: StrictJSONValue]
        do {
            fields = try parser.parse()
        } catch {
            // The shared parser's duplicate-field error contains untrusted text.
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

        guard fields.removeValue(forKey: "schema_version") == .integer(Self.schemaVersion) else {
            throw ApprovalProtocolError.invalidField("schema_version")
        }
        guard try takeString("object_type") == Self.objectType else {
            throw ApprovalProtocolError.invalidField("object_type")
        }
        descriptorSHA256 = try takeString("descriptor_sha256")
        coverageInventorySHA256 = try takeString("coverage_inventory_sha256")
        unitDefinitionSHA256 = try takeString("unit_definition_sha256")
        pass = try takeString("pass")
        architecture = try takeString("architecture")
        hostInventorySHA256 = try takeString("host_inventory_sha256")
        targetAllocationSHA256 = try takeString("target_allocation_sha256")
        gateTargetSHA256 = try takeString("gate_target_sha256")
        guard fields.isEmpty else { throw ApprovalProtocolError.malformedJSON }
        guard pass == "e1" || pass == "e2" else {
            throw ApprovalProtocolError.invalidField("pass")
        }
        guard architecture == "arm64" || architecture == "x86_64" else {
            throw ApprovalProtocolError.invalidField("architecture")
        }
        guard [descriptorSHA256, coverageInventorySHA256, unitDefinitionSHA256,
               hostInventorySHA256, targetAllocationSHA256, gateTargetSHA256]
            .allSatisfy(ProtocolGrammar.isDigest)
        else { throw ApprovalProtocolError.invalidField("binding digest") }
        guard encodedCanonicalBytes() == canonicalBytes else {
            throw ApprovalProtocolError.nonCanonicalEncoding
        }
    }

    public func encodedCanonicalBytes() -> Data {
        // All values have a fixed ASCII grammar; none can require escaping.
        Data(("{\"schema_version\":1,\"object_type\":\"\(Self.objectType)\"," +
            "\"descriptor_sha256\":\"\(descriptorSHA256)\"," +
            "\"coverage_inventory_sha256\":\"\(coverageInventorySHA256)\"," +
            "\"unit_definition_sha256\":\"\(unitDefinitionSHA256)\"," +
            "\"pass\":\"\(pass)\",\"architecture\":\"\(architecture)\"," +
            "\"host_inventory_sha256\":\"\(hostInventorySHA256)\"," +
            "\"target_allocation_sha256\":\"\(targetAllocationSHA256)\"," +
            "\"gate_target_sha256\":\"\(gateTargetSHA256)\"}").utf8)
    }

    /// Plain SHA-256 over exact canonical bytes, not an authority verdict.
    public var bindingSHA256: String {
        ProtocolGrammar.sha256(encodedCanonicalBytes())
    }
}
