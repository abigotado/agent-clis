import struct Foundation.Data

public struct PlanBindings: Equatable, Sendable {
    public let planID: String
    public let planSHA256: String
    public let profileIdentitySHA256: String
    public let accountID: String
    public let projectID: String
    public let projectKey: String
    public let schemaSHA256: String
    public let requestSHA256: String
    public let expectedSHA256: String
}

public struct ValidatedPlanSnapshot: Equatable, Sendable {
    public static let maximumBytes = 512 << 10

    private let storage: Data
    public let bindings: PlanBindings

    public init(canonicalBytes input: Data) throws {
        guard !input.isEmpty, input.count <= Self.maximumBytes else {
            throw ApprovalProtocolError.inputTooLarge(limit: Self.maximumBytes)
        }
        let copied = input.withUnsafeBytes { Data($0) }
        var parser = try BoundedJSONParser(data: copied, maximumBytes: Self.maximumBytes)
        let root = try parser.parse()
        guard JSONCanonicalEncoder.encode(root) == copied else { throw ApprovalProtocolError.nonCanonicalEncoding }
        bindings = try PlanValidator.validate(root, exactBytes: copied)
        storage = copied
    }

    public var byteCount: Int { storage.count }
    public var inertEscapedBytes: String { InertByteCodec.encode(storage) }
    public var sha256: String { bindings.planSHA256 }

    func exactBytes() -> Data { storage }
}

private enum PlanValidator {
    static func validate(_ root: JSONNode, exactBytes: Data) throws -> PlanBindings {
        let plan = try root.exactObject([
            "schema_version", "plan_id", "kind", "profile", "policy", "operation",
            "request_sha256", "expected_sha256",
        ])
        guard plan["schema_version"]?.uint64 == 1,
              let planID = plan["plan_id"]?.string, ProtocolGrammar.isCanonicalBase32ID(planID, prefix: "YTAP-"),
              let kind = plan["kind"]?.string,
              ["issue.create", "issue.update", "comment.add"].contains(kind),
              let requestDigest = plan["request_sha256"]?.string, ProtocolGrammar.isDigest(requestDigest),
              let expectedDigest = plan["expected_sha256"]?.string, ProtocolGrammar.isDigest(expectedDigest),
              let profileNode = plan["profile"], let policyNode = plan["policy"], let operationNode = plan["operation"]
        else { throw ApprovalProtocolError.invalidField("plan") }

        let profile = try validateProfile(profileNode)
        let policy = try validatePolicy(policyNode, kind: kind)
        let operation = try validateOperation(operationNode, kind: kind, planID: planID)
        guard ProtocolGrammar.sha256(JSONCanonicalEncoder.encode(operation.request)) == requestDigest,
              ProtocolGrammar.sha256(JSONCanonicalEncoder.encode(operation.expected)) == expectedDigest
        else { throw ApprovalProtocolError.invalidField("request/expected digest") }

        return PlanBindings(
            planID: planID,
            planSHA256: ProtocolGrammar.sha256(exactBytes),
            profileIdentitySHA256: profile.identity,
            accountID: profile.accountID,
            projectID: policy.projectID,
            projectKey: policy.projectKey,
            schemaSHA256: policy.schema,
            requestSHA256: requestDigest,
            expectedSHA256: expectedDigest
        )
    }

    private static func validateProfile(_ node: JSONNode) throws -> (identity: String, accountID: String) {
        let value = try node.exactObject([
            "name", "instance", "rest_base_url", "oauth_issuer_url", "identity_sha256",
            "credential_generation", "account",
        ])
        guard let name = value["name"]?.string, isName(name),
              let instance = value["instance"]?.string, isURL(instance),
              let rest = value["rest_base_url"]?.string, rest == instance + "/api", rest.utf8.count <= 2048,
              let issuer = value["oauth_issuer_url"]?.string, isURL(issuer),
              let identity = value["identity_sha256"]?.string, ProtocolGrammar.isDigest(identity),
              let generation = value["credential_generation"]?.string, isBoundString(generation, max: 256),
              let accountNode = value["account"]
        else { throw ApprovalProtocolError.invalidField("profile") }
        let account = try accountNode.exactObject(["id", "login"])
        guard let id = account["id"]?.string, ProtocolGrammar.isIdentifier(id),
              let login = account["login"]?.string, isBoundString(login, max: 256)
        else { throw ApprovalProtocolError.invalidField("account") }
        return (identity, id)
    }

    private static func validatePolicy(_ node: JSONNode, kind: String) throws -> (projectID: String, projectKey: String, schema: String) {
        let value = try node.exactObject([
            "project", "policy_revision", "policy_sha256", "schema_sha256", "executor_assurance",
            "authorized_capability", "notification_policy", "reconciliation_strategy",
        ])
        let expectedCapability = ["issue.create": "issue-create", "issue.update": "issue-update", "comment.add": "comment-add"][kind]
        guard let revision = value["policy_revision"]?.uint64, revision > 0,
              let policyDigest = value["policy_sha256"]?.string, ProtocolGrammar.isDigest(policyDigest),
              let schema = value["schema_sha256"]?.string, ProtocolGrammar.isDigest(schema),
              let assurance = value["executor_assurance"]?.string,
              ["rest-best-effort", "custom-mcp-atomic"].contains(assurance),
              value["authorized_capability"]?.string == expectedCapability,
              value["notification_policy"]?.string == "youtrack-default",
              value["reconciliation_strategy"]?.string == "bounded-exact-and-marker",
              let projectNode = value["project"]
        else { throw ApprovalProtocolError.invalidField("policy") }
        let project = try projectNode.exactObject(["id", "key"])
        guard let id = project["id"]?.string, ProtocolGrammar.isIdentifier(id),
              let key = project["key"]?.string, ProtocolGrammar.isProjectKey(key)
        else { throw ApprovalProtocolError.invalidField("project") }
        return (id, key, schema)
    }

    private static func validateOperation(_ node: JSONNode, kind: String, planID: String) throws -> (request: JSONNode, expected: JSONNode) {
        let key = kind == "issue.create" ? "issue_create" : (kind == "issue.update" ? "issue_update" : "comment_add")
        let operation = try node.exactObject([key])
        let pair = try operation[key]!.exactObject(["request", "expected"])
        let request = pair["request"]!, expected = pair["expected"]!
        switch kind {
        case "issue.create": try validateCreate(request, expected, planID: planID)
        case "issue.update": try validateUpdate(request, expected)
        default: try validateComment(request, expected, planID: planID)
        }
        return (request, expected)
    }

    private static func validateCreate(_ request: JSONNode, _ expected: JSONNode, planID: String) throws {
        guard case let .object(pairs) = request else { throw ApprovalProtocolError.invalidField("issue_create") }
        let keys = pairs.map(\.name)
        guard keys == ["summary", "description", "visibility", "marker"] ||
                keys == ["summary", "description", "visibility", "custom_fields", "marker"]
        else { throw ApprovalProtocolError.invalidField("issue_create") }
        let value = Dictionary(uniqueKeysWithValues: pairs.map { ($0.name, $0.value) })
        guard let summary = value["summary"]?.string, isRequiredText(summary, max: 1_024),
              let description = value["description"]?.string, isText(description, min: 0, max: 32 << 10),
              let visibility = value["visibility"], let marker = value["marker"]?.string
        else { throw ApprovalProtocolError.invalidField("issue_create") }
        try validateVisibility(visibility)
        try validateFields(value["custom_fields"])
        try validateMarker(marker, body: description, planID: planID)
        let exp = try expected.exactObject(["project_state_sha256"])
        guard let hash = exp["project_state_sha256"]?.string, ProtocolGrammar.isDigest(hash) else { throw ApprovalProtocolError.invalidField("expected") }
    }

    private static func validateUpdate(_ request: JSONNode, _ expected: JSONNode) throws {
        let value = try request.exactObject(["issue_id", "set"])
        guard let issueID = value["issue_id"]?.string, isIssueID(issueID),
              case let .object(pairs)? = value["set"], !pairs.isEmpty
        else { throw ApprovalProtocolError.invalidField("issue_update") }
        let allowed = ["summary", "description", "custom_fields"]
        let indexes = pairs.compactMap { allowed.firstIndex(of: $0.name) }
        guard indexes.count == pairs.count, indexes == indexes.sorted(), Set(indexes).count == indexes.count else {
            throw ApprovalProtocolError.invalidField("issue_update.set")
        }
        let patch = Dictionary(uniqueKeysWithValues: pairs.map { ($0.name, $0.value) })
        if let summary = patch["summary"]?.string, !isRequiredText(summary, max: 1_024) { throw ApprovalProtocolError.invalidField("summary") }
        if patch["summary"] != nil && patch["summary"]?.string == nil { throw ApprovalProtocolError.invalidField("summary") }
        if let description = patch["description"]?.string, !isText(description, min: 0, max: 32 << 10) { throw ApprovalProtocolError.invalidField("description") }
        if patch["description"] != nil && patch["description"]?.string == nil { throw ApprovalProtocolError.invalidField("description") }
        try validateFields(patch["custom_fields"])
        let exp = try expected.exactObject(["issue_id", "issue_state_sha256", "touched_fields_sha256"])
        guard exp["issue_id"]?.string == issueID,
              let state = exp["issue_state_sha256"]?.string, ProtocolGrammar.isDigest(state),
              let touched = exp["touched_fields_sha256"]?.string, ProtocolGrammar.isDigest(touched)
        else { throw ApprovalProtocolError.invalidField("expected") }
    }

    private static func validateComment(_ request: JSONNode, _ expected: JSONNode, planID: String) throws {
        let value = try request.exactObject(["issue_id", "text", "visibility", "marker"])
        guard let issueID = value["issue_id"]?.string, isIssueID(issueID),
              let text = value["text"]?.string, isText(text, min: 1, max: 32 << 10),
              let visibility = value["visibility"], let marker = value["marker"]?.string
        else { throw ApprovalProtocolError.invalidField("comment") }
        try validateVisibility(visibility)
        try validateMarker(marker, body: text, planID: planID)
        let original = marker == "visible_footer" ? stripMarker(text, planID: planID) : text
        guard isRequiredText(original, max: 32 << 10) else { throw ApprovalProtocolError.invalidField("comment text") }
        let exp = try expected.exactObject(["issue_id", "issue_state_sha256"])
        guard exp["issue_id"]?.string == issueID,
              let hash = exp["issue_state_sha256"]?.string, ProtocolGrammar.isDigest(hash)
        else { throw ApprovalProtocolError.invalidField("expected") }
    }

    private static func validateVisibility(_ node: JSONNode) throws {
        guard case let .object(pairs) = node else { throw ApprovalProtocolError.invalidField("visibility") }
        let value = Dictionary(uniqueKeysWithValues: pairs.map { ($0.name, $0.value) })
        if pairs.map(\.name) == ["mode"], value["mode"]?.string == "public" { return }
        guard pairs.map(\.name) == ["mode", "group_ids"], value["mode"]?.string == "restricted",
              let groups = value["group_ids"]?.array, (1...32).contains(groups.count)
        else { throw ApprovalProtocolError.invalidField("visibility") }
        let ids = groups.compactMap(\.string)
        guard ids.count == groups.count, ids.allSatisfy(ProtocolGrammar.isIdentifier), ids == ids.sorted(), Set(ids).count == ids.count else {
            throw ApprovalProtocolError.invalidField("visibility")
        }
    }

    private static func validateFields(_ node: JSONNode?) throws {
        guard let node else { return }
        guard let fields = node.array, !fields.isEmpty, fields.count <= 100 else { throw ApprovalProtocolError.invalidField("custom_fields") }
        var previous = ""
        for fieldNode in fields {
            guard case let .object(pairs) = fieldNode else { throw ApprovalProtocolError.invalidField("custom_field") }
            let keys = pairs.map(\.name)
            guard keys == ["field_id", "field_type", "value_id"] || keys == ["field_id", "field_type", "text_value"] else {
                throw ApprovalProtocolError.invalidField("custom_field")
            }
            let field = Dictionary(uniqueKeysWithValues: pairs.map { ($0.name, $0.value) })
            guard let id = field["field_id"]?.string, ProtocolGrammar.isIdentifier(id), id > previous,
                  let type = field["field_type"]?.string, isBoundString(type, max: 128)
            else { throw ApprovalProtocolError.invalidField("custom_field") }
            if let valueID = field["value_id"]?.string, !ProtocolGrammar.isIdentifier(valueID) { throw ApprovalProtocolError.invalidField("value_id") }
            if field["value_id"] != nil && field["value_id"]?.string == nil { throw ApprovalProtocolError.invalidField("value_id") }
            if let text = field["text_value"]?.string, !isText(text, min: 0, max: 8 << 10) { throw ApprovalProtocolError.invalidField("text_value") }
            if field["text_value"] != nil && field["text_value"]?.string == nil { throw ApprovalProtocolError.invalidField("text_value") }
            previous = id
        }
    }

    private static func validateMarker(_ marker: String, body: String, planID: String) throws {
        let prefix = Array("Agent plan: ".utf8)
        let exact = prefix + Array(planID.utf8)
        let bodyBytes = Array(body.utf8)
        if marker == "none" {
            guard occurrences(of: prefix, in: bodyBytes) == 0 else { throw ApprovalProtocolError.invalidField("marker") }
        } else if marker == "visible_footer" {
            let footer = [UInt8(0x0A), 0x0A] + exact
            guard (bodyBytes == exact || bodyBytes.suffix(footer.count).elementsEqual(footer)),
                  occurrences(of: prefix, in: bodyBytes) == 1
            else {
                throw ApprovalProtocolError.invalidField("marker")
            }
        } else { throw ApprovalProtocolError.invalidField("marker") }
    }

    private static func stripMarker(_ body: String, planID: String) -> String {
        let marker = Array(("Agent plan: " + planID).utf8)
        let bytes = Array(body.utf8)
        if bytes == marker { return "" }
        return String(decoding: bytes.dropLast(marker.count + 2), as: UTF8.self)
    }

    private static func occurrences(of needle: [UInt8], in bytes: [UInt8]) -> Int {
        guard !needle.isEmpty, bytes.count >= needle.count else { return 0 }
        var count = 0
        for offset in 0...(bytes.count - needle.count) where bytes[offset..<(offset + needle.count)].elementsEqual(needle) {
            count += 1
        }
        return count
    }

    private static func isURL(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 2048, bytes.allSatisfy({ $0 < 0x80 }), value.hasPrefix("https://") else { return false }
        let remainder = String(value.dropFirst(8))
        let slash = remainder.firstIndex(of: "/")
        let authority = slash.map { String(remainder[..<$0]) } ?? remainder
        let path = slash.map { String(remainder[$0...]) } ?? ""
        guard !authority.isEmpty, !authority.contains("@"), !authority.contains("["), !authority.contains("]") else { return false }
        let pieces = authority.split(separator: ":", omittingEmptySubsequences: false)
        guard pieces.count <= 2 else { return false }
        let host = String(pieces[0])
        if pieces.count == 2 {
            let port = String(pieces[1])
            guard !port.isEmpty, port.first != "0", let number = UInt16(port), number > 0, number != 443,
                  port.allSatisfy({ $0.isASCII && $0.isNumber }) else { return false }
        }
        guard isHost(host), isPath(path) else { return false }
        return true
    }

    private static func isHost(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count == 4, parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) {
            return parts.allSatisfy { part in
                (part == "0" || part.first != "0") && (Int(part) ?? 256) <= 255
            }
        }
        guard !host.isEmpty, host.utf8.count <= 253, !host.hasSuffix("."), !parts.isEmpty else { return false }
        return parts.allSatisfy { label in
            (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-" && label.allSatisfy {
                ($0 >= "a" && $0 <= "z") || $0.isNumber || $0 == "-"
            }
        }
    }

    private static func isPath(_ path: String) -> Bool {
        if path.isEmpty { return true }
        guard path.first == "/", !path.hasSuffix("/"), !path.contains("//") else { return false }
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@".utf8)
        return path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy { segment in
            segment != "." && segment != ".." && !segment.isEmpty && segment.utf8.allSatisfy(allowed.contains)
        }
    }

    private static func isName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return (1...64).contains(bytes.count) && ProtocolGrammar.isASCIIAlphanumeric(bytes[0]) &&
            bytes.dropFirst().allSatisfy {
                ProtocolGrammar.isASCIIAlphanumeric($0) || [0x2E, 0x5F, 0x2D].contains($0)
            }
    }
    private static func isIssueID(_ value: String) -> Bool {
        guard let dash = value.lastIndex(of: "-") else { return false }
        let key = String(value[..<dash]), number = String(value[value.index(after: dash)...])
        return ProtocolGrammar.isProjectKey(key) && !number.isEmpty && number.first != "0" && number.allSatisfy { $0.isASCII && $0.isNumber }
    }
    private static func isText(_ value: String, min: Int, max: Int) -> Bool { value.utf8.count >= min && value.utf8.count <= max && !value.contains("\0") }
    private static func isRequiredText(_ value: String, max: Int) -> Bool {
        isText(value, min: 1, max: max) && value.unicodeScalars.contains(where: { !isGoSpace($0) })
    }
    private static func isBoundString(_ value: String, max: Int) -> Bool {
        guard isText(value, min: 1, max: max), let first = value.unicodeScalars.first,
              let last = value.unicodeScalars.last
        else { return false }
        return !isGoSpace(first) && !isGoSpace(last)
    }
    private static func isGoSpace(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x0009...0x000D, 0x0020, 0x0085, 0x00A0, 0x1680,
             0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000:
            true
        default:
            false
        }
    }
}
