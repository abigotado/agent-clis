import struct Foundation.Data

public struct UnsignedApprovalReceipt: Equatable, Sendable {
    public static let schemaVersion = 3
    public static let maximumSigningBytes = 3_072

    public let receiptID: String
    public let nonce: String
    public let challengeSHA256: String
    public let registryRevision: Int
    public let authorizationContextSHA256: String
    public let planID: String
    public let planSHA256: String
    public let profileIdentitySHA256: String
    public let accountID: String
    public let projectID: String
    public let projectKey: String
    public let schemaSHA256: String
    public let requestSHA256: String
    public let expectedSHA256: String
    public let issuedAt: String
    public let expiresAt: String
    public let keyGeneration: String
    public let keyFingerprintSHA256: String

    init(
        receiptID: String, nonce: String, challengeSHA256: String,
        registryRevision: Int, authorizationContextSHA256: String, planID: String, planSHA256: String,
        profileIdentitySHA256: String, accountID: String, projectID: String,
        projectKey: String, schemaSHA256: String, requestSHA256: String,
        expectedSHA256: String, issuedAt: String, expiresAt: String,
        keyGeneration: String, keyFingerprintSHA256: String
    ) throws {
        self.receiptID = receiptID
        self.nonce = nonce
        self.challengeSHA256 = challengeSHA256
        self.registryRevision = registryRevision
        self.authorizationContextSHA256 = authorizationContextSHA256
        self.planID = planID
        self.planSHA256 = planSHA256
        self.profileIdentitySHA256 = profileIdentitySHA256
        self.accountID = accountID
        self.projectID = projectID
        self.projectKey = projectKey
        self.schemaSHA256 = schemaSHA256
        self.requestSHA256 = requestSHA256
        self.expectedSHA256 = expectedSHA256
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.keyGeneration = keyGeneration
        self.keyFingerprintSHA256 = keyFingerprintSHA256
        try validate()
        guard encodedSigningBytes().count <= Self.maximumSigningBytes else {
            throw ApprovalProtocolError.inputTooLarge(limit: Self.maximumSigningBytes)
        }
    }

    public init(signingBytes: Data) throws {
        guard signingBytes.count <= Self.maximumSigningBytes else {
            throw ApprovalProtocolError.inputTooLarge(limit: Self.maximumSigningBytes)
        }
        var fields: [String: StrictJSONValue]
        do {
            var parser = try StrictJSONObjectParser(data: signingBytes, maximumBytes: Self.maximumSigningBytes)
            fields = try parser.parse()
        } catch {
            // Decoder diagnostics may carry attacker-controlled duplicate keys.
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

        guard let version = fields.removeValue(forKey: "schema_version") else {
            throw ApprovalProtocolError.missingField("schema_version")
        }
        guard version == .integer(Self.schemaVersion) else {
            throw ApprovalProtocolError.invalidField("schema_version")
        }

        receiptID = try takeString("receipt_id")
        nonce = try takeString("nonce")
        challengeSHA256 = try takeString("challenge_sha256")
        guard let revisionValue = fields.removeValue(forKey: "registry_revision") else {
            throw ApprovalProtocolError.missingField("registry_revision")
        }
        guard case let .integer(revision) = revisionValue else {
            throw ApprovalProtocolError.invalidField("registry_revision")
        }
        registryRevision = revision
        authorizationContextSHA256 = try takeString("authorization_context_sha256")
        planID = try takeString("plan_id")
        planSHA256 = try takeString("plan_sha256")
        profileIdentitySHA256 = try takeString("profile_identity_sha256")
        accountID = try takeString("account_id")
        projectID = try takeString("project_id")
        projectKey = try takeString("project_key")
        schemaSHA256 = try takeString("schema_sha256")
        requestSHA256 = try takeString("request_sha256")
        expectedSHA256 = try takeString("expected_sha256")
        issuedAt = try takeString("issued_at")
        expiresAt = try takeString("expires_at")
        keyGeneration = try takeString("key_generation")
        keyFingerprintSHA256 = try takeString("key_fingerprint_sha256")

        if !fields.isEmpty {
            throw ApprovalProtocolError.malformedJSON
        }
        try validate()
        guard encodedSigningBytes() == signingBytes else {
            throw ApprovalProtocolError.nonCanonicalEncoding
        }
    }

    public func encodedSigningBytes() -> Data {
        var output = Data()
        output.reserveCapacity(Self.maximumSigningBytes)
        output.append(0x7B)
        appendInteger(name: "schema_version", value: Self.schemaVersion, first: true, into: &output)
        appendString(name: "receipt_id", value: receiptID, into: &output)
        appendString(name: "nonce", value: nonce, into: &output)
        appendString(name: "challenge_sha256", value: challengeSHA256, into: &output)
        appendInteger(name: "registry_revision", value: registryRevision, into: &output)
        appendString(name: "authorization_context_sha256", value: authorizationContextSHA256, into: &output)
        appendString(name: "plan_id", value: planID, into: &output)
        appendString(name: "plan_sha256", value: planSHA256, into: &output)
        appendString(name: "profile_identity_sha256", value: profileIdentitySHA256, into: &output)
        appendString(name: "account_id", value: accountID, into: &output)
        appendString(name: "project_id", value: projectID, into: &output)
        appendString(name: "project_key", value: projectKey, into: &output)
        appendString(name: "schema_sha256", value: schemaSHA256, into: &output)
        appendString(name: "request_sha256", value: requestSHA256, into: &output)
        appendString(name: "expected_sha256", value: expectedSHA256, into: &output)
        appendString(name: "issued_at", value: issuedAt, into: &output)
        appendString(name: "expires_at", value: expiresAt, into: &output)
        appendString(name: "key_generation", value: keyGeneration, into: &output)
        appendString(name: "key_fingerprint_sha256", value: keyFingerprintSHA256, into: &output)
        output.append(0x7D)
        return output
    }

    public var signingSHA256: String {
        Self.sha256Hex(encodedSigningBytes())
    }

    private func validate() throws {
        guard ProtocolGrammar.isCanonicalBase32ID(receiptID, prefix: "YTAR-"),
              ProtocolGrammar.isCanonicalBase32ID(nonce, prefix: "YTAN-")
        else {
            throw ApprovalProtocolError.invalidField("receipt_id/nonce")
        }
        for (name, value) in [
            ("challenge_sha256", challengeSHA256),
            ("authorization_context_sha256", authorizationContextSHA256),
            ("plan_sha256", planSHA256),
            ("profile_identity_sha256", profileIdentitySHA256),
            ("schema_sha256", schemaSHA256),
            ("request_sha256", requestSHA256),
            ("expected_sha256", expectedSHA256),
            ("key_fingerprint_sha256", keyFingerprintSHA256),
        ] where !ProtocolGrammar.isDigest(value) {
            throw ApprovalProtocolError.invalidField(name)
        }
        guard ProtocolGrammar.isCanonicalBase32ID(planID, prefix: "YTAP-") else { throw ApprovalProtocolError.invalidField("plan_id") }
        guard ProtocolGrammar.isIdentifier(accountID) else { throw ApprovalProtocolError.invalidField("account_id") }
        guard ProtocolGrammar.isIdentifier(projectID) else { throw ApprovalProtocolError.invalidField("project_id") }
        guard ProtocolGrammar.isProjectKey(projectKey) else { throw ApprovalProtocolError.invalidField("project_key") }
        guard (1...ProtocolGrammar.maximumRegistryRevision).contains(registryRevision) else {
            throw ApprovalProtocolError.invalidField("registry_revision")
        }
        guard ProtocolGrammar.keyGenerationRevision(keyGeneration) == registryRevision else {
            throw ApprovalProtocolError.invalidField("key_generation")
        }
        guard let issuedSeconds = Self.wholeSecondUTCValue(issuedAt),
              let expiresSeconds = Self.wholeSecondUTCValue(expiresAt),
              expiresSeconds > issuedSeconds,
              expiresSeconds - issuedSeconds <= 5 * 60
        else {
            throw ApprovalProtocolError.invalidField("issued_at/expires_at")
        }
    }

    static func wholeSecondUTCValue(_ value: String) -> Int64? {
        let bytes = Array(value.utf8)
        guard bytes.count == 20,
              bytes[4] == 0x2D, bytes[7] == 0x2D, bytes[10] == 0x54,
              bytes[13] == 0x3A, bytes[16] == 0x3A, bytes[19] == 0x5A
        else { return nil }
        for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
        where bytes[index] < 0x30 || bytes[index] > 0x39 {
            return nil
        }
        func number(_ start: Int, _ count: Int) -> Int {
            bytes[start..<(start + count)].reduce(0) { $0 * 10 + Int($1 - 0x30) }
        }
        let year = number(0, 4)
        let month = number(5, 2)
        let day = number(8, 2)
        let hour = number(11, 2)
        let minute = number(14, 2)
        let second = number(17, 2)
        guard year >= 1, (1...12).contains(month), hour <= 23, minute <= 59, second <= 59 else { return nil }
        let leap = year.isMultiple(of: 400) || (year.isMultiple(of: 4) && !year.isMultiple(of: 100))
        let days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard day >= 1, day <= days[month - 1] else { return nil }

        // Proleptic Gregorian days-from-civil calculation. It avoids locale,
        // formatter, and time-zone behavior in the canonical byte validator.
        let adjustedYear = year - (month <= 2 ? 1 : 0)
        let era = adjustedYear / 400
        let yearOfEra = adjustedYear - era * 400
        let shiftedMonth = month + (month > 2 ? -3 : 9)
        let dayOfYear = (153 * shiftedMonth + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        let civilDays = Int64(era * 146_097 + dayOfEra - 719_468)
        return civilDays * 86_400 + Int64(hour * 3_600 + minute * 60 + second)
    }

    fileprivate static func sha256Hex(_ data: Data) -> String {
        ProtocolGrammar.sha256(data)
    }
}

public struct ApprovalReceipt: Equatable, Sendable {
    public static let maximumReceiptBytes = 4_096

    public let unsigned: UnsignedApprovalReceipt
    public let signature: String

    public init(unsigned: UnsignedApprovalReceipt, signatureDER: Data) throws {
        let parsed = try P256Signature(der: signatureDER)
        self.unsigned = unsigned
        signature = parsed.base64URL
        guard encodedReceiptBytes().count <= Self.maximumReceiptBytes else {
            throw ApprovalProtocolError.inputTooLarge(limit: Self.maximumReceiptBytes)
        }
    }

    public init(unsigned: UnsignedApprovalReceipt, signatureBase64URL: String) throws {
        let parsed = try P256Signature(derBase64URL: signatureBase64URL)
        try self.init(unsigned: unsigned, signatureDER: parsed.der)
    }

    public init(receiptBytes: Data) throws {
        guard receiptBytes.count <= Self.maximumReceiptBytes else {
            throw ApprovalProtocolError.inputTooLarge(limit: Self.maximumReceiptBytes)
        }
        let signatureKey = Data(",\"signature\":".utf8)
        guard let closingBrace = receiptBytes.last, closingBrace == 0x7D,
              let split = receiptBytes.range(of: signatureKey, options: .backwards),
              split.upperBound < receiptBytes.index(before: receiptBytes.endIndex)
        else {
            throw ApprovalProtocolError.malformedJSON
        }
        var unsignedBytes = receiptBytes[..<split.lowerBound]
        unsignedBytes.append(0x7D)
        unsigned = try UnsignedApprovalReceipt(signingBytes: Data(unsignedBytes))

        let signatureValue = receiptBytes[split.upperBound..<receiptBytes.index(before: receiptBytes.endIndex)]
        var wrapper = Data("{\"signature\":".utf8)
        wrapper.append(signatureValue)
        wrapper.append(0x7D)
        let fields: [String: StrictJSONValue]
        do {
            var parser = try StrictJSONObjectParser(data: wrapper, maximumBytes: Self.maximumReceiptBytes)
            fields = try parser.parse()
        } catch {
            throw ApprovalProtocolError.malformedJSON
        }
        guard fields.count == 1, case let .string(parsed)? = fields["signature"] else {
            throw ApprovalProtocolError.invalidField("signature")
        }
        signature = parsed
        _ = try P256Signature(derBase64URL: signature)
        guard encodedReceiptBytes() == receiptBytes else {
            throw ApprovalProtocolError.nonCanonicalEncoding
        }
    }

    public func encodedReceiptBytes() -> Data {
        var output = unsigned.encodedSigningBytes()
        output.removeLast()
        appendString(name: "signature", value: signature, into: &output)
        output.append(0x7D)
        return output
    }

    public var receiptSHA256: String {
        UnsignedApprovalReceipt.sha256Hex(encodedReceiptBytes())
    }
}

private func appendInteger(name: String, value: Int, first: Bool = false, into output: inout Data) {
    if !first { output.append(0x2C) }
    CanonicalJSON.string(name, into: &output)
    output.append(0x3A)
    output.append(contentsOf: String(value).utf8)
}

private func appendString(name: String, value: String, into output: inout Data) {
    output.append(0x2C)
    CanonicalJSON.string(name, into: &output)
    output.append(0x3A)
    CanonicalJSON.string(value, into: &output)
}
