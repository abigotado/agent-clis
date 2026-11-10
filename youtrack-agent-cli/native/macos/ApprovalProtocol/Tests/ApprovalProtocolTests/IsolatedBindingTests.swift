import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

private struct BindingCatalog: Decodable {
    let schema_version: Int
    let positives: [Positive]
    let negatives: [Negative]

    struct Positive: Decodable {
        let name, raw, sha256, pass, architecture: String
    }

    struct Negative: Decodable {
        let name, base, sha256, insert_hex: String
        let offset, delete: Int
    }
}

private func bindingCatalog() throws -> BindingCatalog {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<6 { root.deleteLastPathComponent() }
    let data = try Data(contentsOf: root.appendingPathComponent("testdata/gate1b-isolated-binding/vectors.json"))
    let catalog = try JSONDecoder().decode(BindingCatalog.self, from: data)
    try #require(catalog.schema_version == 1)
    try #require(catalog.positives.count == 4)
    try #require(catalog.negatives.count == 136)
    return catalog
}

private func bindingHash(_ bytes: Data) -> String {
    SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
}

private func bindingInsert(_ value: String) throws -> Data {
    let bytes = Array(value.utf8)
    try #require(bytes.count.isMultiple(of: 2))
    var result = Data()
    for index in stride(from: 0, to: bytes.count, by: 2) {
        let pair = String(decoding: bytes[index..<index + 2], as: UTF8.self)
        let byte = try #require(UInt8(pair, radix: 16))
        try #require(String(format: "%02x", byte) == pair)
        result.append(byte)
    }
    return result
}

@Test func isolatedBindingSharedCanonicalVectors() throws {
    let catalog = try bindingCatalog()
    var seen = Set<String>()
    for vector in catalog.positives {
        try #require(seen.insert(vector.name).inserted)
        var source = Data(vector.raw.utf8)
        try #require(bindingHash(source) == vector.sha256)
        let binding = try IsolatedBinding(canonicalBytes: source)
        #expect(IsolatedBinding.schemaVersion == 1)
        #expect(IsolatedBinding.objectType == "gate1b_isolated_binding_v1")
        #expect(binding.pass == vector.pass)
        #expect(binding.architecture == vector.architecture)
        let digests = [binding.descriptorSHA256, binding.coverageInventorySHA256,
                       binding.unitDefinitionSHA256, binding.hostInventorySHA256,
                       binding.targetAllocationSHA256, binding.gateTargetSHA256]
        for (index, digest) in digests.enumerated() {
            #expect(digest == String(repeating: String(index + 1), count: 64))
        }
        source[0] = 0x5B
        var output = binding.encodedCanonicalBytes()
        #expect(output == Data(vector.raw.utf8))
        #expect(binding.bindingSHA256 == vector.sha256)
        output[0] = 0x5B
        let again = binding.encodedCanonicalBytes()
        #expect(again == Data(vector.raw.utf8))
        let roundTrip = try IsolatedBinding(canonicalBytes: again)
        #expect(roundTrip.bindingSHA256 == vector.sha256)
    }
}

@Test func isolatedBindingSharedMalformedVectors() throws {
    let catalog = try bindingCatalog()
    var bases: [String: Data] = [:]
    for vector in catalog.positives {
        try #require(bases[vector.name] == nil)
        bases[vector.name] = Data(vector.raw.utf8)
    }
    var seen = Set<String>()
    for vector in catalog.negatives {
        try #require(seen.insert(vector.name).inserted)
        let base = try #require(bases[vector.base])
        try #require(vector.offset >= 0 && vector.offset <= base.count)
        try #require(vector.delete >= 0 && vector.delete <= base.count - vector.offset)
        var raw = Data(base.prefix(vector.offset))
        raw.append(try bindingInsert(vector.insert_hex))
        raw.append(base.suffix(base.count - vector.offset - vector.delete))
        try #require(bindingHash(raw) == vector.sha256)
        #expect(throws: ApprovalProtocolError.self) {
            _ = try IsolatedBinding(canonicalBytes: raw)
        }
    }
}
