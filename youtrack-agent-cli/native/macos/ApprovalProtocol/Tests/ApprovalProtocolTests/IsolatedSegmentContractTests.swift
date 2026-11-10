import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

private struct SegmentContractCatalog: Decodable {
    let schema_version: Int
    let positives: [Positive]
    let negatives: [Negative]

    struct Positive: Decodable {
        let name, raw, sha256, mode: String
        let ordinal: Int
        let counts: [Int]
    }

    struct Negative: Decodable {
        let name, base, sha256, insert_hex: String
        let offset, delete: Int
    }
}

private func segmentCatalog() throws -> SegmentContractCatalog {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<6 { root.deleteLastPathComponent() }
    let data = try Data(contentsOf: root.appendingPathComponent("testdata/gate1b-isolated-segment/vectors.json"))
    let catalog = try JSONDecoder().decode(SegmentContractCatalog.self, from: data)
    try #require(catalog.schema_version == 1)
    try #require(catalog.positives.count == 8)
    try #require(catalog.negatives.count == 196)
    return catalog
}

private func segmentHash(_ bytes: Data) -> String {
    SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
}

private func segmentInsert(_ value: String) throws -> Data {
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

@Test func isolatedSegmentContractSharedCanonicalVectors() throws {
    let catalog = try segmentCatalog()
    var seen = Set<String>()
    for vector in catalog.positives {
        try #require(seen.insert(vector.name).inserted)
        var source = Data(vector.raw.utf8)
        try #require(segmentHash(source) == vector.sha256)
        let segment = try IsolatedSegmentContract(canonicalBytes: source)
        #expect(IsolatedSegmentContract.schemaVersion == 1)
        #expect(IsolatedSegmentContract.objectType == "gate1b_isolated_segment_contract_v1")
        #expect(segment.mode == vector.mode)
        #expect(segment.segmentOrdinal == vector.ordinal)
        let digests = [segment.commandContractSHA256, segment.fixtureSetSHA256,
                       segment.assertionSetSHA256, segment.transcriptSetSHA256]
        for (index, digest) in digests.enumerated() {
            #expect(digest == String(repeating: String(index + 1), count: 64))
        }
        let counts = [segment.operationCount, segment.observationCount,
                      segment.transcriptCount, segment.assertionCount,
                      segment.fileCount, segment.maximumEvidenceBytes]
        #expect(counts == vector.counts)
        source[0] = 0x5B
        var output = segment.encodedCanonicalBytes()
        #expect(output == Data(vector.raw.utf8))
        #expect(segment.segmentContractSHA256 == vector.sha256)
        output[0] = 0x5B
        let again = segment.encodedCanonicalBytes()
        #expect(again == Data(vector.raw.utf8))
        let roundTrip = try IsolatedSegmentContract(canonicalBytes: again)
        #expect(roundTrip.segmentContractSHA256 == vector.sha256)
    }
}

@Test func isolatedSegmentContractSharedMalformedVectors() throws {
    let catalog = try segmentCatalog()
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
        raw.append(try segmentInsert(vector.insert_hex))
        raw.append(base.suffix(base.count - vector.offset - vector.delete))
        try #require(segmentHash(raw) == vector.sha256)
        #expect(throws: ApprovalProtocolError.self) {
            _ = try IsolatedSegmentContract(canonicalBytes: raw)
        }
    }
}
