import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

// Exercise the existing shared Date-facing oracle, including its actual active
// consumer. These supplied historical fixtures assert no live-clock authority.
private struct RegistryTimeCorpus: Decodable {
    struct Timestamp: Decodable {
        let id: String; let text: String; let unix_seconds: Int64?
    }
    struct Interval: Decodable {
        let id: String; let start: String; let end: String; let seconds: Int64
    }
    struct Active: Decodable {
        let id: String; let base: String; let intent_id: String
        let created_at: String; let expires_at: String
        let raw_hex: String; let sha256: String; let reason_class: String
    }
    let schema_version: Int; let scope: String; let sources: [IntentCorpus.Source]
    let timestamps: [Timestamp]; let intervals: [Interval]; let active: [Active]
}

private func registryTimeDate(_ text: String) throws -> Date {
    try RegistryObject(fields: [("test_at", "\"" + text + "\"")]).time("test_at")
}

@Test func registryTimeSharedCorpus() throws {
    let corpus = try JSONDecoder().decode(RegistryTimeCorpus.self, from: intentFixtureData("testdata/gate1a-registry-time/corpus.json"))
    #expect(corpus.schema_version == 1)
    #expect(corpus.scope == "registry-timestamp-interop")
    try #require(corpus.sources.map(\.path) == ["testdata/gate1a-registry/corpus.json", "testdata/gate1a-registry-intent/corpus.json", "testdata/gate1a-registry-active/corpus.json"])
    #expect(corpus.sources.map(\.sha256) == [
        "b0fbce184a136c8b20689d51bb9eae0a46ecf510447c78a45728f8f4d88fde61",
        "ef65c0ae8132a37a0d6a04be2ba742537fa56ac78f32d4ce537f94c363557a05",
        "5fbe731e9ffa05c340586d0210d2a07ee7778e49c0d157d8d277cc029cb828c0",
    ])
    for source in corpus.sources {
        #expect(source.sha256 == intentHex(Data(SHA256.hash(data: try intentFixtureData(source.path)))))
    }
    // Literal signed Unix seconds were independently checked with ECMAScript's
    // proleptic Gregorian Date implementation, not Foundation or the generator.
    let timestamps: [(String, String, Int64?)] = [
        ("year-zero", "0000-01-01T00:00:00Z", -62167219200),
        ("year-one", "0001-01-01T00:00:00Z", -62135596800),
        ("epoch", "1970-01-01T00:00:00Z", 0),
        ("year-max", "9999-12-31T23:59:59Z", 253402300799),
        ("leap-zero", "0000-02-29T12:00:00Z", -62162078400),
        ("leap-1600", "1600-02-29T12:00:00Z", -11670955200),
        ("leap-2000", "2000-02-29T12:00:00Z", 951825600),
        ("cutover-oct4", "1582-10-04T00:00:00Z", -12220243200),
        ("cutover-oct10", "1582-10-10T00:00:00Z", -12219724800),
        ("cutover-oct15", "1582-10-15T00:00:00Z", -12219292800),
        ("invalid-1500-leap", "1500-02-29T12:00:00Z", nil),
        ("invalid-1700-leap", "1700-02-29T12:00:00Z", nil),
        ("invalid-1900-leap", "1900-02-29T12:00:00Z", nil),
        ("invalid-zero-feb30", "0000-02-30T12:00:00Z", nil),
        ("month-zero", "2000-00-01T00:00:00Z", nil),
        ("month-overflow", "2000-13-01T00:00:00Z", nil),
        ("day-zero", "2000-01-00T00:00:00Z", nil),
        ("day-overflow", "2000-04-31T00:00:00Z", nil),
        ("hour-overflow", "2000-01-01T24:00:00Z", nil),
        ("minute-overflow", "2000-01-01T00:60:00Z", nil),
        ("second-overflow", "2000-01-01T00:00:60Z", nil),
        ("expanded-year", "10000-01-01T00:00:00Z", nil),
        ("signed-year", "-001-01-01T00:00:00Z", nil),
        ("fraction", "2000-01-01T00:00:00.0Z", nil),
        ("offset", "2000-01-01T00:00:00+00:00", nil),
        ("separator", "2000-01-01 00:00:00Z", nil),
        ("nonascii-digit", "２０００-01-01T00:00:00Z", nil),
    ]
    try #require(corpus.timestamps.map(\.id) == timestamps.map(\.0))
    for (vector, pinned) in zip(corpus.timestamps, timestamps) {
        #expect(vector.text == pinned.1)
        #expect(vector.unix_seconds == pinned.2)
        if let seconds = pinned.2 {
            do { #expect(try registryTimeDate(vector.text).timeIntervalSince1970 == Double(seconds), "\(vector.id)") }
            catch { Issue.record("\(vector.id): \(error)") }
        } else {
            #expect(throws: RegistryReason.boundsGrammar, "\(vector.id)") { _ = try registryTimeDate(vector.text) }
        }
    }
    let intervals: [(String, String, String, Int64)] = [
        ("zero-leap", "0000-02-28T23:59:59Z", "0000-02-29T00:00:00Z", 1),
        ("century-nonleap", "1500-02-28T23:59:59Z", "1500-03-01T00:00:00Z", 1),
        ("cutover-1", "1582-10-04T23:59:59Z", "1582-10-05T00:00:00Z", 1),
        ("cutover-gap", "1582-10-04T23:59:59Z", "1582-10-15T00:00:00Z", 864001),
        ("ttl-300", "1582-10-10T00:00:00Z", "1582-10-10T00:05:00Z", 300),
        ("ttl-600", "1582-10-10T00:00:00Z", "1582-10-10T00:10:00Z", 600),
        ("ttl-601", "1582-10-10T00:00:00Z", "1582-10-10T00:10:01Z", 601),
        ("reverse", "1582-10-10T00:10:00Z", "1582-10-10T00:00:00Z", -600),
        ("full-range", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z", 315569519999),
    ]
    try #require(corpus.intervals.map(\.id) == intervals.map(\.0))
    for (vector, pinned) in zip(corpus.intervals, intervals) {
        #expect(vector.start == pinned.1)
        #expect(vector.end == pinned.2)
        #expect(vector.seconds == pinned.3)
        do {
            let actual = try registryTimeDate(vector.end).timeIntervalSince(registryTimeDate(vector.start))
            #expect(actual == Double(pinned.3), "\(vector.id)")
        } catch { Issue.record("\(vector.id): \(error)") }
    }
}

@Test func registryTimeExistingActiveHistoricalRegression() throws {
    let corpus = try JSONDecoder().decode(RegistryTimeCorpus.self, from: intentFixtureData("testdata/gate1a-registry-time/corpus.json"))
    let active = try JSONDecoder().decode(ActiveCorpus.self, from: intentFixtureData("testdata/gate1a-registry-active/corpus.json"))
    let intents = try JSONDecoder().decode(IntentCorpus.self, from: intentFixtureData("testdata/gate1a-registry-intent/corpus.json"))
    let core = try registryCorpus()
    let base = try #require(active.positives.first { $0.id == "active-enroll1" })
    let raw = String(decoding: try intentBytes(base.raw_hex), as: UTF8.self)
    // Full active hashes were independently computed with Node SHA-256, over
    // the frozen enroll fixture with only these two timestamp strings changed.
    let cases: [(String, String, String, String, ActiveFailure?)] = [
        ("active-zero", "0000-02-29T00:00:00Z", "0000-02-29T00:10:00Z", "4e37f15c2a922efda4da6e46d2ec979309b1047644e493912dbb81ce8c5d3a3d", nil),
        ("active-gap", "1582-10-10T00:00:00Z", "1582-10-10T00:10:00Z", "139cda3920db332f6a5e23d82bf32cad2d6cf3682c57b84acb293ff70a35e239", nil),
        ("active-century-leap", "1600-02-29T00:00:00Z", "1600-02-29T00:10:00Z", "325b90747196c6691c79ad7ecc43418de6d130859039ce2d2065721d1563c36f", nil),
        ("active-invalid-leap", "1500-02-29T00:00:00Z", "1500-02-29T00:10:00Z", "df8086329d371f8b790c5a57df2366a7cc01293ba3bec6b1024efe0d79b5e014", .bounds),
        ("active-cutover", "1582-10-04T23:59:59Z", "1582-10-15T00:00:00Z", "13747980e67323caf814c6aa5c0518b48f43912338ec43718b75d6eec1cc8d53", .temporal),
        ("active-601", "1582-10-10T00:00:00Z", "1582-10-10T00:10:01Z", "ed23c55032cac1135e8c73a227ed8c70380cc749d952dd106b0d19b4518c674d", .temporal),
        ("active-reverse", "1582-10-10T00:10:00Z", "1582-10-10T00:00:00Z", "1c82d78c3a198542b4c0720e423c3f33506e205d79e44ef93dd1602e5de7885d", .temporal),
    ]
    try #require(corpus.active.map(\.id) == cases.map(\.0))
    #expect(base.sha256 == "caf9ff28abe86dc19df7774563ad8c296c004038cbbf092056860abe82b11942")
    for (vector, pinned) in zip(corpus.active, cases) {
        let expected = Data(raw.replacingOccurrences(of: "2026-09-01T12:00:00Z", with: pinned.1)
            .replacingOccurrences(of: "2026-09-01T12:10:00Z", with: pinned.2).utf8)
        let bytes = try intentBytes(vector.raw_hex)
        #expect(vector.base == "active-enroll1")
        #expect(vector.intent_id == "intent-enroll1")
        #expect(vector.created_at == pinned.1)
        #expect(vector.expires_at == pinned.2)
        #expect(vector.sha256 == pinned.3)
        #expect(vector.reason_class == (pinned.4?.rawValue ?? ""))
        #expect(bytes == expected)
        #expect(activeDigest(bytes) == pinned.3)
        if let reason = pinned.4 {
            #expect(throws: reason, "\(vector.id)") {
                _ = try validateActive(bytes, digest: vector.sha256, intentID: vector.intent_id, intents: intents, core: core)
            }
        } else {
            do {
                let value = try validateActive(bytes, digest: vector.sha256, intentID: vector.intent_id, intents: intents, core: core)
                #expect(try value.time("expires_at").timeIntervalSince(value.time("created_at")) == 600, "\(vector.id)")
            } catch { Issue.record("\(vector.id): \(error)") }
        }
    }
}
