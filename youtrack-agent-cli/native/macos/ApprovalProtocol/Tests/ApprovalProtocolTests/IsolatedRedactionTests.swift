import Foundation
import Testing
@testable import ApprovalProtocol

@Test func isolatedParsersRedactDuplicateFieldDiagnostics() throws {
    for marker in ["UNTRUSTED_SENTINEL_FIRST", "UNTRUSTED_SENTINEL_SECOND"] {
        let raw = Data("{\"schema_version\":1,\"\(marker)\":1,\"\(marker)\":2}".utf8)
        try #require(raw.count <= 4096)
        // Control only, not production API: prove the internal parser emits
        // the attacker-controlled duplicate key before the public boundary.
        var control = try StrictJSONObjectParser(data: raw, maximumBytes: 4096)
        #expect(throws: ApprovalProtocolError.duplicateField(marker)) {
            _ = try control.parse()
        }
        #expect(throws: ApprovalProtocolError.malformedJSON) {
            _ = try IsolatedBinding(canonicalBytes: raw)
        }
        #expect(throws: ApprovalProtocolError.malformedJSON) {
            _ = try IsolatedSegmentContract(canonicalBytes: raw)
        }
    }
}
