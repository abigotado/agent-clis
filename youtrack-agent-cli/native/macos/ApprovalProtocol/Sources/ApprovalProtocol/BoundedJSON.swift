import struct Foundation.Data

struct JSONMember {
    let name: String
    let value: JSONNode
}

indirect enum JSONNode {
    case object([JSONMember])
    case array([JSONNode])
    case string(String)
    case unsigned(UInt64)
    case boolean(Bool)
    case null
}

struct BoundedJSONParser {
    static let maximumDepth = 12
    static let maximumValues = 1_024
    static let maximumObjectFields = 32
    static let maximumArrayElements = 100

    private let bytes: [UInt8]
    private var offset = 0
    private var values = 0

    init(data: Data, maximumBytes: Int) throws {
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw ApprovalProtocolError.inputTooLarge(limit: maximumBytes)
        }
        bytes = Array(data)
    }

    mutating func parse() throws -> JSONNode {
        let result = try parseValue(depth: 0)
        guard offset == bytes.count else { throw ApprovalProtocolError.malformedJSON }
        return result
    }

    private mutating func parseValue(depth: Int) throws -> JSONNode {
        guard depth <= Self.maximumDepth, values < Self.maximumValues else {
            throw ApprovalProtocolError.malformedJSON
        }
        values += 1
        guard let byte = peek else { throw ApprovalProtocolError.malformedJSON }
        switch byte {
        case 0x7B: return try parseObject(depth: depth)
        case 0x5B: return try parseArray(depth: depth)
        case 0x22: return .string(try parseString())
        case 0x30...0x39: return .unsigned(try parseUInt64())
        case 0x74: try literal("true"); return .boolean(true)
        case 0x66: try literal("false"); return .boolean(false)
        case 0x6E: try literal("null"); return .null
        default: throw ApprovalProtocolError.malformedJSON
        }
    }

    private mutating func parseObject(depth: Int) throws -> JSONNode {
        offset += 1
        var pairs: [JSONMember] = []
        if take(0x7D) { return .object(pairs) }
        while true {
            guard pairs.count < Self.maximumObjectFields else { throw ApprovalProtocolError.malformedJSON }
            let key = try parseString()
            guard !pairs.contains(where: { $0.name == key }) else {
                throw ApprovalProtocolError.duplicateField(key)
            }
            guard take(0x3A) else { throw ApprovalProtocolError.malformedJSON }
            pairs.append(JSONMember(name: key, value: try parseValue(depth: depth + 1)))
            if take(0x7D) { return .object(pairs) }
            guard take(0x2C) else { throw ApprovalProtocolError.malformedJSON }
        }
    }

    private mutating func parseArray(depth: Int) throws -> JSONNode {
        offset += 1
        var items: [JSONNode] = []
        if take(0x5D) { return .array(items) }
        while true {
            guard items.count < Self.maximumArrayElements else { throw ApprovalProtocolError.malformedJSON }
            items.append(try parseValue(depth: depth + 1))
            if take(0x5D) { return .array(items) }
            guard take(0x2C) else { throw ApprovalProtocolError.malformedJSON }
        }
    }

    private mutating func parseUInt64() throws -> UInt64 {
        guard let first = peek, first >= 0x30, first <= 0x39 else { throw ApprovalProtocolError.malformedJSON }
        if first == 0x30 {
            offset += 1
            if let next = peek, next >= 0x30, next <= 0x39 { throw ApprovalProtocolError.malformedJSON }
            return 0
        }
        var value: UInt64 = 0
        while let byte = peek, byte >= 0x30, byte <= 0x39 {
            let digit = UInt64(byte - 0x30)
            guard value <= (UInt64.max - digit) / 10 else { throw ApprovalProtocolError.malformedJSON }
            value = value * 10 + digit
            offset += 1
        }
        return value
    }

    private mutating func parseString() throws -> String {
        guard take(0x22) else { throw ApprovalProtocolError.malformedJSON }
        var result = ""
        var start = offset
        func decode(_ range: Range<Int>) throws -> String {
            let segment = Array(bytes[range])
            let text = String(decoding: segment, as: UTF8.self)
            guard Array(text.utf8) == segment else { throw ApprovalProtocolError.malformedJSON }
            return text
        }
        while let byte = peek {
            if byte == 0x22 {
                result += try decode(start..<offset); offset += 1; return result
            }
            if byte < 0x20 { throw ApprovalProtocolError.malformedJSON }
            if byte != 0x5C { offset += 1; continue }
            result += try decode(start..<offset); offset += 1
            guard let escaped = peek else { throw ApprovalProtocolError.malformedJSON }; offset += 1
            switch escaped {
            case 0x22: result.append("\"")
            case 0x5C: result.append("\\")
            case 0x2F: result.append("/")
            case 0x62: result.append("\u{0008}")
            case 0x66: result.append("\u{000C}")
            case 0x6E: result.append("\n")
            case 0x72: result.append("\r")
            case 0x74: result.append("\t")
            case 0x75:
                let first = try hexQuad()
                let scalar: UInt32
                if (0xD800...0xDBFF).contains(first) {
                    guard take(0x5C), take(0x75) else { throw ApprovalProtocolError.malformedJSON }
                    let second = try hexQuad()
                    guard (0xDC00...0xDFFF).contains(second) else { throw ApprovalProtocolError.malformedJSON }
                    scalar = 0x10000 + ((first - 0xD800) << 10) + second - 0xDC00
                } else {
                    guard !(0xDC00...0xDFFF).contains(first) else { throw ApprovalProtocolError.malformedJSON }
                    scalar = first
                }
                guard let unicode = UnicodeScalar(scalar) else { throw ApprovalProtocolError.malformedJSON }
                result.unicodeScalars.append(unicode)
            default: throw ApprovalProtocolError.malformedJSON
            }
            start = offset
        }
        throw ApprovalProtocolError.malformedJSON
    }

    private mutating func hexQuad() throws -> UInt32 {
        guard offset <= bytes.count - 4 else { throw ApprovalProtocolError.malformedJSON }
        var value: UInt32 = 0
        for _ in 0..<4 {
            let byte = bytes[offset]; offset += 1
            let digit: UInt32
            switch byte {
            case 0x30...0x39: digit = UInt32(byte - 0x30)
            case 0x41...0x46: digit = UInt32(byte - 0x41 + 10)
            case 0x61...0x66: digit = UInt32(byte - 0x61 + 10)
            default: throw ApprovalProtocolError.malformedJSON
            }
            value = value << 4 | digit
        }
        return value
    }

    private mutating func literal(_ text: StaticString) throws {
        let expected = text.withUTF8Buffer { Array($0) }
        guard offset + expected.count <= bytes.count,
              bytes[offset..<(offset + expected.count)].elementsEqual(expected)
        else { throw ApprovalProtocolError.malformedJSON }
        offset += expected.count
    }

    private var peek: UInt8? { offset < bytes.count ? bytes[offset] : nil }
    private mutating func take(_ byte: UInt8) -> Bool {
        guard peek == byte else { return false }; offset += 1; return true
    }
}

enum JSONCanonicalEncoder {
    static func encode(_ node: JSONNode) -> Data {
        var output = Data()
        append(node, into: &output)
        return output
    }

    private static func append(_ node: JSONNode, into output: inout Data) {
        switch node {
        case let .object(pairs):
            output.append(0x7B)
            for (index, pair) in pairs.enumerated() {
                if index > 0 { output.append(0x2C) }
                CanonicalJSON.string(pair.name, into: &output); output.append(0x3A); append(pair.value, into: &output)
            }
            output.append(0x7D)
        case let .array(items):
            output.append(0x5B)
            for (index, item) in items.enumerated() {
                if index > 0 { output.append(0x2C) }; append(item, into: &output)
            }
            output.append(0x5D)
        case let .string(value): CanonicalJSON.string(value, into: &output)
        case let .unsigned(value): output.append(contentsOf: String(value).utf8)
        case let .boolean(value): output.append(contentsOf: (value ? "true" : "false").utf8)
        case .null: output.append(contentsOf: "null".utf8)
        }
    }
}

extension JSONNode {
    func exactObject(_ keys: [String]) throws -> [String: JSONNode] {
        guard case let .object(pairs) = self, pairs.map(\.name) == keys else { throw ApprovalProtocolError.nonCanonicalEncoding }
        return Dictionary(uniqueKeysWithValues: pairs.map { ($0.name, $0.value) })
    }

    var string: String? { if case let .string(value) = self { value } else { nil } }
    var uint64: UInt64? { if case let .unsigned(value) = self { value } else { nil } }
    var array: [JSONNode]? { if case let .array(value) = self { value } else { nil } }
}
