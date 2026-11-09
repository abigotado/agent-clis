import struct Foundation.Data

enum StrictJSONValue: Equatable {
    case integer(Int)
    case string(String)
}

struct StrictJSONObjectParser {
    private let bytes: [UInt8]
    private var offset = 0

    init(data: Data, maximumBytes: Int) throws {
        guard data.count <= maximumBytes else {
            throw ApprovalProtocolError.inputTooLarge(limit: maximumBytes)
        }
        bytes = Array(data)
    }

    mutating func parse() throws -> [String: StrictJSONValue] {
        skipWhitespace()
        try consume(0x7B) // {
        skipWhitespace()

        var result: [String: StrictJSONValue] = [:]
        if take(0x7D) { // }
            skipWhitespace()
            guard isAtEnd else { throw ApprovalProtocolError.malformedJSON }
            return result
        }

        while true {
            let key = try parseString()
            guard result[key] == nil else {
                throw ApprovalProtocolError.duplicateField(key)
            }
            skipWhitespace()
            try consume(0x3A) // :
            skipWhitespace()

            let value: StrictJSONValue
            if peek == 0x22 {
                value = .string(try parseString())
            } else {
                value = .integer(try parseInteger())
            }
            result[key] = value

            skipWhitespace()
            if take(0x7D) { break }
            try consume(0x2C) // ,
            skipWhitespace()
        }

        skipWhitespace()
        guard isAtEnd else { throw ApprovalProtocolError.malformedJSON }
        return result
    }

    private var isAtEnd: Bool { offset == bytes.count }
    private var peek: UInt8? { isAtEnd ? nil : bytes[offset] }

    private mutating func skipWhitespace() {
        while let byte = peek, byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D {
            offset += 1
        }
    }

    @discardableResult
    private mutating func take(_ byte: UInt8) -> Bool {
        guard peek == byte else { return false }
        offset += 1
        return true
    }

    private mutating func consume(_ byte: UInt8) throws {
        guard take(byte) else { throw ApprovalProtocolError.malformedJSON }
    }

    private mutating func parseInteger() throws -> Int {
        let start = offset
        if take(0x2D) {} // -
        guard let first = peek, first >= 0x30, first <= 0x39 else {
            throw ApprovalProtocolError.malformedJSON
        }
        if first == 0x30 {
            offset += 1
            if let next = peek, next >= 0x30, next <= 0x39 {
                throw ApprovalProtocolError.malformedJSON
            }
        } else {
            while let byte = peek, byte >= 0x30, byte <= 0x39 {
                offset += 1
            }
        }
        guard let string = String(bytes: bytes[start..<offset], encoding: .utf8),
              let value = Int(string)
        else {
            throw ApprovalProtocolError.malformedJSON
        }
        return value
    }

    private mutating func parseString() throws -> String {
        try consume(0x22)
        var result = ""
        var unescapedStart = offset

        func decoded(_ range: Range<Int>) throws -> String {
            guard let value = String(bytes: bytes[range], encoding: .utf8) else {
                throw ApprovalProtocolError.malformedJSON
            }
            return value
        }

        while let byte = peek {
            if byte == 0x22 {
                result += try decoded(unescapedStart..<offset)
                offset += 1
                return result
            }
            if byte < 0x20 {
                throw ApprovalProtocolError.malformedJSON
            }
            if byte != 0x5C {
                offset += 1
                continue
            }

            result += try decoded(unescapedStart..<offset)
            offset += 1
            guard let escaped = peek else { throw ApprovalProtocolError.malformedJSON }
            offset += 1
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
                let first = try parseHexQuad()
                let scalarValue: UInt32
                if (0xD800...0xDBFF).contains(first) {
                    guard take(0x5C), take(0x75) else {
                        throw ApprovalProtocolError.malformedJSON
                    }
                    let second = try parseHexQuad()
                    guard (0xDC00...0xDFFF).contains(second) else {
                        throw ApprovalProtocolError.malformedJSON
                    }
                    scalarValue = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                } else {
                    guard !(0xDC00...0xDFFF).contains(first) else {
                        throw ApprovalProtocolError.malformedJSON
                    }
                    scalarValue = first
                }
                guard let scalar = UnicodeScalar(scalarValue) else {
                    throw ApprovalProtocolError.malformedJSON
                }
                result.unicodeScalars.append(scalar)
            default:
                throw ApprovalProtocolError.malformedJSON
            }
            unescapedStart = offset
        }
        throw ApprovalProtocolError.malformedJSON
    }

    private mutating func parseHexQuad() throws -> UInt32 {
        guard offset <= bytes.count - 4 else { throw ApprovalProtocolError.malformedJSON }
        var value: UInt32 = 0
        for _ in 0..<4 {
            let byte = bytes[offset]
            offset += 1
            let digit: UInt32
            switch byte {
            case 0x30...0x39: digit = UInt32(byte - 0x30)
            case 0x41...0x46: digit = UInt32(byte - 0x41 + 10)
            case 0x61...0x66: digit = UInt32(byte - 0x61 + 10)
            default: throw ApprovalProtocolError.malformedJSON
            }
            value = (value << 4) | digit
        }
        return value
    }
}

enum CanonicalJSON {
    static func string(_ value: String, into output: inout Data) {
        output.append(0x22)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x08: output.append(contentsOf: [0x5C, 0x62])
            case 0x09: output.append(contentsOf: [0x5C, 0x74])
            case 0x0A: output.append(contentsOf: [0x5C, 0x6E])
            case 0x0C: output.append(contentsOf: [0x5C, 0x66])
            case 0x0D: output.append(contentsOf: [0x5C, 0x72])
            case 0x22: output.append(contentsOf: [0x5C, 0x22])
            case 0x5C: output.append(contentsOf: [0x5C, 0x5C])
            case 0x00...0x1F, 0x3C, 0x3E, 0x26, 0x2028, 0x2029:
                appendUnicodeEscape(UInt16(scalar.value), into: &output)
            default:
                output.append(contentsOf: String(scalar).utf8)
            }
        }
        output.append(0x22)
    }

    private static func appendUnicodeEscape(_ value: UInt16, into output: inout Data) {
        let hex = Array("0123456789abcdef".utf8)
        output.append(contentsOf: [
            0x5C, 0x75,
            hex[Int((value >> 12) & 0xF)],
            hex[Int((value >> 8) & 0xF)],
            hex[Int((value >> 4) & 0xF)],
            hex[Int(value & 0xF)],
        ])
    }
}
