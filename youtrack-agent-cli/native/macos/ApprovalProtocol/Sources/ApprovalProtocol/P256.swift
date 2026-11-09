import enum CryptoKit.P256
import struct CryptoKit.SHA256
import struct Foundation.Data

public enum P256PublicKeyCodec {
    public static let x963ByteCount = 65
    public static let spkiByteCount = 91

    private static let spkiPrefix = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    ])

    public static func spkiDER(fromX963 x963: Data) throws -> Data {
        guard x963.count == x963ByteCount, x963.first == 0x04 else {
            throw ApprovalProtocolError.invalidPublicKey
        }
        do {
            let key = try P256.Signing.PublicKey(x963Representation: x963)
            guard key.x963Representation == x963 else {
                throw ApprovalProtocolError.invalidPublicKey
            }
        } catch {
            throw ApprovalProtocolError.invalidPublicKey
        }
        var result = spkiPrefix
        result.append(x963)
        return result
    }

    public static func x963(fromSPKIDER spki: Data) throws -> Data {
        guard spki.count == spkiByteCount, spki.prefix(spkiPrefix.count) == spkiPrefix else {
            throw ApprovalProtocolError.invalidPublicKey
        }
        let x963 = Data(spki.dropFirst(spkiPrefix.count))
        _ = try spkiDER(fromX963: x963)
        return x963
    }

    public static func fingerprintSHA256(x963: Data) throws -> String {
        let spki = try spkiDER(fromX963: x963)
        return SHA256.hash(data: spki).map { String(format: "%02x", $0) }.joined()
    }

    public static func verify(message: Data, derSignature: Data, x963: Data) throws -> Bool {
        let validatedSignature = try P256Signature(der: derSignature)
        do {
            let key = try P256.Signing.PublicKey(x963Representation: x963)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: derSignature)
            if key.isValidSignature(signature, for: message) { return true }

            // Some native verifiers reject a valid low-S representation but accept
            // its (r, N-s) twin. The verification point negates, preserving x.
            // Strict low-S ingress above remains mandatory; the twin stays local.
            let equivalentDER = try validatedSignature.equivalentHighSDER()
            let equivalentSignature: P256.Signing.ECDSASignature
            do {
                equivalentSignature = try P256.Signing.ECDSASignature(derRepresentation: equivalentDER)
            } catch {
                // The optional compatibility representation may be unsupported.
                // Preserve the original verification verdict in that case.
                return false
            }
            return key.isValidSignature(equivalentSignature, for: message)
        } catch {
            throw ApprovalProtocolError.invalidSignature
        }
    }
}

public struct P256Signature: Equatable, Sendable {
    public static let maximumDERBytes = 72
    public static let maximumBase64URLBytes = 96

    public let der: Data

    public init(der: Data) throws {
        guard der.count <= Self.maximumDERBytes, der.count >= 8 else {
            throw ApprovalProtocolError.invalidSignature
        }
        let bytes = Array(der)
        guard bytes[0] == 0x30, Int(bytes[1]) == bytes.count - 2 else {
            throw ApprovalProtocolError.invalidSignature
        }
        var offset = 2
        let r = try Self.parseInteger(bytes, offset: &offset)
        let s = try Self.parseInteger(bytes, offset: &offset)
        guard offset == bytes.count, Self.isScalar(r), Self.isScalar(s), Self.isLowS(s) else {
            throw ApprovalProtocolError.invalidSignature
        }
        self.der = der
    }

    public init(derBase64URL value: String) throws {
        guard value.utf8.count <= Self.maximumBase64URLBytes else {
            throw ApprovalProtocolError.invalidSignature
        }
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, !bytes.contains(0x3D), bytes.count % 4 != 1,
              bytes.allSatisfy({
                  ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) ||
                      ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F
              })
        else {
            throw ApprovalProtocolError.invalidSignature
        }
        var padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.utf8.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded) else {
            throw ApprovalProtocolError.invalidSignature
        }
        try self.init(der: decoded)
        guard base64URL == value else {
            throw ApprovalProtocolError.invalidSignature
        }
    }

    public var base64URL: String {
        der.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func normalizeLowS(der: Data) throws -> P256Signature {
        guard der.count <= maximumDERBytes, der.count >= 8 else { throw ApprovalProtocolError.invalidSignature }
        let bytes = Array(der)
        guard bytes[0] == 0x30, Int(bytes[1]) == bytes.count - 2 else { throw ApprovalProtocolError.invalidSignature }
        var offset = 2
        let r = try parseInteger(bytes, offset: &offset)
        let s = try parseInteger(bytes, offset: &offset)
        guard offset == bytes.count, isScalar(r), isScalar(s) else { throw ApprovalProtocolError.invalidSignature }
        let normalizedS = isLowS(s) ? Array(s) : subtractFromOrder(Array(s))
        var body = Data()
        appendInteger(Array(r), into: &body)
        appendInteger(normalizedS, into: &body)
        var result = Data([0x30, UInt8(body.count)])
        result.append(body)
        return try P256Signature(der: result)
    }

    fileprivate func equivalentHighSDER() throws -> Data {
        let bytes = Array(der)
        var offset = 2
        let r = try Self.parseInteger(bytes, offset: &offset)
        let s = try Self.parseInteger(bytes, offset: &offset)
        var body = Data()
        Self.appendInteger(Array(r), into: &body)
        Self.appendInteger(Self.subtractFromOrder(Array(s)), into: &body)
        var result = Data([0x30, UInt8(body.count)])
        result.append(body)
        return result
    }

    private static func parseInteger(_ bytes: [UInt8], offset: inout Int) throws -> ArraySlice<UInt8> {
        guard offset + 2 <= bytes.count, bytes[offset] == 0x02 else {
            throw ApprovalProtocolError.invalidSignature
        }
        let length = Int(bytes[offset + 1])
        offset += 2
        guard (1...33).contains(length), offset + length <= bytes.count else {
            throw ApprovalProtocolError.invalidSignature
        }
        let integer = bytes[offset..<(offset + length)]
        offset += length
        guard integer.first! & 0x80 == 0,
              !(integer.count > 1 && integer.first == 0 && integer.dropFirst().first! & 0x80 == 0)
        else {
            throw ApprovalProtocolError.invalidSignature
        }
        return integer.first == 0 ? integer.dropFirst() : integer
    }

    private static func isScalar(_ integer: ArraySlice<UInt8>) -> Bool {
        let order: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
        ]
        guard !integer.isEmpty, integer.count <= order.count, integer.contains(where: { $0 != 0 }) else {
            return false
        }
        guard integer.count == order.count else { return true }
        return integer.lexicographicallyPrecedes(order)
    }

    private static func isLowS(_ integer: ArraySlice<UInt8>) -> Bool {
        let halfOrder: [UInt8] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
            0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
        ]
        guard integer.count == halfOrder.count else { return integer.count < halfOrder.count }
        return integer.elementsEqual(halfOrder) || integer.lexicographicallyPrecedes(halfOrder)
    }

    private static func subtractFromOrder(_ scalar: [UInt8]) -> [UInt8] {
        var order: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
        ]
        let padded = Array(repeating: UInt8(0), count: 32 - scalar.count) + scalar
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var value = Int(order[index]) - Int(padded[index]) - borrow
            if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }
            order[index] = UInt8(value)
        }
        while order.count > 1, order.first == 0 { order.removeFirst() }
        return order
    }

    private static func appendInteger(_ magnitude: [UInt8], into output: inout Data) {
        let needsZero = magnitude.first! & 0x80 != 0
        output.append(0x02)
        output.append(UInt8(magnitude.count + (needsZero ? 1 : 0)))
        if needsZero { output.append(0) }
        output.append(contentsOf: magnitude)
    }
}
