import struct CryptoKit.SHA256
import struct Foundation.Data

enum ProtocolGrammar {
    static let maximumRegistryRevision = 256
    private static let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    static func isCanonicalBase32ID(_ value: String, prefix: String) -> Bool {
        guard value.hasPrefix(prefix) else { return false }
        let encoded = Array(value.dropFirst(prefix.count).utf8)
        guard encoded.count == 26, encoded.allSatisfy(base32Alphabet.contains),
              let last = encoded.last, let index = base32Alphabet.firstIndex(of: last)
        else { return false }
        return index & 3 == 0
    }

    static func base32ID(prefix: String, bytes: Data) throws -> String {
        guard bytes.count == 16 else { throw ApprovalProtocolError.invalidField("random") }
        let raw = Array(bytes)
        var encoded = ""
        encoded.reserveCapacity(26)
        for group in 0..<26 {
            var value = 0
            for bit in 0..<5 {
                let bitIndex = group * 5 + bit
                value <<= 1
                if bitIndex < 128 {
                    value |= Int((raw[bitIndex / 8] >> UInt8(7 - bitIndex % 8)) & 1)
                }
            }
            encoded.append(Character(UnicodeScalar(base32Alphabet[value])))
        }
        return prefix + encoded
    }

    static func isIdentifier(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (1...128).contains(bytes.count), isASCIIAlphanumeric(bytes[0]) else { return false }
        return bytes.dropFirst().allSatisfy {
            isASCIIAlphanumeric($0) || $0 == 0x2E || $0 == 0x5F || $0 == 0x3A || $0 == 0x2D
        }
    }

    static func isProjectKey(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (1...32).contains(bytes.count), (0x41...0x5A).contains(bytes[0]) else { return false }
        return bytes.dropFirst().allSatisfy {
            (0x41...0x5A).contains($0) || (0x30...0x39).contains($0) || $0 == 0x5F
        }
    }

    static func isKeyGeneration(_ value: String) -> Bool {
        keyGenerationRevision(value) != nil
    }

    static func keyGenerationRevision(_ value: String) -> Int? {
        let bytes = Array(value.utf8)
        guard bytes.count == 25, bytes.prefix(5).elementsEqual("YTAG-".utf8) else { return nil }
        var revision = 0
        for byte in bytes.dropFirst(5) {
            guard (0x30...0x39).contains(byte) else { return nil }
            revision = revision * 10 + Int(byte - 0x30)
            guard revision <= maximumRegistryRevision else { return nil }
        }
        return (1...maximumRegistryRevision).contains(revision) ? revision : nil
    }

    static func isDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
        }
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func isASCIIAlphanumeric(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }
}
