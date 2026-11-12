package operatorwrite

import (
	"encoding/binary"
	"hash/crc32"
)

// pngChunk builds one PNG chunk with a correct CRC.
func pngChunk(kind string, data []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	out = append(out, kind...)
	out = append(out, data...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out[4:]))
}

// minimalPNG is a structurally valid PNG whose tEXt chunk carries tail, so a
// test can vary the bytes and the total size.
func minimalPNG(tail []byte) []byte {
	ihdr := []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0}
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, pngChunk("IHDR", ihdr)...)
	out = append(out, pngChunk("tEXt", tail)...)
	return append(out, pngChunk("IEND", nil)...)
}

// minimalPNGOfSize builds a valid PNG of exactly n bytes (n >= 57).
func minimalPNGOfSize(n int) []byte { return minimalPNG(make([]byte, n-len(minimalPNG(nil)))) }

var (
	// minimalJPEG is SOI, JFIF APP0, a 1x1 grayscale SOF0 and EOI.
	minimalJPEG = []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" +
		"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xd9")
	minimalGIF  = gifWithImage()
	minimalWebP = []byte("RIFF\x16\x00\x00\x00WEBPVP8 \x0a\x00\x00\x000123456789")
	minimalPDF  = []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
	pngBytes    = minimalPNG([]byte("body"))
	webpBytes   = minimalWebP
)

// pngWithSize is a chunk-valid PNG whose IHDR declares width x height.
func pngWithSize(width, height uint32) []byte {
	ihdr := binary.BigEndian.AppendUint32(nil, width)
	ihdr = binary.BigEndian.AppendUint32(ihdr, height)
	ihdr = append(ihdr, 8, 0, 0, 0, 0)
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, pngChunk("IHDR", ihdr)...)
	return append(out, pngChunk("IEND", nil)...)
}
