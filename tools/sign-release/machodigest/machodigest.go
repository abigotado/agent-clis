// Package machodigest computes a signature-independent digest of a thin
// 64-bit little-endian Mach-O file.
//
// The digest is taken over a normalized byte stream: the file bytes before
// LC_CODE_SIGNATURE.dataoff, with three fields a re-sign legitimately changes
// zeroed (the __LINKEDIT vmsize and filesize, and LC_CODE_SIGNATURE.datasize).
// The stream has no framing. Any other difference between two files changes
// it, so equal streams mean equal code, data and load commands, whatever
// signature each file carries. The digest says nothing about the signature
// itself; a caller that cares about entitlements, flags or the designated
// requirement must check them separately.
//
// The parser walks the load commands itself and refuses the layouts that would
// let bytes escape the stream. Every load command lies before __LINKEDIT, so
// the stream covers all of them, and a segment that starts at file offset 0
// covers them. There is one __LINKEDIT, it ends the file and its vmsize covers
// its filesize. There is one LC_CODE_SIGNATURE, 16-aligned, ending the file.
// The file ranges of the load commands listed below (the symbol and string
// tables, the dyld info and its relatives, the linkedit data commands,
// LC_TWOLEVEL_HINTS and LC_NOTE) must end at or before the signature.
//
// Load commands outside that list are skipped without a check: their file
// ranges, if they have any, are not compared with the signature. The list is
// the set of commands the attested CI builds emit, so the tool does not claim
// to refuse every layout it does not understand. A linker command that points
// into the signature region is not seen until it is added here.
package machodigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
)

// MaxSize is the largest input accepted, in bytes.
const MaxSize = 512 << 20

// Rule names the layout rule an input violated.
type Rule string

// The rules machodigest enforces. Each refusal names exactly one.
const (
	RuleSize             Rule = "size-limit"
	RuleThin             Rule = "thin-file"
	RuleFormat           Rule = "macho64-little-endian"
	RuleLoadCommands     Rule = "well-formed-load-commands"
	RuleLinkeditCount    Rule = "single-linkedit"
	RuleLinkeditLast     Rule = "linkedit-last-segment"
	RuleLinkeditEnd      Rule = "linkedit-ends-at-end-of-file"
	RuleLinkeditVMSize   Rule = "linkedit-vmsize-covers-filesize"
	RuleCommandsEnd      Rule = "load-commands-before-linkedit"
	RuleHeaderSegment    Rule = "segment-covers-load-commands"
	RuleSignatureCount   Rule = "single-code-signature"
	RuleSignatureAlign   Rule = "signature-16-aligned"
	RuleSignatureOverlap Rule = "signature-after-linkedit-data"
	RuleSignatureEnd     Rule = "signature-ends-at-end-of-file"
)

// RuleError reports an input that violates a layout rule.
type RuleError struct {
	Rule   Rule
	Detail string
}

// Error describes the violated rule.
func (e *RuleError) Error() string {
	return fmt.Sprintf("refused Mach-O: rule %s: %s", e.Rule, e.Detail)
}

func refuse(rule Rule, format string, args ...any) error {
	return &RuleError{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

const (
	headerSize = 32

	lcSegment            = 0x1
	lcSymtab             = 0x2
	lcDysymtab           = 0xb
	lcTwolevelHints      = 0x16
	lcSegment64          = 0x19
	lcCodeSignature      = 0x1d
	lcSegmentSplitInfo   = 0x1e
	lcDyldInfo           = 0x22
	lcDyldInfoOnly       = 0x80000022
	lcFunctionStarts     = 0x26
	lcDataInCode         = 0x29
	lcDylibCodeSignDrs   = 0x2b
	lcLinkerOptimization = 0x2e
	lcNote               = 0x31
	lcDyldExportsTrie    = 0x80000033
	lcDyldChainedFixups  = 0x80000034
	lcAtomInfo           = 0x36
	lcFunctionVariants   = 0x37
	lcFunctionVariantFix = 0x38
	lcLazyLoadDylibInfo  = 0x3a

	nlist64Size       = 16
	dylibModule64Size = 56
	tocEntrySize      = 8
	indexEntrySize    = 4
	relocationSize    = 8
	twolevelHintSize  = 4

	segmentCommandSize  = 72
	linkeditDataSize    = 16
	dyldInfoSize        = 48
	symtabSize          = 24
	dysymtabSize        = 80
	twolevelHintsSize   = 16
	noteSize            = 40
	noteOffsetAt        = 24
	noteSizeAt          = 32
	signatureAlignment  = 16
	signatureDatasizeAt = 12
	segmentVMSizeAt     = 32
	segmentNameLen      = 16
	segmentFileSizeAt   = 48
)

var (
	macho64LE    = []byte{0xcf, 0xfa, 0xed, 0xfe}
	macho64BE    = []byte{0xfe, 0xed, 0xfa, 0xcf}
	macho32LE    = []byte{0xce, 0xfa, 0xed, 0xfe}
	macho32BE    = []byte{0xfe, 0xed, 0xfa, 0xce}
	fatMagics    = [][]byte{{0xca, 0xfe, 0xba, 0xbe}, {0xca, 0xfe, 0xba, 0xbf}, {0xbe, 0xba, 0xfe, 0xca}, {0xbf, 0xba, 0xfe, 0xca}}
	linkeditName = "__LINKEDIT"
)

type segment struct {
	name     string
	vmsize   uint64
	fileoff  uint64
	filesize uint64
}

// span is a run of bytes the stream replaces with zeros.
type span struct {
	off, size int
}

// layout is what the stream needs from a validated file.
type layout struct {
	dataoff int
	zeroed  []span
}

// Read reads r to its end and refuses an input larger than MaxSize.
func Read(r io.Reader) ([]byte, error) {
	return readLimited(r, MaxSize)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read Mach-O input: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, refuse(RuleSize, "input is larger than %d bytes", limit)
	}
	return data, nil
}

// Write validates data and writes its normalized stream to w. Nothing is
// written when data is refused.
func Write(w io.Writer, data []byte) error {
	l, err := parse(data)
	if err != nil {
		return err
	}
	pos := 0
	for _, z := range l.zeroed {
		if _, err := w.Write(data[pos:z.off]); err != nil {
			return fmt.Errorf("write Mach-O stream: %w", err)
		}
		if _, err := w.Write(make([]byte, z.size)); err != nil {
			return fmt.Errorf("write Mach-O stream: %w", err)
		}
		pos = z.off + z.size
	}
	if _, err := w.Write(data[pos:l.dataoff]); err != nil {
		return fmt.Errorf("write Mach-O stream: %w", err)
	}
	return nil
}

// Sum returns the sha256 of the normalized stream of data.
func Sum(data []byte) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	h := sha256.New()
	if err := Write(h, data); err != nil {
		return sum, err
	}
	h.Sum(sum[:0])
	return sum, nil
}

func parse(data []byte) (layout, error) {
	if int64(len(data)) > MaxSize {
		return layout{}, refuse(RuleSize, "input is larger than %d bytes", MaxSize)
	}
	if err := checkMagic(data); err != nil {
		return layout{}, err
	}
	if len(data) < headerSize {
		return layout{}, refuse(RuleLoadCommands, "file is %d bytes, shorter than the %d-byte header", len(data), headerSize)
	}
	ncmds := binary.LittleEndian.Uint32(data[16:])
	sizeofcmds := binary.LittleEndian.Uint32(data[20:])
	if uint64(headerSize)+uint64(sizeofcmds) > uint64(len(data)) {
		return layout{}, refuse(RuleLoadCommands, "load commands (%d bytes) run past the end of the file", sizeofcmds)
	}

	w := walker{base: headerSize, cmds: data[headerSize : headerSize+int(sizeofcmds)]}
	if err := w.walk(ncmds); err != nil {
		return layout{}, err
	}
	return w.validate(uint64(len(data)), uint64(headerSize)+uint64(sizeofcmds))
}

func checkMagic(data []byte) error {
	if len(data) < 4 {
		return refuse(RuleFormat, "file is %d bytes, too short for a Mach-O magic", len(data))
	}
	magic := data[:4]
	switch {
	case bytes.Equal(magic, macho64LE):
		return nil
	case slices.ContainsFunc(fatMagics, func(m []byte) bool { return bytes.Equal(m, magic) }):
		return refuse(RuleThin, "universal (fat) files are not supported")
	case bytes.Equal(magic, macho32LE), bytes.Equal(magic, macho32BE):
		return refuse(RuleFormat, "32-bit Mach-O is not supported")
	case bytes.Equal(magic, macho64BE):
		return refuse(RuleFormat, "big-endian Mach-O is not supported")
	default:
		return refuse(RuleFormat, "magic %x is not a Mach-O file", magic)
	}
}

type walker struct {
	base int
	cmds []byte

	segments   []segment
	linkedit   []segment
	linkeditAt []int // absolute offsets of the __LINKEDIT segment commands
	signatures []signature

	// The claimed file range that ends last, and where it ends.
	farthestWhat string
	farthestEnd  uint64
}

type signature struct {
	cmdAt    int // absolute offset of the command
	dataoff  uint64
	datasize uint64
}

func (w *walker) walk(ncmds uint32) error {
	off := 0
	for i := range ncmds {
		if len(w.cmds)-off < 8 {
			return refuse(RuleLoadCommands, "load command %d has no room for its header", i)
		}
		cmd := binary.LittleEndian.Uint32(w.cmds[off:])
		size := int(binary.LittleEndian.Uint32(w.cmds[off+4:]))
		if size < 8 || size%8 != 0 || size > len(w.cmds)-off {
			return refuse(RuleLoadCommands, "load command %d has size %d, which is invalid or runs past the commands", i, size)
		}
		if err := w.command(cmd, w.cmds[off:off+size], w.base+off); err != nil {
			return err
		}
		off += size
	}
	// A header that counts fewer commands than sizeofcmds holds would hide the
	// rest from every check, and the stream hashes those bytes as if seen.
	if off != len(w.cmds) {
		return refuse(RuleLoadCommands, "the %d load commands fill %d of the %d bytes the header declares", ncmds, off, len(w.cmds))
	}
	return nil
}

func minSize(name string, body []byte, want int) error {
	if len(body) < want {
		return refuse(RuleLoadCommands, "%s is %d bytes, shorter than its %d-byte layout", name, len(body), want)
	}
	return nil
}

func (w *walker) command(cmd uint32, body []byte, at int) error {
	u32 := func(o int) uint64 { return uint64(binary.LittleEndian.Uint32(body[o:])) }
	switch cmd {
	case lcSegment:
		return refuse(RuleFormat, "32-bit segment command in a 64-bit file")
	case lcSegment64:
		if err := minSize("LC_SEGMENT_64", body, segmentCommandSize); err != nil {
			return err
		}
		name, err := segmentName(body[8 : 8+segmentNameLen])
		if err != nil {
			return err
		}
		seg := segment{
			name:     name,
			vmsize:   binary.LittleEndian.Uint64(body[segmentVMSizeAt:]),
			fileoff:  binary.LittleEndian.Uint64(body[40:]),
			filesize: binary.LittleEndian.Uint64(body[segmentFileSizeAt:]),
		}
		if seg.fileoff+seg.filesize < seg.fileoff {
			return refuse(RuleLoadCommands, "segment %q file range overflows", seg.name)
		}
		w.segments = append(w.segments, seg)
		if seg.name == linkeditName {
			w.linkedit = append(w.linkedit, seg)
			w.linkeditAt = append(w.linkeditAt, at)
		}
	case lcCodeSignature:
		if err := minSize("LC_CODE_SIGNATURE", body, linkeditDataSize); err != nil {
			return err
		}
		w.signatures = append(w.signatures, signature{cmdAt: at, dataoff: u32(8), datasize: u32(12)})
	case lcSegmentSplitInfo, lcFunctionStarts, lcDataInCode, lcDylibCodeSignDrs, lcLinkerOptimization,
		lcDyldExportsTrie, lcDyldChainedFixups, lcAtomInfo, lcFunctionVariants, lcFunctionVariantFix, lcLazyLoadDylibInfo:
		if err := minSize(commandName(cmd), body, linkeditDataSize); err != nil {
			return err
		}
		w.claim(commandName(cmd), u32(8), u32(12))
	case lcDyldInfo, lcDyldInfoOnly:
		if err := minSize("LC_DYLD_INFO", body, dyldInfoSize); err != nil {
			return err
		}
		for i, what := range []string{"rebase", "bind", "weak bind", "lazy bind", "export"} {
			w.claim("LC_DYLD_INFO "+what, u32(8+8*i), u32(12+8*i))
		}
	case lcSymtab:
		if err := minSize("LC_SYMTAB", body, symtabSize); err != nil {
			return err
		}
		w.claim("LC_SYMTAB symbols", u32(8), u32(12)*nlist64Size)
		w.claim("LC_SYMTAB strings", u32(16), u32(20))
	case lcTwolevelHints:
		if err := minSize("LC_TWOLEVEL_HINTS", body, twolevelHintsSize); err != nil {
			return err
		}
		w.claim("LC_TWOLEVEL_HINTS", u32(8), u32(12)*twolevelHintSize)
	case lcNote:
		if err := minSize("LC_NOTE", body, noteSize); err != nil {
			return err
		}
		off := binary.LittleEndian.Uint64(body[noteOffsetAt:])
		size := binary.LittleEndian.Uint64(body[noteSizeAt:])
		if off+size < off {
			return refuse(RuleLoadCommands, "LC_NOTE file range %d+%d overflows", off, size)
		}
		w.claim("LC_NOTE", off, size)
	case lcDysymtab:
		if err := minSize("LC_DYSYMTAB", body, dysymtabSize); err != nil {
			return err
		}
		w.claim("LC_DYSYMTAB table of contents", u32(32), u32(36)*tocEntrySize)
		w.claim("LC_DYSYMTAB module table", u32(40), u32(44)*dylibModule64Size)
		w.claim("LC_DYSYMTAB referenced symbols", u32(48), u32(52)*indexEntrySize)
		w.claim("LC_DYSYMTAB indirect symbols", u32(56), u32(60)*indexEntrySize)
		w.claim("LC_DYSYMTAB external relocations", u32(64), u32(68)*relocationSize)
		w.claim("LC_DYSYMTAB local relocations", u32(72), u32(76)*relocationSize)
	}
	return nil
}

func commandName(cmd uint32) string {
	switch cmd {
	case lcAtomInfo:
		return "LC_ATOM_INFO"
	case lcFunctionVariants:
		return "LC_FUNCTION_VARIANTS"
	case lcFunctionVariantFix:
		return "LC_FUNCTION_VARIANT_FIXUPS"
	case lcLazyLoadDylibInfo:
		return "LC_LAZY_LOAD_DYLIB_INFO"
	case lcSegmentSplitInfo:
		return "LC_SEGMENT_SPLIT_INFO"
	case lcFunctionStarts:
		return "LC_FUNCTION_STARTS"
	case lcDataInCode:
		return "LC_DATA_IN_CODE"
	case lcDylibCodeSignDrs:
		return "LC_DYLIB_CODE_SIGN_DRS"
	case lcLinkerOptimization:
		return "LC_LINKER_OPTIMIZATION_HINT"
	case lcDyldExportsTrie:
		return "LC_DYLD_EXPORTS_TRIE"
	case lcDyldChainedFixups:
		return "LC_DYLD_CHAINED_FIXUPS"
	default:
		return fmt.Sprintf("load command %#x", cmd)
	}
}

// segmentName reads a segment name as a C string: it stops at the first NUL,
// and anything but NUL after it is refused.
func segmentName(raw []byte) (string, error) {
	end := bytes.IndexByte(raw, 0)
	if end < 0 {
		return string(raw), nil
	}
	if rest := raw[end:]; len(bytes.TrimRight(rest, "\x00")) != 0 {
		return "", refuse(RuleLoadCommands, "segment name %q has bytes after its first NUL", raw)
	}
	return string(raw[:end]), nil
}

// claim records a non-empty data range a load command points at. Only the
// range that ends last matters to the overlap rule. The callers have already
// ruled out an overflow of off+size.
func (w *walker) claim(what string, off, size uint64) {
	if size == 0 {
		return
	}
	if end := off + size; end > w.farthestEnd {
		w.farthestWhat, w.farthestEnd = what, end
	}
}

func (w *walker) validate(fileLen, commandsEnd uint64) (layout, error) {
	if len(w.linkedit) != 1 {
		return layout{}, refuse(RuleLinkeditCount, "found %d %s segments, want exactly 1", len(w.linkedit), linkeditName)
	}
	le := w.linkedit[0]
	for _, seg := range w.segments {
		if seg.name == linkeditName {
			continue
		}
		if seg.fileoff > le.fileoff || seg.fileoff+seg.filesize > le.fileoff {
			return layout{}, refuse(RuleLinkeditLast, "segment %q (file range %d..%d) is not before %s at %d",
				seg.name, seg.fileoff, seg.fileoff+seg.filesize, linkeditName, le.fileoff)
		}
	}
	if le.fileoff+le.filesize != fileLen {
		return layout{}, refuse(RuleLinkeditEnd, "%s ends at %d, the file is %d bytes", linkeditName, le.fileoff+le.filesize, fileLen)
	}
	if le.vmsize < le.filesize {
		return layout{}, refuse(RuleLinkeditVMSize, "%s vmsize %d is smaller than its file size %d", linkeditName, le.vmsize, le.filesize)
	}
	// Everything the stream leaves out starts at the signature, which is not
	// before __LINKEDIT, so commands that end before __LINKEDIT are all hashed.
	if commandsEnd > le.fileoff {
		return layout{}, refuse(RuleCommandsEnd, "load commands end at %d, past %s at %d", commandsEnd, linkeditName, le.fileoff)
	}
	if !slices.ContainsFunc(w.segments, func(s segment) bool { return s.fileoff == 0 && s.filesize >= commandsEnd }) {
		return layout{}, refuse(RuleHeaderSegment, "no segment starts at file offset 0 and covers the %d bytes of header and load commands", commandsEnd)
	}

	if len(w.signatures) != 1 {
		return layout{}, refuse(RuleSignatureCount, "found %d LC_CODE_SIGNATURE commands, want exactly 1", len(w.signatures))
	}
	sig := w.signatures[0]
	if sig.dataoff%signatureAlignment != 0 {
		return layout{}, refuse(RuleSignatureAlign, "signature offset %d is not %d-aligned", sig.dataoff, signatureAlignment)
	}
	if sig.dataoff < le.fileoff {
		return layout{}, refuse(RuleSignatureOverlap, "signature offset %d is before %s at %d", sig.dataoff, linkeditName, le.fileoff)
	}
	if w.farthestEnd > sig.dataoff {
		return layout{}, refuse(RuleSignatureOverlap, "%s ends at %d, past the signature offset %d", w.farthestWhat, w.farthestEnd, sig.dataoff)
	}
	if sig.datasize == 0 || sig.dataoff+sig.datasize != fileLen {
		return layout{}, refuse(RuleSignatureEnd, "signature range %d+%d does not end at the %d-byte end of the file", sig.dataoff, sig.datasize, fileLen)
	}

	zeroed := []span{
		{off: w.linkeditAt[0] + segmentVMSizeAt, size: 8},
		{off: w.linkeditAt[0] + segmentFileSizeAt, size: 8},
		{off: sig.cmdAt + signatureDatasizeAt, size: 4},
	}
	// The fields lie inside the load commands, which end before __LINKEDIT and
	// so before the signature, so Write never zeroes past the stream.
	slices.SortFunc(zeroed, func(a, b span) int { return a.off - b.off })
	return layout{dataoff: int(sig.dataoff), zeroed: zeroed}, nil
}
