// Package machofixture builds small synthetic thin 64-bit Mach-O files for
// tests, so no binary blob is committed. The files are structurally valid for
// machodigest but are not runnable.
package machofixture

import (
	"encoding/binary"
)

const (
	linkeditPage = 0x4000
	textSize     = 0x1000
	headerSize   = 32

	lcSegment64          = 0x19
	lcSymtab             = 0x2
	lcDysymtab           = 0xb
	lcTwolevelHints      = 0x16
	lcCodeSignature      = 0x1d
	lcSegmentSplitInfo   = 0x1e
	lcFunctionStarts     = 0x26
	lcDataInCode         = 0x29
	lcDylibCodeSignDrs   = 0x2b
	lcLinkerOptimization = 0x2e
	lcNote               = 0x31
	lcDyldInfoOnly       = 0x80000022
	lcDyldExportsTrie    = 0x80000033
	lcDyldChainedFixups  = 0x80000034
	lcAtomInfo           = 0x36
	lcFunctionVariants   = 0x37
	lcFunctionVariantFix = 0x38
	lcLazyLoadDylibInfo  = 0x3a
)

// Spec varies the generated file. The zero value is a valid file.
type Spec struct {
	// Signature is the signature blob. Empty selects a 64-byte blob.
	Signature []byte
	// ExtraSignatureCommands adds that many further LC_CODE_SIGNATURE commands.
	ExtraSignatureCommands int
	// SignatureGap inserts that many unused bytes before the signature, which
	// moves its offset off the 16-byte boundary unless it is a multiple of 16.
	SignatureGap int
}

// Range is a file range a load command claims, as the offsets of its
// little-endian offset and count fields. A range ends at its offset plus the
// count times Unit. The fields are uint32, or uint64 when Wide is set.
type Range struct {
	Name    string
	OffAt   int
	CountAt int
	Unit    int
	Wide    bool
}

// File is a generated file and the offsets tests need to alter it.
type File struct {
	Bytes []byte

	// TextCmdAt and LinkeditCmdAt are the offsets of the segment commands.
	TextCmdAt     int
	LinkeditCmdAt int
	// SignatureCmdAt is the offset of the first LC_CODE_SIGNATURE command;
	// SignatureOff and SignatureSize are the range it claims.
	SignatureCmdAt int
	SignatureOff   int
	SignatureSize  int
	// TextByteAt is the offset of a byte inside the __TEXT content.
	TextByteAt int
	// FlagsAt is the offset of the header flags field.
	FlagsAt int
	// Ranges are the linkedit data ranges other than the signature.
	Ranges []Range
	// Cmds maps a load command name (LC_SYMTAB, LC_DYSYMTAB, LC_DYLD_INFO_ONLY,
	// LC_NOTE and the linkedit data commands) to its offset.
	Cmds map[string]int
}

// Build returns the file described by spec.
func Build(spec Spec) File {
	sig := spec.Signature
	if len(sig) == 0 {
		sig = pattern(64, 5)
	}

	f := File{Cmds: map[string]int{}}
	b := &builder{}
	b.u32(0xfeedfacf)
	b.u32(0x0100000c) // CPU_TYPE_ARM64
	b.u32(0)
	b.u32(2) // MH_EXECUTE
	ncmdsAt := b.skip(4)
	sizeAt := b.skip(4)
	f.FlagsAt = len(b.buf)
	b.u32(0x200085)
	b.u32(0)

	cmdsStart := len(b.buf)
	// Layout of the linkedit content, in file order. Every size is a multiple
	// of 16 so the last range ends exactly where the signature begins.
	const linkeditStart = textSize
	cursor := linkeditStart
	alloc := func(size int) int {
		at := cursor
		cursor += size
		return at
	}
	rebase, bind, weak, lazy, export := alloc(16), alloc(16), alloc(16), alloc(16), alloc(16)
	fixups := alloc(32)
	trie := alloc(32)
	starts := alloc(16)
	dic := alloc(16)
	syms := alloc(64)
	strs := alloc(32)
	indirect := alloc(16)
	extrel := alloc(16)
	locrel := alloc(16)
	toc := alloc(16)
	modules := alloc(64)
	extref := alloc(16)
	hints := alloc(16)
	splitInfo, drs, linkerOpt := alloc(16), alloc(16), alloc(16)
	atomInfo, variants, variantFixups, lazyLoad := alloc(16), alloc(16), alloc(16), alloc(16)
	note := alloc(16)
	sigOff := cursor + spec.SignatureGap
	linkeditSize := sigOff + len(sig) - linkeditStart

	ncmds := 0
	segment := func(name string, vmaddr, vmsize, fileoff, filesize uint64) int {
		at := len(b.buf)
		ncmds++
		b.u32(lcSegment64)
		b.u32(72)
		b.name(name)
		b.u64(vmaddr)
		b.u64(vmsize)
		b.u64(fileoff)
		b.u64(filesize)
		b.u32(7)
		b.u32(5)
		b.u32(0)
		b.u32(0)
		return at
	}
	dataCmd := func(cmd uint32, name string, off, size int) {
		f.Cmds[name] = len(b.buf)
		ncmds++
		b.u32(cmd)
		b.u32(16)
		f.Ranges = append(f.Ranges, Range{Name: name, OffAt: len(b.buf), CountAt: len(b.buf) + 4, Unit: 1})
		b.u32(uint32(off))
		b.u32(uint32(size))
	}

	segment("__PAGEZERO", 0, 0x100000000, 0, 0)
	f.TextCmdAt = segment("__TEXT", 0x100000000, textSize, 0, textSize)
	vmsize := (linkeditSize + linkeditPage - 1) / linkeditPage * linkeditPage
	f.LinkeditCmdAt = segment("__LINKEDIT", 0x100004000, uint64(vmsize), linkeditStart, uint64(linkeditSize))

	ncmds++
	f.Cmds["LC_DYLD_INFO_ONLY"] = len(b.buf)
	b.u32(lcDyldInfoOnly)
	b.u32(48)
	for i, off := range []int{rebase, bind, weak, lazy, export} {
		name := []string{"rebase", "bind", "weak bind", "lazy bind", "export"}[i]
		f.Ranges = append(f.Ranges, Range{Name: "dyld info " + name, OffAt: len(b.buf), CountAt: len(b.buf) + 4, Unit: 1})
		b.u32(uint32(off))
		b.u32(16)
	}

	ncmds++
	f.Cmds["LC_SYMTAB"] = len(b.buf)
	b.u32(lcSymtab)
	b.u32(24)
	f.Ranges = append(f.Ranges, Range{Name: "symtab symbols", OffAt: len(b.buf), CountAt: len(b.buf) + 4, Unit: 16})
	b.u32(uint32(syms))
	b.u32(4)
	f.Ranges = append(f.Ranges, Range{Name: "symtab strings", OffAt: len(b.buf), CountAt: len(b.buf) + 4, Unit: 1})
	b.u32(uint32(strs))
	b.u32(32)

	ncmds++
	f.Cmds["LC_DYSYMTAB"] = len(b.buf)
	b.u32(lcDysymtab)
	b.u32(80)
	dysymtab := len(b.buf)
	b.buf = append(b.buf, make([]byte, 72)...)
	set := func(name string, offField, countField, off, count, unit int) {
		binary.LittleEndian.PutUint32(b.buf[dysymtab+offField:], uint32(off))
		binary.LittleEndian.PutUint32(b.buf[dysymtab+countField:], uint32(count))
		f.Ranges = append(f.Ranges, Range{Name: name, OffAt: dysymtab + offField, CountAt: dysymtab + countField, Unit: unit})
	}
	set("dysymtab table of contents", 24, 28, toc, 2, 8)
	set("dysymtab module table", 32, 36, modules, 1, 56)
	set("dysymtab referenced symbols", 40, 44, extref, 4, 4)
	set("dysymtab indirect symbols", 48, 52, indirect, 4, 4)
	set("dysymtab external relocations", 56, 60, extrel, 2, 8)
	set("dysymtab local relocations", 64, 68, locrel, 2, 8)

	dataCmd(lcDyldChainedFixups, "LC_DYLD_CHAINED_FIXUPS", fixups, 32)
	dataCmd(lcDyldExportsTrie, "LC_DYLD_EXPORTS_TRIE", trie, 32)
	dataCmd(lcFunctionStarts, "LC_FUNCTION_STARTS", starts, 16)
	dataCmd(lcDataInCode, "LC_DATA_IN_CODE", dic, 16)
	dataCmd(lcSegmentSplitInfo, "LC_SEGMENT_SPLIT_INFO", splitInfo, 16)
	dataCmd(lcDylibCodeSignDrs, "LC_DYLIB_CODE_SIGN_DRS", drs, 16)
	dataCmd(lcLinkerOptimization, "LC_LINKER_OPTIMIZATION_HINT", linkerOpt, 16)
	dataCmd(lcAtomInfo, "LC_ATOM_INFO", atomInfo, 16)
	dataCmd(lcFunctionVariants, "LC_FUNCTION_VARIANTS", variants, 16)
	dataCmd(lcFunctionVariantFix, "LC_FUNCTION_VARIANT_FIXUPS", variantFixups, 16)
	dataCmd(lcLazyLoadDylibInfo, "LC_LAZY_LOAD_DYLIB_INFO", lazyLoad, 16)

	ncmds++
	f.Cmds["LC_TWOLEVEL_HINTS"] = len(b.buf)
	b.u32(lcTwolevelHints)
	b.u32(16)
	f.Ranges = append(f.Ranges, Range{Name: "LC_TWOLEVEL_HINTS", OffAt: len(b.buf), CountAt: len(b.buf) + 4, Unit: 4})
	b.u32(uint32(hints))
	b.u32(4)

	ncmds++
	f.Cmds["LC_NOTE"] = len(b.buf)
	b.u32(lcNote)
	b.u32(40)
	b.name("note-owner")
	f.Ranges = append(f.Ranges, Range{Name: "LC_NOTE", OffAt: len(b.buf), CountAt: len(b.buf) + 8, Unit: 1, Wide: true})
	b.u64(uint64(note))
	b.u64(16)

	f.SignatureCmdAt = len(b.buf)
	for range 1 + spec.ExtraSignatureCommands {
		ncmds++
		b.u32(lcCodeSignature)
		b.u32(16)
		b.u32(uint32(sigOff))
		b.u32(uint32(len(sig)))
	}
	binary.LittleEndian.PutUint32(b.buf[ncmdsAt:], uint32(ncmds))
	binary.LittleEndian.PutUint32(b.buf[sizeAt:], uint32(len(b.buf)-cmdsStart))

	// __TEXT content, then the linkedit content and the signature.
	text := pattern(textSize-len(b.buf), 13)
	b.buf = append(b.buf, text...)
	f.TextByteAt = textSize - len(text)/2
	b.buf = append(b.buf, pattern(sigOff-linkeditStart, 7)...)
	b.buf = append(b.buf, sig...)

	f.SignatureOff = sigOff
	f.SignatureSize = len(sig)
	f.Bytes = b.buf
	return f
}

// Clone returns a copy of the file bytes that a test may alter.
func (f File) Clone() []byte {
	return append([]byte(nil), f.Bytes...)
}

type builder struct {
	buf []byte
}

func (b *builder) u32(v uint32) {
	b.buf = binary.LittleEndian.AppendUint32(b.buf, v)
}

func (b *builder) u64(v uint64) {
	b.buf = binary.LittleEndian.AppendUint64(b.buf, v)
}

func (b *builder) skip(n int) int {
	at := len(b.buf)
	b.buf = append(b.buf, make([]byte, n)...)
	return at
}

func (b *builder) name(s string) {
	var raw [16]byte
	copy(raw[:], s)
	b.buf = append(b.buf, raw[:]...)
}

// pattern returns n deterministic non-zero-looking bytes.
func pattern(n, step int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*step + 1)
	}
	return out
}
