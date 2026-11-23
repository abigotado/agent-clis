package machodigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/machofixture"
)

// goldenDigest pins the stream of the default fixture. A change to the
// normalization or to the fixture shows up here first.
const goldenDigest = "e037f6b39ebd7880084b511d8c48ac3fbabe7a89dd5ad03156d8fdf71236715e"

func sumHex(t *testing.T, data []byte) string {
	t.Helper()
	sum, err := Sum(data)
	if err != nil {
		t.Fatalf("Sum() error = %v", err)
	}
	return hex.EncodeToString(sum[:])
}

func put32(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
func put64(b []byte, at int, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }

func TestSumIsStable(t *testing.T) {
	t.Parallel()

	f := machofixture.Build(machofixture.Spec{})
	first := sumHex(t, f.Bytes)
	if again := sumHex(t, machofixture.Build(machofixture.Spec{}).Bytes); again != first {
		t.Fatalf("digest changed between identical builds: %s vs %s", first, again)
	}
	if first != goldenDigest {
		t.Fatalf("digest = %s, want %s", first, goldenDigest)
	}
}

func TestStreamShape(t *testing.T) {
	t.Parallel()

	f := machofixture.Build(machofixture.Spec{})
	var got bytes.Buffer
	if err := Write(&got, f.Bytes); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	want := f.Clone()[:f.SignatureOff]
	put64(want, f.LinkeditCmdAt+32, 0)
	put64(want, f.LinkeditCmdAt+48, 0)
	put32(want, f.SignatureCmdAt+12, 0)
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("stream differs from the expected prefix with three zeroed fields (got %d bytes, want %d)", got.Len(), len(want))
	}
	if sum, err := Sum(f.Bytes); err != nil || sum != sha256.Sum256(want) {
		t.Fatalf("Sum() = %x, %v, want sha256 of the stream", sum, err)
	}
}

func TestDigestIgnoresWhatAReSignChanges(t *testing.T) {
	t.Parallel()

	base := machofixture.Build(machofixture.Spec{})
	want := sumHex(t, base.Bytes)

	tests := []struct {
		name string
		file machofixture.File
	}{
		{name: "different signature blob", file: machofixture.Build(machofixture.Spec{Signature: bytes.Repeat([]byte{0xaa}, 64)})},
		{name: "longer signature changes datasize and linkedit sizes", file: machofixture.Build(machofixture.Spec{Signature: bytes.Repeat([]byte{0x55}, 20000)})},
		{name: "shorter signature", file: machofixture.Build(machofixture.Spec{Signature: bytes.Repeat([]byte{0x01}, 16)})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sumHex(t, tt.file.Bytes); got != want {
				t.Fatalf("digest = %s, want %s", got, want)
			}
		})
	}

	t.Run("fixture sizes really differ", func(t *testing.T) {
		t.Parallel()
		long := machofixture.Build(machofixture.Spec{Signature: bytes.Repeat([]byte{0x55}, 20000)})
		for _, at := range []int{long.LinkeditCmdAt + 32, long.LinkeditCmdAt + 48, long.SignatureCmdAt + 12} {
			if bytes.Equal(long.Bytes[at:at+4], base.Bytes[at:at+4]) {
				t.Fatalf("field at %d is identical, the test would prove nothing", at)
			}
		}
	})

	t.Run("sizes altered in place", func(t *testing.T) {
		t.Parallel()
		b := base.Clone()
		put64(b, base.LinkeditCmdAt+32, 0x123456)
		// filesize and datasize cannot change without breaking the end-of-file
		// rules, so they are exercised by the longer-signature case above.
		if got := sumHex(t, b); got != want {
			t.Fatalf("digest = %s, want %s", got, want)
		}
	})
}

func TestDigestChangesWithAnythingElse(t *testing.T) {
	t.Parallel()

	base := machofixture.Build(machofixture.Spec{})
	want := sumHex(t, base.Bytes)

	tests := []struct {
		name   string
		mutate func(b []byte, f machofixture.File)
	}{
		{name: "__TEXT byte", mutate: func(b []byte, f machofixture.File) { b[f.TextByteAt] ^= 1 }},
		{name: "linkedit data before the signature", mutate: func(b []byte, f machofixture.File) { b[f.SignatureOff-1] ^= 1 }},
		{name: "header flags", mutate: func(b []byte, f machofixture.File) { b[f.FlagsAt] ^= 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := base.Clone()
			tt.mutate(b, base)
			if got := sumHex(t, b); got == want {
				t.Fatal("digest did not change")
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	t.Parallel()

	base := machofixture.Build(machofixture.Spec{})
	tests := []struct {
		name string
		data func() []byte
		rule Rule
	}{
		{name: "empty", data: func() []byte { return nil }, rule: RuleFormat},
		{name: "not a Mach-O", data: func() []byte { return []byte("#!/bin/sh\n") }, rule: RuleFormat},
		{name: "truncated header", data: func() []byte { return base.Bytes[:20] }, rule: RuleLoadCommands},
		{name: "truncated inside load commands", data: func() []byte { return base.Bytes[:100] }, rule: RuleLoadCommands},
		{name: "truncated by one byte", data: func() []byte { return base.Bytes[:len(base.Bytes)-1] }, rule: RuleLinkeditEnd},
		{name: "truncated inside the signature", data: func() []byte { return base.Bytes[:base.SignatureOff+10] }, rule: RuleLinkeditEnd},
		{name: "fat file", data: func() []byte {
			b := base.Clone()
			copy(b, []byte{0xca, 0xfe, 0xba, 0xbe})
			return b
		}, rule: RuleThin},
		{name: "fat64 file", data: func() []byte {
			b := base.Clone()
			copy(b, []byte{0xca, 0xfe, 0xba, 0xbf})
			return b
		}, rule: RuleThin},
		{name: "32-bit", data: func() []byte {
			b := base.Clone()
			copy(b, []byte{0xce, 0xfa, 0xed, 0xfe})
			return b
		}, rule: RuleFormat},
		{name: "big-endian", data: func() []byte {
			b := base.Clone()
			copy(b, []byte{0xfe, 0xed, 0xfa, 0xcf})
			return b
		}, rule: RuleFormat},
		{name: "32-bit segment command", data: func() []byte {
			b := base.Clone()
			put32(b, base.TextCmdAt, 0x1)
			return b
		}, rule: RuleFormat},
		{name: "load command runs past the commands", data: func() []byte {
			b := base.Clone()
			put32(b, base.TextCmdAt+4, 0x10000)
			return b
		}, rule: RuleLoadCommands},
		{name: "load command size not a multiple of 8", data: func() []byte {
			b := base.Clone()
			put32(b, base.TextCmdAt+4, 74)
			return b
		}, rule: RuleLoadCommands},
		{name: "two LC_CODE_SIGNATURE", data: func() []byte {
			return machofixture.Build(machofixture.Spec{ExtraSignatureCommands: 1}).Bytes
		}, rule: RuleSignatureCount},
		{name: "no LC_CODE_SIGNATURE", data: func() []byte {
			b := base.Clone()
			put32(b, base.SignatureCmdAt, 0x32) // LC_BUILD_VERSION, which the walker skips
			return b
		}, rule: RuleSignatureCount},
		{name: "misaligned dataoff", data: func() []byte {
			return machofixture.Build(machofixture.Spec{SignatureGap: 1}).Bytes
		}, rule: RuleSignatureAlign},
		{name: "signature before the end of linkedit data without gap", data: func() []byte {
			b := base.Clone()
			put32(b, base.SignatureCmdAt+8, uint32(base.SignatureOff-16))
			put32(b, base.SignatureCmdAt+12, uint32(base.SignatureSize+16))
			return b
		}, rule: RuleSignatureOverlap},
		{name: "signature before __LINKEDIT", data: func() []byte {
			b := base.Clone()
			put32(b, base.SignatureCmdAt+8, 0)
			put32(b, base.SignatureCmdAt+12, uint32(len(b)))
			return b
		}, rule: RuleSignatureOverlap},
		{name: "trailing bytes after the signature", data: func() []byte {
			return append(base.Clone(), 0)
		}, rule: RuleLinkeditEnd},
		{name: "signature shorter than the linkedit tail", data: func() []byte {
			b := base.Clone()
			put32(b, base.SignatureCmdAt+12, uint32(base.SignatureSize-16))
			return b
		}, rule: RuleSignatureEnd},
		{name: "empty signature", data: func() []byte {
			b := base.Clone()
			put32(b, base.SignatureCmdAt+8, uint32(len(b)))
			put32(b, base.SignatureCmdAt+12, 0)
			return b
		}, rule: RuleSignatureEnd},
		{name: "no __LINKEDIT", data: func() []byte {
			b := base.Clone()
			copy(b[base.LinkeditCmdAt+8:], "__LINKEDIX\x00")
			return b
		}, rule: RuleLinkeditCount},
		{name: "two __LINKEDIT", data: func() []byte {
			b := base.Clone()
			copy(b[base.TextCmdAt+8:], "__LINKEDIT\x00")
			return b
		}, rule: RuleLinkeditCount},
		{name: "__LINKEDIT is not last", data: func() []byte {
			b := base.Clone()
			put64(b, base.TextCmdAt+48, 0x1010)
			return b
		}, rule: RuleLinkeditLast},
		{name: "__LINKEDIT filesize short of the file", data: func() []byte {
			b := base.Clone()
			put64(b, base.LinkeditCmdAt+48, uint64(len(b)-0x1000-16))
			return b
		}, rule: RuleLinkeditEnd},
		{name: "__LINKEDIT filesize overflows", data: func() []byte {
			b := base.Clone()
			put64(b, base.LinkeditCmdAt+48, ^uint64(0))
			return b
		}, rule: RuleLoadCommands},
		{name: "load command size 0", data: func() []byte {
			b := base.Clone()
			put32(b, base.TextCmdAt+4, 0)
			return b
		}, rule: RuleLoadCommands},
		{name: "ncmds larger than the commands present", data: func() []byte {
			b := base.Clone()
			put32(b, 16, binary.LittleEndian.Uint32(b[16:])+1)
			return b
		}, rule: RuleLoadCommands},
		{name: "ncmds smaller drops the signature command", data: func() []byte {
			b := base.Clone()
			put32(b, 16, binary.LittleEndian.Uint32(b[16:])-1)
			return b
		}, rule: RuleLoadCommands},
		{name: "__LINKEDIT vmsize smaller than filesize", data: func() []byte {
			b := base.Clone()
			put64(b, base.LinkeditCmdAt+32, binary.LittleEndian.Uint64(b[base.LinkeditCmdAt+48:])-1)
			return b
		}, rule: RuleLinkeditVMSize},
		{name: "__LINKEDIT vmsize zero", data: func() []byte {
			b := base.Clone()
			put64(b, base.LinkeditCmdAt+32, 0)
			return b
		}, rule: RuleLinkeditVMSize},
		{name: "sizeofcmds reaches past the commands the header counts", data: func() []byte {
			b := base.Clone()
			put32(b, 20, 0x1000) // the commands fill fewer bytes than this
			return b
		}, rule: RuleLoadCommands},
		{name: "no segment covers the load commands", data: func() []byte {
			b := base.Clone()
			put64(b, base.TextCmdAt+48, 0x10)
			return b
		}, rule: RuleHeaderSegment},
		{name: "no segment starts at file offset 0", data: func() []byte {
			b := base.Clone()
			put64(b, base.TextCmdAt+40, 8)
			put64(b, base.TextCmdAt+48, 0x1000-8)
			return b
		}, rule: RuleHeaderSegment},
		{name: "__LINKEDIT name has bytes after its NUL", data: func() []byte {
			b := base.Clone()
			b[base.LinkeditCmdAt+8+11] = 'X'
			return b
		}, rule: RuleLoadCommands},
		{name: "__TEXT name has bytes after its NUL", data: func() []byte {
			b := base.Clone()
			b[base.TextCmdAt+8+7] = 'X'
			return b
		}, rule: RuleLoadCommands},
		{name: "LC_NOTE range overflows", data: func() []byte {
			b := base.Clone()
			put64(b, base.Cmds["LC_NOTE"]+24, ^uint64(0)-7)
			put64(b, base.Cmds["LC_NOTE"]+32, 16)
			return b
		}, rule: RuleLoadCommands},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := tt.data()
			assertRefused(t, tt.rule, func() error { return Write(io.Discard, data) })
			assertRefused(t, tt.rule, func() error { _, err := Sum(data); return err })
		})
	}
}

func assertRefused(t *testing.T, rule Rule, call func() error) {
	t.Helper()
	err := call()
	var re *RuleError
	if !errors.As(err, &re) {
		t.Fatalf("error = %v, want a *RuleError", err)
	}
	if re.Rule != rule {
		t.Fatalf("rule = %s, want %s (%v)", re.Rule, rule, err)
	}
	if !strings.Contains(err.Error(), string(rule)) {
		t.Fatalf("error %q does not name rule %s", err, rule)
	}
}

// pastSignature stretches the range r of b to end past the signature.
func pastSignature(b []byte, f machofixture.File, r machofixture.Range) {
	if r.Wide {
		off := int(binary.LittleEndian.Uint64(b[r.OffAt:]))
		// The smallest count whose range ends one byte or more past the signature.
		put64(b, r.CountAt, uint64((f.SignatureOff-off)/r.Unit+1))
		return
	}
	off := int(binary.LittleEndian.Uint32(b[r.OffAt:]))
	put32(b, r.CountAt, uint32((f.SignatureOff-off)/r.Unit+1))
}

func TestOverlappingLinkeditData(t *testing.T) {
	t.Parallel()

	base := machofixture.Build(machofixture.Spec{})
	if len(base.Ranges) == 0 {
		t.Fatal("fixture has no linkedit data ranges")
	}
	for _, r := range base.Ranges {
		t.Run(r.Name, func(t *testing.T) {
			t.Parallel()
			b := base.Clone()
			pastSignature(b, base, r)
			assertRefused(t, RuleSignatureOverlap, func() error { return Write(io.Discard, b) })
		})
	}

	t.Run("the covered commands", func(t *testing.T) {
		t.Parallel()
		names := make(map[string]bool)
		for _, r := range base.Ranges {
			names[r.Name] = true
		}
		for _, want := range []string{
			"dysymtab table of contents", "dysymtab module table", "dysymtab referenced symbols",
			"LC_SEGMENT_SPLIT_INFO", "LC_DYLIB_CODE_SIGN_DRS", "LC_LINKER_OPTIMIZATION_HINT",
			"LC_ATOM_INFO", "LC_FUNCTION_VARIANTS", "LC_FUNCTION_VARIANT_FIXUPS", "LC_LAZY_LOAD_DYLIB_INFO",
			"LC_TWOLEVEL_HINTS", "LC_NOTE",
		} {
			if !names[want] {
				t.Errorf("fixture has no range named %q", want)
			}
		}
	})

	t.Run("LC_DYLD_INFO without the required bit", func(t *testing.T) {
		t.Parallel()
		b := base.Clone()
		put32(b, base.Cmds["LC_DYLD_INFO_ONLY"], 0x22)
		if _, err := Sum(b); err != nil {
			t.Fatalf("Sum() error = %v", err)
		}
		for _, r := range base.Ranges {
			if !strings.HasPrefix(r.Name, "dyld info ") {
				continue
			}
			c := bytes.Clone(b)
			pastSignature(c, base, r)
			assertRefused(t, RuleSignatureOverlap, func() error { return Write(io.Discard, c) })
		}
	})

	t.Run("only the farthest range counts and it names the culprit", func(t *testing.T) {
		t.Parallel()
		b := base.Clone()
		for _, r := range base.Ranges {
			if r.Name == "LC_NOTE" {
				pastSignature(b, base, r)
			}
		}
		err := Write(io.Discard, b)
		assertRefused(t, RuleSignatureOverlap, func() error { return err })
		if !strings.Contains(err.Error(), "LC_NOTE") {
			t.Fatalf("error %q does not name LC_NOTE", err)
		}
	})

	t.Run("a command the walker does not know is ignored", func(t *testing.T) {
		t.Parallel()
		// Deliberate: the checked ranges come from the commands CI emits, so an
		// unknown command is skipped whatever it points at.
		b := base.Clone()
		at := base.Cmds["LC_DATA_IN_CODE"]
		put32(b, at, 0x32)
		put32(b, at+12, uint32(len(b)))
		if _, err := Sum(b); err != nil {
			t.Fatalf("Sum() error = %v", err)
		}
	})

	t.Run("a range ending exactly at the signature is accepted", func(t *testing.T) {
		t.Parallel()
		if _, err := Sum(base.Bytes); err != nil {
			t.Fatalf("Sum() error = %v", err)
		}
	})
}

func TestTooSmallCommandSizes(t *testing.T) {
	t.Parallel()

	base := machofixture.Build(machofixture.Spec{})
	tests := []struct {
		name    string
		at      int
		cmd     uint32 // replaces the command id when non-zero
		cmdsize uint32
	}{
		{name: "LC_SEGMENT_64", at: base.TextCmdAt, cmdsize: 64},
		{name: "LC_CODE_SIGNATURE", at: base.SignatureCmdAt, cmdsize: 8},
		{name: "LC_SYMTAB", at: base.Cmds["LC_SYMTAB"], cmdsize: 16},
		{name: "LC_DYSYMTAB", at: base.Cmds["LC_DYSYMTAB"], cmdsize: 72},
		{name: "LC_DYLD_INFO_ONLY", at: base.Cmds["LC_DYLD_INFO_ONLY"], cmdsize: 40},
		{name: "LC_DYLD_INFO", at: base.Cmds["LC_DYLD_INFO_ONLY"], cmd: 0x22, cmdsize: 40},
		{name: "LC_TWOLEVEL_HINTS", at: base.Cmds["LC_TWOLEVEL_HINTS"], cmdsize: 8},
		{name: "LC_NOTE", at: base.Cmds["LC_NOTE"], cmdsize: 32},
	}
	for _, name := range []string{
		"LC_DYLD_CHAINED_FIXUPS", "LC_DYLD_EXPORTS_TRIE", "LC_FUNCTION_STARTS", "LC_DATA_IN_CODE",
		"LC_SEGMENT_SPLIT_INFO", "LC_DYLIB_CODE_SIGN_DRS", "LC_LINKER_OPTIMIZATION_HINT",
		"LC_ATOM_INFO", "LC_FUNCTION_VARIANTS", "LC_FUNCTION_VARIANT_FIXUPS", "LC_LAZY_LOAD_DYLIB_INFO",
	} {
		tests = append(tests, struct {
			name    string
			at      int
			cmd     uint32
			cmdsize uint32
		}{name: name, at: base.Cmds[name], cmdsize: 8})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.at == 0 {
				t.Fatalf("fixture has no %s command", tt.name)
			}
			b := base.Clone()
			if tt.cmd != 0 {
				put32(b, tt.at, tt.cmd)
			}
			put32(b, tt.at+4, tt.cmdsize)
			assertRefused(t, RuleLoadCommands, func() error { return Write(io.Discard, b) })
		})
	}
}

// tinyFile builds a 240-byte thin Mach-O around the given load commands. The
// padding after the commands is zero.
func tinyFile(cmds ...[]byte) []byte {
	var body []byte
	for _, c := range cmds {
		body = append(body, c...)
	}
	b := make([]byte, 240)
	put32(b, 0, 0xfeedfacf)
	put32(b, 12, 2)
	put32(b, 16, uint32(len(cmds)))
	put32(b, 20, uint32(len(body)))
	copy(b[headerSize:], body)
	return b
}

func tinySegment(name string, fileoff, filesize uint64) []byte {
	c := make([]byte, segmentCommandSize)
	put32(c, 0, lcSegment64)
	put32(c, 4, segmentCommandSize)
	copy(c[8:24], name)
	put64(c, 32, 0x4000)
	put64(c, 40, fileoff)
	put64(c, 48, filesize)
	return c
}

func tinySignature(dataoff, datasize uint32) []byte {
	c := make([]byte, linkeditDataSize)
	put32(c, 0, lcCodeSignature)
	put32(c, 4, linkeditDataSize)
	put32(c, 8, dataoff)
	put32(c, 12, datasize)
	return c
}

func tinyCommand(cmd uint32, size int) []byte {
	c := make([]byte, size)
	put32(c, 0, cmd)
	put32(c, 4, uint32(size))
	return c
}

func TestLoadCommandsMustEndBeforeLinkedit(t *testing.T) {
	t.Parallel()

	const lcMain = 0x80000028
	text := tinySegment("__TEXT", 0, 192)
	linkedit := tinySegment("__LINKEDIT", 192, 48)
	sig := tinySignature(192, 48)

	tests := []struct {
		name string
		data []byte
		rule Rule // empty means accepted
	}{
		{name: "commands end exactly where __LINKEDIT starts", data: tinyFile(text, linkedit, sig)},
		{
			// The reviewer's case: LC_MAIN sits at 192..216, at and past dataoff, so
			// the stream stops before it and would never hash it.
			name: "LC_MAIN past dataoff after the signature command",
			data: tinyFile(text, linkedit, sig, tinyCommand(lcMain, 24)),
			rule: RuleCommandsEnd,
		},
		{
			name: "LC_CODE_SIGNATURE itself at or after dataoff",
			data: tinyFile(text, linkedit, tinyCommand(lcMain, 24), sig),
			rule: RuleCommandsEnd,
		},
		{
			name: "segment at offset 0 too short for the commands",
			data: tinyFile(tinySegment("__TEXT", 0, 160), linkedit, sig),
			rule: RuleHeaderSegment,
		},
		{
			name: "no segment at offset 0",
			data: tinyFile(tinySegment("__TEXT", 16, 176), linkedit, sig),
			rule: RuleHeaderSegment,
		},
		{
			name: "__LINKEDIT at offset 0",
			data: tinyFile(text, tinySegment("__LINKEDIT", 0, 240), sig),
			rule: RuleLinkeditLast,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.rule == "" {
				if _, err := Sum(tt.data); err != nil {
					t.Fatalf("Sum() error = %v", err)
				}
				return
			}
			assertRefused(t, tt.rule, func() error { return Write(io.Discard, tt.data) })
		})
	}
}

func TestLoadCommandsMustFillSizeofcmds(t *testing.T) {
	t.Parallel()

	const lcMain = 0x80000028
	// The commands end at 216, before __LINKEDIT at 224, so only the count
	// can reveal that LC_MAIN is not walked.
	cmds := [][]byte{
		tinySegment("__TEXT", 0, 224),
		tinySegment("__LINKEDIT", 224, 16),
		tinySignature(224, 16),
		tinyCommand(lcMain, 24),
	}
	tests := []struct {
		name  string
		ncmds uint32
		rule  Rule // empty means accepted
	}{
		{name: "ncmds counts every command", ncmds: 4},
		{name: "ncmds drops LC_MAIN, which is not the signature", ncmds: 3, rule: RuleLoadCommands},
		{name: "ncmds counts more commands than the bytes hold", ncmds: 5, rule: RuleLoadCommands},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := tinyFile(cmds...)
			put32(data, 16, tt.ncmds)
			if tt.rule == "" {
				if _, err := Sum(data); err != nil {
					t.Fatalf("Sum() error = %v", err)
				}
				return
			}
			assertRefused(t, tt.rule, func() error { return Write(io.Discard, data) })
		})
	}
}

func TestSegmentNamesAreCStrings(t *testing.T) {
	t.Parallel()

	sig := tinySignature(192, 48)
	text := tinySegment("__TEXT", 0, 192)
	tests := []struct {
		name     string
		linkedit string
		accepted bool
	}{
		{name: "NUL padded", linkedit: "__LINKEDIT", accepted: true},
		{name: "bytes after the first NUL", linkedit: "__LINKEDIT\x00junk", accepted: false},
		{name: "a single byte after the first NUL", linkedit: "__LINKEDIT\x00\x00\x00\x00\x00X", accepted: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := tinyFile(text, tinySegment(tt.linkedit, 192, 48), sig)
			if tt.accepted {
				if _, err := Sum(data); err != nil {
					t.Fatalf("Sum() error = %v", err)
				}
				return
			}
			assertRefused(t, RuleLoadCommands, func() error { return Write(io.Discard, data) })
		})
	}

	t.Run("a 16-byte name has no NUL and is not __LINKEDIT", func(t *testing.T) {
		t.Parallel()
		data := tinyFile(text, tinySegment("__LINKEDIT_ABCDEF", 192, 48), sig)
		assertRefused(t, RuleLinkeditCount, func() error { return Write(io.Discard, data) })
	})
}

func FuzzSum(f *testing.F) {
	base := machofixture.Build(machofixture.Spec{})
	f.Add(base.Bytes)
	f.Add(machofixture.Build(machofixture.Spec{Signature: bytes.Repeat([]byte{0xaa}, 16)}).Bytes)
	f.Add(base.Bytes[:base.SignatureOff])
	f.Add(tinyFile(tinySegment("__TEXT", 0, 192), tinySegment("__LINKEDIT", 192, 48), tinySignature(192, 48)))
	f.Add([]byte{0xcf, 0xfa, 0xed, 0xfe})

	f.Fuzz(func(t *testing.T, data []byte) {
		sum, err := Sum(data)
		if err != nil {
			var re *RuleError
			if !errors.As(err, &re) {
				t.Fatalf("Sum() error = %v, want a *RuleError for an in-memory input", err)
			}
			return
		}
		var stream bytes.Buffer
		if err := Write(&stream, data); err != nil {
			t.Fatalf("Write() error = %v after Sum() succeeded", err)
		}
		if sum != sha256.Sum256(stream.Bytes()) {
			t.Fatal("Sum() is not the sha256 of the Write() stream")
		}
	})
}

func TestWriteWritesNothingWhenRefused(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	data := machofixture.Build(machofixture.Spec{SignatureGap: 1}).Bytes
	if err := Write(&out, data); err == nil {
		t.Fatal("Write() error = nil, want a refusal")
	}
	if out.Len() != 0 {
		t.Fatalf("Write() wrote %d bytes before refusing", out.Len())
	}
}

func TestWriteWrapsWriterFailure(t *testing.T) {
	t.Parallel()

	boom := errors.New("disk full")
	err := Write(failingWriter{err: boom}, machofixture.Build(machofixture.Spec{}).Bytes)
	if !errors.Is(err, boom) {
		t.Fatalf("Write() error = %v, want it to wrap %v", err, boom)
	}
	var re *RuleError
	if errors.As(err, &re) {
		t.Fatalf("Write() reported a writer failure as a rule violation: %v", err)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestReadBoundsTheInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   int
		limit   int64
		refused bool
	}{
		{name: "below the limit", input: 9, limit: 10},
		{name: "exactly the limit", input: 10, limit: 10},
		{name: "one byte over", input: 11, limit: 10, refused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := readLimited(bytes.NewReader(make([]byte, tt.input)), tt.limit)
			if tt.refused {
				assertRefused(t, RuleSize, func() error { return err })
				return
			}
			if err != nil || len(data) != tt.input {
				t.Fatalf("readLimited() = %d bytes, %v, want %d bytes", len(data), err, tt.input)
			}
		})
	}

	t.Run("reader failure is not a rule violation", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("io failure")
		_, err := Read(io.MultiReader(strings.NewReader("x"), errReader{boom}))
		var re *RuleError
		if !errors.Is(err, boom) || errors.As(err, &re) {
			t.Fatalf("Read() error = %v, want a wrapped reader error", err)
		}
	})

	t.Run("the public limit is 512 MiB", func(t *testing.T) {
		t.Parallel()
		if MaxSize != 512<<20 {
			t.Fatalf("MaxSize = %d, want %d", MaxSize, 512<<20)
		}
	})
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
