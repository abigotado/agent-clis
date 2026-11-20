package release

import (
	"archive/tar"
	"bytes"
	"debug/macho"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/machofixture"
)

var wantEntries = []string{"LICENSE", "README.md", testCLI}

func smallLimits() Limits {
	return Limits{MaxArchive: 1 << 20, MaxChecksums: 4096, MaxEntry: 1 << 10, MaxExtracted: 2 << 10}
}

func TestExtractArchive(t *testing.T) {
	body := []byte("data")
	good := []tarEntry{regular("LICENSE", body), regular("README.md", body), regular(testCLI, body)}
	with := func(i int, e tarEntry) []tarEntry {
		out := slices.Clone(good)
		out[i] = e
		return out
	}
	tests := []struct {
		name    string
		entries []tarEntry
		limits  Limits
		reason  string // empty means accepted
	}{
		{name: "exact entry set is accepted", entries: good},
		{name: "path traversal", entries: with(0, regular("../LICENSE", body)), reason: "parent reference"},
		{name: "traversal hidden in the middle", entries: with(0, regular("a/../LICENSE", body)), reason: "parent reference"},
		{name: "absolute path", entries: with(0, regular("/etc/passwd", body)), reason: "absolute path"},
		{name: "directory part", entries: with(0, regular("dir/LICENSE", body)), reason: "directory part"},
		{name: "backslash in the name", entries: with(0, regular(`dir\LICENSE`, body)), reason: "directory part"},
		{name: "symbolic link", entries: with(0, tarEntry{hdr: tar.Header{Name: "LICENSE", Typeflag: tar.TypeSymlink, Linkname: "README.md"}}), reason: "is a link"},
		{name: "hard link", entries: with(0, tarEntry{hdr: tar.Header{Name: "LICENSE", Typeflag: tar.TypeLink, Linkname: "README.md"}}), reason: "is a link"},
		{name: "directory entry", entries: with(0, tarEntry{hdr: tar.Header{Name: "LICENSE/", Typeflag: tar.TypeDir}}), reason: "is a directory"},
		{name: "device entry", entries: with(0, tarEntry{hdr: tar.Header{Name: "LICENSE", Typeflag: tar.TypeChar}}), reason: "regular file"},
		{name: "extra entry", entries: append(slices.Clone(good), regular("EXTRA", body)), reason: "is not one of"},
		{name: "missing entry", entries: good[:2], reason: "lacks the member"},
		{name: "duplicate entry", entries: append(slices.Clone(good), regular("LICENSE", body)), reason: "appears twice"},
		{name: "entry over the per-entry limit", entries: with(2, regular(testCLI, make([]byte, 2<<10))), reason: "reports 2048 bytes, over the limit"},
		{name: "entries over the total limit", entries: []tarEntry{regular("LICENSE", make([]byte, 900)), regular("README.md", make([]byte, 900)), regular(testCLI, make([]byte, 900))}, reason: "together"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lim := tc.limits
			if lim == (Limits{}) {
				lim = smallLimits()
			}
			files, err := extractArchive(makeTarGz(t, tc.entries...), wantEntries, lim)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("extractArchive() error = %v", err)
				}
				if len(files) != 3 || !bytes.Equal(files[testCLI], body) {
					t.Fatalf("files = %v", files)
				}
				return
			}
			if err == nil {
				t.Fatalf("extractArchive() error = nil, want a refusal containing %q", tc.reason)
			}
			wantRefusal(t, err, StepExtract, tc.reason)
		})
	}

	t.Run("not gzip", func(t *testing.T) {
		_, err := extractArchive([]byte("not gzip"), wantEntries, smallLimits())
		wantRefusal(t, err, StepExtract, "not gzip")
	})
	t.Run("gzip around something that is not tar", func(t *testing.T) {
		_, err := extractArchive(makeGzip(t, bytes.Repeat([]byte{0x7f}, 600)), wantEntries, smallLimits())
		wantRefusal(t, err, StepExtract, "not a tar stream")
	})
}

func TestCheckMachO(t *testing.T) {
	fat := func() []byte {
		thin := thinBinary(macho.CpuArm64)
		const offset = 0x4000
		out := make([]byte, offset+len(thin))
		binary.BigEndian.PutUint32(out[0:], 0xcafebabe)
		binary.BigEndian.PutUint32(out[4:], 1)
		binary.BigEndian.PutUint32(out[8:], uint32(macho.CpuArm64))
		binary.BigEndian.PutUint32(out[16:], offset)
		binary.BigEndian.PutUint32(out[20:], uint32(len(thin)))
		copy(out[offset:], thin)
		return out
	}()
	dylib := thinBinary(macho.CpuArm64)
	binary.LittleEndian.PutUint32(dylib[12:], uint32(macho.TypeDylib))

	tests := []struct {
		name   string
		data   []byte
		want   macho.Cpu
		reason string
	}{
		{name: "thin arm64", data: thinBinary(macho.CpuArm64), want: macho.CpuArm64},
		{name: "thin amd64", data: thinBinary(macho.CpuAmd64), want: macho.CpuAmd64},
		{name: "arm64 where amd64 is expected", data: thinBinary(macho.CpuArm64), want: macho.CpuAmd64, reason: "built for CPU"},
		{name: "amd64 where arm64 is expected", data: thinBinary(macho.CpuAmd64), want: macho.CpuArm64, reason: "built for CPU"},
		{name: "fat binary", data: fat, want: macho.CpuArm64, reason: "universal"},
		{name: "text file", data: []byte("#!/bin/sh\necho hi\n"), want: macho.CpuArm64, reason: "not a Mach-O"},
		{name: "empty file", data: nil, want: macho.CpuArm64, reason: "too short"},
		{name: "ELF file", data: append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 64)...), want: macho.CpuAmd64, reason: "not a Mach-O"},
		{name: "dynamic library is not an executable", data: dylib, want: macho.CpuArm64, reason: "want an executable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMachO(testCLI, tc.data, tc.want)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("checkMachO() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkMachO() error = nil, want a refusal containing %q", tc.reason)
			}
			wantRefusal(t, err, StepMachO, tc.reason)
		})
	}
}

// TestUnpackRefusesWhatMachodigestRefuses shows a Mach-O that debug/macho
// accepts but machodigest does not (two code signatures) still stops the run
// and leaves no stream file.
func TestUnpackRefusesWhatMachodigestRefuses(t *testing.T) {
	s := newScenario(t)
	bad := machofixture.Build(machofixture.Spec{ExtraSignatureCommands: 1})
	b := bad.Clone()
	binary.LittleEndian.PutUint32(b[4:], uint32(macho.CpuAmd64))
	binary.LittleEndian.PutUint32(b[bad.Cmds["LC_SYMTAB"]+12:], 0)
	s.replaceArchive(0, makeTarGz(t, regular("LICENSE", nil), regular("README.md", nil), regular(testCLI, b)))
	_, err := s.run()
	if err == nil {
		t.Fatal("Run() error = nil, want a refusal")
	}
	wantRefusal(t, err, StepMachO, "single-code-signature")
	if strings.Contains(err.Error(), "source-digest") {
		t.Fatalf("error reached attestation: %v", err)
	}
}
