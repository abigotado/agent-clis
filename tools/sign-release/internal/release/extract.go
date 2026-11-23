package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/macho"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// extractArchive unpacks a .tar.gz held in memory. It accepts exactly the wanted
// member names: every member a regular file whose name has no directory part,
// no "..", no absolute path and no link, no member twice, none missing, none
// extra, and every size bounded.
func extractArchive(data []byte, want []string, lim Limits) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, refuse(StepExtract, "archive is not gzip: %v", err)
	}
	defer func() {
		_ = zr.Close() // reading from memory; Close only reports a checksum state already seen by Read
	}()
	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, refuse(StepExtract, "archive is not a tar stream: %v", err)
		}
		if err := checkMember(hdr, want, files); err != nil {
			return nil, err
		}
		if hdr.Size < 0 || hdr.Size > lim.MaxEntry {
			return nil, refuse(StepExtract, "member %q reports %d bytes, over the limit %d", hdr.Name, hdr.Size, lim.MaxEntry)
		}
		// Refused before the read, so an oversize archive is never inflated.
		if total+hdr.Size > lim.MaxExtracted {
			return nil, refuse(StepExtract, "member %q would take the members together over the limit %d", hdr.Name, lim.MaxExtracted)
		}
		// The tar reader yields at most hdr.Size bytes, which is bounded above.
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, refuse(StepExtract, "read member %q: %v", hdr.Name, err)
		}
		total += int64(len(body))
		files[hdr.Name] = body
	}
	for _, name := range want {
		if _, ok := files[name]; !ok {
			return nil, refuse(StepExtract, "archive lacks the member %q", name)
		}
	}
	return files, nil
}

func checkMember(hdr *tar.Header, want []string, seen map[string][]byte) error {
	switch hdr.Typeflag {
	case tar.TypeReg:
	case tar.TypeSymlink, tar.TypeLink:
		return refuse(StepExtract, "member %q is a link", hdr.Name)
	case tar.TypeDir:
		return refuse(StepExtract, "member %q is a directory", hdr.Name)
	default:
		return refuse(StepExtract, "member %q has the type %q, want a regular file", hdr.Name, string(hdr.Typeflag))
	}
	switch name := hdr.Name; {
	case name == "":
		return refuse(StepExtract, "a member has an empty name")
	case strings.HasPrefix(name, "/") || filepath.IsAbs(name):
		return refuse(StepExtract, "member %q is an absolute path", name)
	case name == "." || name == ".." || strings.Contains(name, ".."):
		return refuse(StepExtract, "member %q contains a parent reference", name)
	case strings.ContainsAny(name, "/\\\x00"):
		return refuse(StepExtract, "member %q has a directory part", name)
	}
	if _, dup := seen[hdr.Name]; dup {
		return refuse(StepExtract, "member %q appears twice", hdr.Name)
	}
	if !slices.Contains(want, hdr.Name) {
		return refuse(StepExtract, "member %q is not one of %v", hdr.Name, want)
	}
	return nil
}

// checkMachO requires data to be a thin Mach-O executable of the wanted CPU.
// Universal files are refused by magic before any parser sees them.
func checkMachO(name string, data []byte, want macho.Cpu) error {
	if len(data) < 4 {
		return refuse(StepMachO, "%q is %d bytes, too short for a Mach-O", name, len(data))
	}
	switch magic := data[:4]; {
	case bytes.Equal(magic, []byte{0xca, 0xfe, 0xba, 0xbe}), bytes.Equal(magic, []byte{0xca, 0xfe, 0xba, 0xbf}),
		bytes.Equal(magic, []byte{0xbe, 0xba, 0xfe, 0xca}), bytes.Equal(magic, []byte{0xbf, 0xba, 0xfe, 0xca}):
		return refuse(StepMachO, "%q is a universal (fat) binary, want a thin one", name)
	}
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return refuse(StepMachO, "%q is not a Mach-O file: %v", name, err)
	}
	defer func() {
		_ = f.Close() // reads from memory; nothing to flush
	}()
	if f.Type != macho.TypeExec {
		return refuse(StepMachO, "%q has the Mach-O type %v, want an executable", name, f.Type)
	}
	if f.Cpu != want {
		return refuse(StepMachO, "%q is built for CPU %v, want %v", name, f.Cpu, want)
	}
	return nil
}

// writeMembers writes the members into a new 0700 directory below parent and
// returns it. Files are created 0600, never executable.
func writeMembers(parent, sub string, files map[string][]byte, order []string) (string, error) {
	dir := filepath.Join(parent, sub)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("create extraction directory: %w", err)
	}
	for _, name := range order {
		if err := writeNew(filepath.Join(dir, name), files[name]); err != nil {
			return "", err
		}
	}
	return dir, nil
}
