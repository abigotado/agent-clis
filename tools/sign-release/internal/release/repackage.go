package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

// gzipOSUnknown is the fixed value of the gzip header's OS byte (RFC 1952,
// "unknown"), so the archive does not depend on the machine that wrote it.
const gzipOSUnknown = 255

const (
	binaryMode = 0o755
	memberMode = 0o644
)

type commitJSON struct {
	SHA       string `json:"sha"`
	Committer struct {
		Date string `json:"date"`
	} `json:"committer"`
}

var rfc3339UTC = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// parseCommitTime parses a commit date strictly: RFC 3339, UTC written as Z,
// whole seconds, after the epoch.
func parseCommitTime(s string) (time.Time, error) {
	if !rfc3339UTC.MatchString(s) {
		return time.Time{}, refuse(StepRepackage, "commit date %q is not an RFC 3339 UTC time with whole seconds", s)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, refuse(StepRepackage, "commit date %q does not parse: %v", s, err)
	}
	if t.Unix() <= 0 {
		return time.Time{}, refuse(StepRepackage, "commit date %q is not after the epoch", s)
	}
	return t.UTC(), nil
}

// commitTime reads the committer date of the commit the tag points at. Every
// archive member takes it as its mtime, so the archive is a function of the
// release and not of when the tool ran.
func commitTime(ctx context.Context, r runner.Runner, gh string, pl plan, commit string) (time.Time, error) {
	stdout, _, err := r.Run(ctx, apiArgv(gh, "repos/"+pl.repo+"/git/commits/"+commit), nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("read commit %s: %w", commit, err)
	}
	var c commitJSON
	if err := json.Unmarshal(stdout, &c); err != nil {
		return time.Time{}, fmt.Errorf("decode commit %s: %w", commit, err)
	}
	if c.SHA != commit {
		return time.Time{}, refuse(StepRepackage, "commit read answered for %q, want %q", c.SHA, commit)
	}
	return parseCommitTime(c.Committer.Date)
}

// buildArchive writes a deterministic .tar.gz: the members in the given order,
// USTAR headers, uid and gid 0 with no names, the commit time as mtime, mode
// 0755 for the binary and 0644 for the rest, and a gzip header with no name,
// no time and a fixed OS byte. The compression level is pinned. The bytes of
// the compressed stream are those of this Go toolchain's compress/flate, so
// the golden in the tests moves with a toolchain change that alters it.
func buildArchive(order []string, binary string, files map[string][]byte, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("start gzip: %w", err)
	}
	zw.Header = gzip.Header{OS: gzipOSUnknown}
	tw := tar.NewWriter(zw)
	for _, name := range order {
		body, ok := files[name]
		if !ok {
			return nil, refuse(StepRepackage, "member %q is missing", name)
		}
		mode := int64(memberMode)
		if name == binary {
			mode = binaryMode
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len(body)),
			Mode:     mode,
			ModTime:  mtime,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header %q: %w", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			return nil, fmt.Errorf("write tar member %q: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}
	return buf.Bytes(), nil
}

// buildChecksums renders `<hex>  <name>` lines, in the order given, each
// ending in a newline.
func buildChecksums(names []string, files map[string][]byte) []byte {
	var out strings.Builder
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		out.WriteString(hex.EncodeToString(sum[:]))
		out.WriteString("  ")
		out.WriteString(name)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

// outputFile is a file of the upload set.
type outputFile struct {
	name string
	path string
	data []byte
}

// repackage builds the two signed archives and the new checksums file and
// writes them into a new 0700 directory below the work directory. The files
// come back in upload order: amd64, arm64, checksums.
func repackage(workDir string, pl plan, signed [2][]byte, arts [2]Artifact, mtime time.Time) ([]outputFile, error) {
	dir := filepath.Join(workDir, "signed")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create signed directory: %w", err)
	}
	var out []outputFile
	data := map[string][]byte{}
	var names []string
	for i, art := range arts {
		members := make(map[string][]byte, len(art.members))
		for name, body := range art.members {
			members[name] = body
		}
		members[pl.cli] = signed[i]
		archive, err := buildArchive(pl.entries, pl.cli, members, mtime)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", art.ArchiveName, err)
		}
		data[art.ArchiveName] = archive
		names = append(names, art.ArchiveName)
		out = append(out, outputFile{name: art.ArchiveName, path: filepath.Join(dir, art.ArchiveName), data: archive})
	}
	out = append(out, outputFile{name: pl.checksums, path: filepath.Join(dir, pl.checksums), data: buildChecksums(names, data)})
	for _, f := range out {
		if err := writeNew(f.path, f.data); err != nil {
			return nil, err
		}
	}
	return out, nil
}
