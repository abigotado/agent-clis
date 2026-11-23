package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

// downloaded is an asset held in memory and written to the work directory.
type downloaded struct {
	data []byte
	path string
}

// downloadAsset fetches one asset by ID through gh and writes it to dir. The
// reported size and the received bytes are both held to limit, and they must
// agree.
func downloadAsset(ctx context.Context, r runner.Runner, gh, repo, dir string, a asset, limit int64) (downloaded, error) {
	data, err := fetchAsset(ctx, r, gh, repo, a, limit)
	if err != nil {
		return downloaded{}, err
	}
	path := filepath.Join(dir, a.Name)
	if err := writeNew(path, data); err != nil {
		return downloaded{}, err
	}
	return downloaded{data: data, path: path}, nil
}

// fetchAsset fetches one asset by ID through gh and holds it in memory.
func fetchAsset(ctx context.Context, r runner.Runner, gh, repo string, a asset, limit int64) ([]byte, error) {
	if a.Size > limit {
		return nil, refuse(StepDownload, "asset %q reports %d bytes, over the limit %d", a.Name, a.Size, limit)
	}
	argv := apiArgv(gh, "repos/"+repo+"/releases/assets/"+strconv.FormatInt(a.ID, 10), "-H", "Accept: application/octet-stream")
	stdout, _, err := r.Run(ctx, argv, nil)
	if err != nil {
		return nil, fmt.Errorf("download asset %q: %w", a.Name, err)
	}
	if int64(len(stdout)) > limit {
		return nil, refuse(StepDownload, "asset %q delivered %d bytes, over the limit %d", a.Name, len(stdout), limit)
	}
	if int64(len(stdout)) != a.Size {
		return nil, refuse(StepDownload, "asset %q delivered %d bytes, the release reports %d", a.Name, len(stdout), a.Size)
	}
	return stdout, nil
}

// writeNew creates path exclusively with mode 0600 and writes data. The name
// is never a symbolic link target: O_EXCL refuses an existing entry.
func writeNew(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("close %s: %w", path, cerr)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

var checksumLine = regexp.MustCompile(`^([0-9a-f]{64})  ([^\x00-\x1f/\\ ]+)$`)

// parseChecksums reads a checksums file in the `<hex>  <name>` format. It must
// list exactly the wanted names, each once, with lowercase hex, two spaces, LF
// line ends and no blank or extra lines.
func parseChecksums(data []byte, want []string) (map[string][sha256.Size]byte, error) {
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		return nil, refuse(StepChecksum, "checksums file does not end in a newline")
	}
	sums := map[string][sha256.Size]byte{}
	for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		m := checksumLine.FindStringSubmatch(line)
		if m == nil {
			return nil, refuse(StepChecksum, "line %d is not `<64 lowercase hex>  <name>`", i+1)
		}
		if !slices.Contains(want, m[2]) {
			return nil, refuse(StepChecksum, "line %d lists the unexpected name %q", i+1, m[2])
		}
		if _, dup := sums[m[2]]; dup {
			return nil, refuse(StepChecksum, "line %d lists %q a second time", i+1, m[2])
		}
		var sum [sha256.Size]byte
		if _, err := hex.Decode(sum[:], []byte(m[1])); err != nil {
			return nil, refuse(StepChecksum, "line %d: bad digest: %v", i+1, err)
		}
		sums[m[2]] = sum
	}
	for _, name := range want {
		if _, ok := sums[name]; !ok {
			return nil, refuse(StepChecksum, "checksums file does not list %q", name)
		}
	}
	return sums, nil
}

func verifySum(name string, data []byte, want [sha256.Size]byte) error {
	got := sha256.Sum256(data)
	if !bytes.Equal(got[:], want[:]) {
		return refuse(StepChecksum, "sha256 of %q is %x, checksums file says %x", name, got, want)
	}
	return nil
}
