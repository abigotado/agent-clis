package release

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

// publishBody is the exact request body of the publishing PATCH. It carries no
// tag_name and no target_commitish, so it cannot move the tag or retarget the
// release; the bytes are pinned by a test.
const publishBody = `{"draft":false}`

type immutableJSON struct {
	Enabled *bool `json:"enabled"`
}

// checkImmutable requires immutable releases on the repository (R13). Anything
// but an answer with enabled true is a refusal that names both causes, because
// gh exits non-zero on 403 and 404 alike and the two cannot be told apart here.
func checkImmutable(ctx context.Context, r runner.Runner, gh string, pl plan) error {
	const causes = "either immutable releases are disabled for the repository or the stored gh login lacks the permission to read the setting; enable the setting in the repository settings and check the login, then run again"
	stdout, stderr, err := r.Run(ctx, apiArgv(gh, "repos/"+pl.repo+"/immutable-releases"), nil)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("read the immutable releases setting: %w", ctxErr)
		}
		var exit *runner.ExitError
		if errors.As(err, &exit) {
			return refuse(StepImmutable, "the immutable releases setting of %s did not answer 200 (%v, stderr %s): %s", pl.repo, err, snippet(stderr), causes)
		}
		return fmt.Errorf("read the immutable releases setting: %w", err)
	}
	var s immutableJSON
	if err := json.Unmarshal(stdout, &s); err != nil {
		return refuse(StepImmutable, "the immutable releases answer of %s is not a JSON object: %v: %s", pl.repo, err, causes)
	}
	if s.Enabled == nil || !*s.Enabled {
		return refuse(StepImmutable, "the immutable releases answer of %s does not say enabled true: %s", pl.repo, causes)
	}
	return nil
}

// prompter asks the operator to type the tag. It owns one buffered reader for
// the whole run, so the second answer is not swallowed by the first read.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

const maxAnswer = 1024

func newPrompter(in io.Reader, out io.Writer) *prompter {
	return &prompter{in: bufio.NewReaderSize(in, maxAnswer), out: out}
}

// maxTries bounds how often one prompt is repeated after a wrong answer.
const maxTries = 3

// confirm prints question and requires the answer to equal tag exactly, with
// no trimming but the line end. A wrong answer asks again, up to maxTries
// answers in all; running out of input or an answer longer than the line
// bound refuses at once.
func (p *prompter) confirm(question, tag string) error {
	for try := 1; ; try++ {
		if _, err := io.WriteString(p.out, question); err != nil {
			return fmt.Errorf("write the prompt: %w", err)
		}
		line, err := p.in.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			return refuse(StepConfirm, "the answer is longer than %d bytes", maxAnswer)
		case err != nil && !errors.Is(err, io.EOF):
			return fmt.Errorf("read the answer: %w", err)
		}
		answer := strings.TrimSuffix(string(line), "\n")
		if answer == tag {
			return nil
		}
		if err != nil || try >= maxTries {
			return refuse(StepConfirm, "the typed answer %s is not the tag %s (answer %d of %d)", strconv.Quote(answer), strconv.Quote(tag), try, maxTries)
		}
		if _, werr := fmt.Fprintf(p.out, "not the tag; try again (%d of %d)\n", try, maxTries); werr != nil {
			return fmt.Errorf("write the prompt: %w", werr)
		}
	}
}

// uploadRepo is the --repo value of gh release upload. That command has no
// --hostname flag, but its --repo takes [HOST/]OWNER/REPO, so the host is part
// of the value and neither GH_HOST nor a saved default host can redirect it.
func uploadRepo(pl plan) string { return ghHost + "/" + pl.repo }

// uploadFiles uploads the signed files to the draft.
func uploadFiles(ctx context.Context, r runner.Runner, gh string, pl plan, files []outputFile) error {
	argv := []string{gh, "release", "upload", pl.tag}
	for _, f := range files {
		argv = append(argv, f.path)
	}
	argv = append(argv, "--clobber", "--repo", uploadRepo(pl))
	_, _, err := runStep(ctx, r, StepUpload, "gh release upload", argv, nil)
	return err
}

type assetDetail struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type releaseDetail struct {
	ID        int64         `json:"id"`
	TagName   string        `json:"tag_name"`
	Draft     bool          `json:"draft"`
	Immutable *bool         `json:"immutable"`
	Assets    []assetDetail `json:"assets"`
}

// readRelease reads the release by ID, never by tag, and checks it is the same
// release.
func readRelease(ctx context.Context, r runner.Runner, gh string, pl plan, id int64, step Step) (releaseDetail, error) {
	stdout, _, err := r.Run(ctx, apiArgv(gh, "repos/"+pl.repo+"/releases/"+strconv.FormatInt(id, 10)), nil)
	if err != nil {
		return releaseDetail{}, fmt.Errorf("read release %d: %w", id, err)
	}
	var rel releaseDetail
	if err := json.Unmarshal(stdout, &rel); err != nil {
		return releaseDetail{}, fmt.Errorf("decode release %d: %w", id, err)
	}
	if rel.ID != id {
		return releaseDetail{}, refuse(step, "release read answered for id %d, want %d", rel.ID, id)
	}
	if rel.TagName != pl.tag {
		return releaseDetail{}, refuse(step, "release %d has the tag %q, want %q", id, rel.TagName, pl.tag)
	}
	if len(rel.Assets) > maxAssets {
		return releaseDetail{}, refuse(step, "release %d has %d assets, more than the bound %d", id, len(rel.Assets), maxAssets)
	}
	return rel, nil
}

// checkAssetSet requires the release to hold exactly the expected assets, the
// Linux ones untouched (same IDs as when the draft was resolved) and each
// darwin one equal to what was uploaded. The asset's digest field is compared;
// when GitHub does not report it the asset is downloaded and hashed.
func checkAssetSet(ctx context.Context, r runner.Runner, gh string, pl plan, limits Limits, step Step, rel releaseDetail, before map[string]int64, local []outputFile) error {
	seen := map[string]assetDetail{}
	for _, a := range rel.Assets {
		if !slices.Contains(pl.expected, a.Name) {
			return refuse(step, "release has the unexpected asset %q", a.Name)
		}
		if _, dup := seen[a.Name]; dup {
			return refuse(step, "release has the asset %q more than once", a.Name)
		}
		seen[a.Name] = a
	}
	for _, name := range pl.expected {
		if _, ok := seen[name]; !ok {
			return refuse(step, "release lacks the asset %q", name)
		}
	}
	darwin := map[string]outputFile{}
	for _, f := range local {
		darwin[f.name] = f
	}
	for _, name := range pl.expected {
		a := seen[name]
		f, isDarwin := darwin[name]
		if !isDarwin {
			if a.ID != before[name] {
				return refuse(step, "asset %q was replaced (id %d, was %d); only the darwin assets may change", name, a.ID, before[name])
			}
			continue
		}
		sum := sha256.Sum256(f.data)
		want := "sha256:" + hex.EncodeToString(sum[:])
		if a.Size != int64(len(f.data)) {
			return refuse(step, "asset %q is %d bytes, uploaded %d", name, a.Size, len(f.data))
		}
		if a.Digest == "" {
			data, err := fetchAsset(ctx, r, gh, pl.repo, asset{ID: a.ID, Name: a.Name, Size: a.Size}, limits.MaxArchive)
			if err != nil {
				return err
			}
			got := sha256.Sum256(data)
			if got != sum {
				return refuse(step, "asset %q downloaded back has sha256 %x, uploaded %x", name, got, sum)
			}
			continue
		}
		if a.Digest != want {
			return refuse(step, "asset %q has the digest %q, uploaded %q", name, a.Digest, want)
		}
	}
	return nil
}

// checkIdentity lists the releases and requires exactly one with the tag, the
// pinned one, still a draft. gh release upload finds its target by tag, so a
// second release with the tag, or the pinned one replaced, could take the
// files; the refusal names the IDs found.
func checkIdentity(ctx context.Context, r runner.Runner, gh string, pl plan, id int64, when string) error {
	releases, err := listReleases(ctx, r, gh, pl.repo)
	if err != nil {
		return err
	}
	var ids []int64
	draft := false
	for _, rel := range releases {
		if rel.TagName == pl.tag {
			ids = append(ids, rel.ID)
			draft = rel.Draft
		}
	}
	if len(ids) != 1 || ids[0] != id {
		return refuse(StepUpload, "%s the releases with the tag %q have the IDs %v, want exactly the pinned release %d", when, pl.tag, ids, id)
	}
	if !draft {
		return refuse(StepUpload, "%s the pinned release %d is not a draft", when, id)
	}
	return nil
}

// recheckFiles requires every file of the upload set to still hold the bytes
// the tool built and verified. gh reads the files itself, so this is the last
// look before it does; the digest check after the upload remains.
func recheckFiles(files []outputFile, limit int64) error {
	for _, f := range files {
		data, err := readRegular(StepUpload, f.path, limit)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, f.data) {
			return refuse(StepUpload, "%s changed on disk after it was built", f.path)
		}
	}
	return nil
}

// checkTag requires the tag to still point at the attested commit.
func checkTag(ctx context.Context, r runner.Runner, gh string, pl plan, commit string) error {
	got, err := tagCommit(ctx, r, gh, pl)
	if err != nil {
		return err
	}
	if got != commit {
		return refuse(StepTag, "tag %q now points at %s, the attested commit is %s", pl.tag, got, commit)
	}
	return nil
}

// publish sends the one PATCH that makes the draft public. No earlier failure
// reaches it: the caller returns before this on any error.
func publish(ctx context.Context, r runner.Runner, gh string, pl plan, id int64) error {
	argv := []string{gh, "api", "--hostname", ghHost, "-X", "PATCH", "repos/" + pl.repo + "/releases/" + strconv.FormatInt(id, 10), "--input", "-"}
	if _, _, err := r.Run(ctx, argv, []byte(publishBody)); err != nil {
		return refuse(StepPublish, "the publishing PATCH did not complete (%v); the release %d may or may not be published; read it with gh before doing anything else, and never retry blindly", err, id)
	}
	return nil
}
