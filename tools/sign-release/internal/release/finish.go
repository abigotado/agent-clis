package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

// Console is the operator's terminal.
type Console struct {
	// In supplies the answers to the two tag prompts.
	In io.Reader
	// Out receives the prompts and one line per step; it is stderr.
	Out io.Writer
}

// PublishedAsset is one asset the tool uploaded.
type PublishedAsset struct {
	Name   string
	SHA256 string
}

// Published is what a finished run reports.
type Published struct {
	Tag       string
	ReleaseID int64
	Commit    string
	Assets    []PublishedAsset
}

// Finish performs steps 6 to 11 on the Result of Run: it signs and verifies
// both binaries, repackages the archives, uploads them to the draft, checks the
// tag and publishes. The one PATCH that publishes is reached only when every
// earlier step passed. Every command goes through r and none starts a binary.
func Finish(ctx context.Context, r runner.Runner, p Params, res Result, c Console) (Published, error) {
	pl := res.pl
	if pl.tag == "" || res.Tag != pl.tag || res.ReleaseID <= 0 || !commitPattern.MatchString(res.Commit) {
		return Published{}, refuse(StepPreflight, "the result was not produced by Run")
	}
	if c.In == nil || c.Out == nil {
		return Published{}, refuse(StepPreflight, "the console has no input or output")
	}
	say := func(format string, args ...any) {
		// Progress is best effort: a closed stderr must not stop a run between
		// the upload and the publish.
		_, _ = fmt.Fprintf(c.Out, format+"\n", args...)
	}
	ask := newPrompter(c.In, c.Out)

	// Fail before the first Keychain prompt if the repository cannot publish
	// an immutable release.
	if err := checkImmutable(ctx, r, p.GH, pl); err != nil {
		return Published{}, err
	}
	say("immutable releases: enabled for %s", pl.repo)

	arts := [2]Artifact{res.AMD64, res.ARM64}
	var signed [2][]byte
	for i, art := range arts {
		bin, err := signAndVerify(ctx, r, pl, res.limits, art)
		if err != nil {
			return Published{}, err
		}
		signed[i] = bin
		say("sign %s: signed and verified, machodigest stream unchanged", pl.archives[i].arch)
	}

	mtime, err := commitTime(ctx, r, p.GH, pl, res.Commit)
	if err != nil {
		return Published{}, err
	}
	files, err := repackage(p.WorkDir, pl, signed, arts, mtime)
	if err != nil {
		return Published{}, err
	}
	say("repackage: %d files with mtime %s", len(files), mtime.Format("2006-01-02T15:04:05Z"))

	question := fmt.Sprintf("Type the tag %s to upload %d signed files to the draft release %d of %s (Ctrl-C takes effect only after Enter): ", pl.tag, len(files), res.ReleaseID, pl.repo)
	if err := ask.confirm(question, pl.tag); err != nil {
		return Published{}, err
	}

	// restoreSteps is the one text of how to put the originals back; the notes
	// below share it so they cannot drift.
	restoreSteps := fmt.Sprintf("restore the originals from %s (both darwin archives and %s, as downloaded) with `gh release upload %s <files> --clobber --repo %s`, then run again",
		p.WorkDir, pl.checksums, pl.tag, uploadRepo(pl))
	// From the start of the upload to the PATCH, a failure may leave the draft
	// holding signed assets no attestation covers.
	restore := func(err error) error {
		return fmt.Errorf("%w; the upload may have changed the draft release %d: if it now carries signed darwin assets that no attestation covers, a re-run will refuse it, and then %s",
			err, res.ReleaseID, restoreSteps)
	}
	// After an identity failure it is not proven which release took the files.
	restoreUnproven := func(err error) error {
		return fmt.Errorf("%w; gh uploads to the release it finds for the tag, so it is not proven that release %d took the files: list the releases of %s and, for each draft that carries signed darwin assets (a re-run will refuse it), %s",
			err, res.ReleaseID, pl.tag, restoreSteps)
	}
	if err := checkIdentity(ctx, r, p.GH, pl, res.ReleaseID, "before the upload,"); err != nil {
		return Published{}, err
	}
	if err := recheckFiles(files, res.limits.MaxArchive); err != nil {
		return Published{}, err
	}
	if err := uploadFiles(ctx, r, p.GH, pl, files); err != nil {
		return Published{}, restore(err)
	}
	if err := checkIdentity(ctx, r, p.GH, pl, res.ReleaseID, "after the upload,"); err != nil {
		return Published{}, restoreUnproven(err)
	}
	rel, err := readRelease(ctx, r, p.GH, pl, res.ReleaseID, StepUpload)
	if err != nil {
		return Published{}, restore(err)
	}
	if !rel.Draft {
		return Published{}, restore(refuse(StepUpload, "release %d is no longer a draft after the upload", res.ReleaseID))
	}
	if err := checkAssetSet(ctx, r, p.GH, pl, res.limits, StepUpload, rel, res.AssetIDs, files); err != nil {
		return Published{}, restore(err)
	}
	say("upload: %d assets uploaded, the asset set and the digests match", len(files))

	if err := checkTag(ctx, r, p.GH, pl, res.Commit); err != nil {
		return Published{}, restore(err)
	}
	say("tag: %s still points at %s", pl.tag, res.Commit)

	question = fmt.Sprintf("Type the tag %s again to publish the release %d of %s; published assets cannot be changed (Ctrl-C takes effect only after Enter): ", pl.tag, res.ReleaseID, pl.repo)
	if err := ask.confirm(question, pl.tag); err != nil {
		return Published{}, restore(err)
	}
	// The prompt can take as long as the operator likes; look at the tag and
	// the release once more right before the PATCH.
	if err := checkTag(ctx, r, p.GH, pl, res.Commit); err != nil {
		return Published{}, restore(err)
	}
	current, err := readRelease(ctx, r, p.GH, pl, res.ReleaseID, StepPublish)
	if err != nil {
		return Published{}, restore(err)
	}
	if !current.Draft {
		return Published{}, restore(refuse(StepPublish, "release %d is no longer a draft just before the PATCH", res.ReleaseID))
	}
	if err := checkAssetSet(ctx, r, p.GH, pl, res.limits, StepPublish, current, res.AssetIDs, files); err != nil {
		return Published{}, restore(err)
	}
	if err := checkImmutable(ctx, r, p.GH, pl); err != nil {
		return Published{}, restore(err)
	}
	if err := publish(ctx, r, p.GH, pl, res.ReleaseID); err != nil {
		return Published{}, fmt.Errorf("%w; if it is still a draft, %s", err, restoreSteps)
	}

	// After the PATCH the release may be public. A check that ran and failed
	// means published assets cannot be fixed; a read that did not complete
	// proves nothing, so the operator reads the release first.
	afterPublish := func(err error) error {
		var ref *Refusal
		if errors.As(err, &ref) {
			return fmt.Errorf("%w; the release was published but the check afterwards failed; published assets cannot be changed, so cut the next patch version and never re-upload", err)
		}
		return fmt.Errorf("%w; the release was probably published but could not be read back; read release %d with gh before doing anything else", err, res.ReleaseID)
	}
	got, err := readRelease(ctx, r, p.GH, pl, res.ReleaseID, StepPublish)
	if err != nil {
		return Published{}, afterPublish(err)
	}
	switch {
	case got.Draft:
		return Published{}, restore(refuse(StepPublish, "release %d is still a draft after the PATCH", res.ReleaseID))
	case got.Immutable == nil || !*got.Immutable:
		return Published{}, afterPublish(refuse(StepPublish, "release %d is not immutable", res.ReleaseID))
	}
	if err := checkAssetSet(ctx, r, p.GH, pl, res.limits, StepPublish, got, res.AssetIDs, files); err != nil {
		return Published{}, afterPublish(err)
	}
	if err := checkTag(ctx, r, p.GH, pl, res.Commit); err != nil {
		return Published{}, afterPublish(err)
	}
	say("publish: release %d is public and immutable, tag %s unchanged", res.ReleaseID, pl.tag)

	out := Published{Tag: pl.tag, ReleaseID: res.ReleaseID, Commit: res.Commit}
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		out.Assets = append(out.Assets, PublishedAsset{Name: f.name, SHA256: hex.EncodeToString(sum[:])})
	}
	return out, nil
}
