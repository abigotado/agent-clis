package release

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
	"github.com/abigotado/agent-clis/tools/sign-release/machodigest"
)

// Artifact is what one architecture left in the work directory.
type Artifact struct {
	// ArchiveName is the release asset name of the archive.
	ArchiveName string
	// ArchivePath is the downloaded archive.
	ArchivePath string
	// ExtractDir holds every archive member, written 0600.
	ExtractDir string
	// BinaryPath is the extracted CLI binary. It is never executed.
	BinaryPath string
	// StreamPath is the machodigest stream of the binary.
	StreamPath string

	// stream is the machodigest stream the attestation covers, kept in memory so
	// signing is compared against what was verified and not against a file a
	// later step could find changed.
	stream []byte
	// members are the verified archive members, by name, as attested.
	members map[string][]byte
}

// Result is what steps 1 to 6 hand to the signing step.
type Result struct {
	ReleaseID int64
	Tag       string
	// Commit is the commit the tag points at and all four attestations name.
	Commit string
	// AssetIDs maps every asset name of the release to its ID.
	AssetIDs map[string]int64
	// ChecksumsPath is the downloaded checksums-darwin.txt.
	ChecksumsPath string
	AMD64         Artifact
	ARM64         Artifact

	// pl and limits are what the later steps need and a caller must not change.
	pl     plan
	limits Limits
}

// Run performs steps 1 to 6. Every command goes through r, and none of them
// starts a downloaded or extracted file.
func Run(ctx context.Context, r runner.Runner, p Params) (Result, error) {
	pl, limits, err := preflight(p)
	if err != nil {
		return Result{}, err
	}
	if err := ghAuthStatus(ctx, r, p.GH); err != nil {
		return Result{}, err
	}
	rel, err := resolve(ctx, r, p.GH, pl)
	if err != nil {
		return Result{}, err
	}

	res := Result{ReleaseID: rel.id, Tag: pl.tag, AssetIDs: make(map[string]int64, len(rel.assets)), pl: pl, limits: limits}
	for name, a := range rel.assets {
		res.AssetIDs[name] = a.ID
	}

	sumsFile, err := downloadAsset(ctx, r, p.GH, pl.repo, p.WorkDir, rel.assets[pl.checksums], limits.MaxChecksums)
	if err != nil {
		return Result{}, err
	}
	res.ChecksumsPath = sumsFile.path
	want := []string{pl.archives[0].name, pl.archives[1].name}
	sums, err := parseChecksums(sumsFile.data, want)
	if err != nil {
		return Result{}, err
	}

	var archives [2]downloaded
	for i, ap := range pl.archives {
		arc, err := downloadAsset(ctx, r, p.GH, pl.repo, p.WorkDir, rel.assets[ap.name], limits.MaxArchive)
		if err != nil {
			return Result{}, err
		}
		if err := verifySum(ap.name, arc.data, sums[ap.name]); err != nil {
			return Result{}, err
		}
		archives[i] = arc
	}

	res.Commit, err = tagCommit(ctx, r, p.GH, pl)
	if err != nil {
		return Result{}, err
	}

	// Provenance first: nothing is parsed, extracted or written until both
	// archives carry a verified attestation for the tag's commit.
	for _, arc := range archives {
		if err := verifyFile(ctx, r, p.GH, pl, arc.path, res.Commit); err != nil {
			return Result{}, err
		}
	}

	// Parse and check both binaries in memory; write only once both pass.
	var contents [2]unpacked
	for i, ap := range pl.archives {
		contents[i], err = unpack(pl, ap, archives[i].data, limits)
		if err != nil {
			return Result{}, err
		}
	}
	artifacts := [2]*Artifact{&res.AMD64, &res.ARM64}
	for i, ap := range pl.archives {
		*artifacts[i], err = store(p.WorkDir, pl, ap, archives[i], contents[i])
		if err != nil {
			return Result{}, err
		}
	}
	for _, a := range artifacts {
		if err := verifyFile(ctx, r, p.GH, pl, a.StreamPath, res.Commit); err != nil {
			return Result{}, err
		}
	}
	return res, nil
}

// unpacked is one archive's members and the stream of its binary, in memory.
type unpacked struct {
	files  map[string][]byte
	stream []byte
}

// unpack extracts one archive, checks the binary and builds its stream, all in
// memory. A refused archive leaves nothing on disk.
func unpack(pl plan, ap archivePlan, data []byte, limits Limits) (unpacked, error) {
	files, err := extractArchive(data, pl.entries, limits)
	if err != nil {
		return unpacked{}, fmt.Errorf("%s: %w", ap.name, err)
	}
	binary := files[pl.cli]
	if err := checkMachO(pl.cli, binary, ap.cpu); err != nil {
		return unpacked{}, fmt.Errorf("%s: %w", ap.name, err)
	}
	var stream bytes.Buffer
	if err := machodigest.Write(&stream, binary); err != nil {
		return unpacked{}, refuse(StepMachO, "%s: %v", ap.name, err)
	}
	return unpacked{files: files, stream: stream.Bytes()}, nil
}

// store writes the members and the stream of a checked archive.
func store(workDir string, pl plan, ap archivePlan, arc downloaded, u unpacked) (Artifact, error) {
	dir, err := writeMembers(workDir, ap.arch, u.files, pl.entries)
	if err != nil {
		return Artifact{}, err
	}
	streamPath := filepath.Join(workDir, strings.TrimSuffix(ap.name, ".tar.gz")+".machostream")
	if err := writeNew(streamPath, u.stream); err != nil {
		return Artifact{}, err
	}
	return Artifact{
		ArchiveName: ap.name,
		ArchivePath: arc.path,
		ExtractDir:  dir,
		BinaryPath:  filepath.Join(dir, pl.cli),
		StreamPath:  streamPath,
		stream:      u.stream,
		members:     u.files,
	}, nil
}
