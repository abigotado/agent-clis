// Package release implements steps 1 to 6 of the sign-release design: it
// resolves the draft release, downloads and checks the darwin assets, unpacks
// the archives, parses the binaries and verifies their attestations. Every
// external command goes through a runner.Runner, and nothing downloaded or
// extracted is ever executed: the only programs the tool starts are gh and, in
// later steps, /usr/bin/codesign.
package release

import (
	"debug/macho"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/codesign"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/config"
)

// Limits bounds what the tool reads. Every bound applies to the size the
// release reports and to the bytes actually received.
type Limits struct {
	// MaxArchive bounds one downloaded archive.
	MaxArchive int64
	// MaxChecksums bounds the downloaded checksums file.
	MaxChecksums int64
	// MaxEntry bounds one unpacked archive member.
	MaxEntry int64
	// MaxExtracted bounds the unpacked members of one archive together.
	MaxExtracted int64
}

// DefaultLimits returns the bounds used in production.
func DefaultLimits() Limits {
	return Limits{MaxArchive: 128 << 20, MaxChecksums: 64 << 10, MaxEntry: 256 << 20, MaxExtracted: 384 << 20}
}

func (l Limits) validate() error {
	for _, v := range []struct {
		name  string
		value int64
	}{{"MaxArchive", l.MaxArchive}, {"MaxChecksums", l.MaxChecksums}, {"MaxEntry", l.MaxEntry}, {"MaxExtracted", l.MaxExtracted}} {
		if v.value <= 0 {
			return refuse(StepPreflight, "limit %s is %d, want a positive size", v.name, v.value)
		}
	}
	return nil
}

// Params is everything Run needs.
type Params struct {
	Config config.Config
	// CLI is the name of the CLI in Config.CLIs.
	CLI string
	// Version is a semantic version without a leading v.
	Version string
	// GH is the absolute path of gh, resolved once by the caller. It is the
	// program every command starts.
	GH string
	// WorkDir is a new, empty directory with mode 0700 made by the caller.
	WorkDir string
	// Limits bounds the reads; the zero value selects DefaultLimits.
	Limits Limits
}

type archivePlan struct {
	arch string
	name string
	cpu  macho.Cpu
}

type plan struct {
	cli       string
	entries   []string
	exp       codesign.Expectation
	repo      string
	tag       string
	signer    string // <repo>/<signer_workflow>
	archives  [2]archivePlan
	checksums string
	expected  []string // every asset name the release must carry, sorted
}

// preflight validates everything that needs no command: the configuration
// itself (a Config built in code is not trusted), the work directory,
// the limits, the configuration, the CLI, its readiness to sign and the
// asset names. It runs before the first gh call.
func preflight(p Params) (plan, Limits, error) {
	if err := p.Config.Validate(); err != nil {
		return plan{}, Limits{}, fmt.Errorf("preflight: %w", err)
	}
	limits := p.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if err := limits.validate(); err != nil {
		return plan{}, Limits{}, err
	}
	cli, err := p.Config.CLI(p.CLI)
	if err != nil {
		return plan{}, Limits{}, fmt.Errorf("preflight: %w", err)
	}
	if err := cli.ReadyToSign(p.CLI); err != nil {
		return plan{}, Limits{}, fmt.Errorf("preflight: %w", err)
	}
	exp, err := codesign.ExpectationFor(p.CLI, cli)
	if err != nil {
		return plan{}, Limits{}, fmt.Errorf("preflight: %w", err)
	}
	if !slices.Contains(cli.Assets.ArchiveEntries, p.CLI) {
		return plan{}, Limits{}, refuse(StepPreflight, "archive_entries does not list the binary %q", p.CLI)
	}
	if err := checkWorkDir(p.WorkDir); err != nil {
		return plan{}, Limits{}, err
	}
	if !filepath.IsAbs(p.GH) {
		return plan{}, Limits{}, refuse(StepPreflight, "gh path %q is not absolute", p.GH)
	}

	pl := plan{
		cli:       p.CLI,
		entries:   cli.Assets.ArchiveEntries,
		exp:       exp,
		repo:      p.Config.Repository,
		signer:    p.Config.Repository + "/" + p.Config.SignerWorkflow,
		checksums: cli.Assets.DarwinChecksums,
	}
	if _, err := config.ExpandName("x-"+config.VersionPlaceholder, p.Version); err != nil {
		return plan{}, Limits{}, fmt.Errorf("preflight: %w", err)
	}
	pl.tag = cli.TagPrefix + p.Version

	names := []string{cli.Assets.DarwinChecksums, cli.Assets.LinuxChecksums}
	for i, a := range []struct {
		arch     string
		cpu      macho.Cpu
		darwin   string
		linuxTpl string
	}{
		{"amd64", macho.CpuAmd64, cli.Assets.DarwinArchives.AMD64, cli.Assets.LinuxArchives.AMD64},
		{"arm64", macho.CpuArm64, cli.Assets.DarwinArchives.ARM64, cli.Assets.LinuxArchives.ARM64},
	} {
		darwin, err := config.ExpandName(a.darwin, p.Version)
		if err != nil {
			return plan{}, Limits{}, fmt.Errorf("preflight: %w", err)
		}
		linux, err := config.ExpandName(a.linuxTpl, p.Version)
		if err != nil {
			return plan{}, Limits{}, fmt.Errorf("preflight: %w", err)
		}
		pl.archives[i] = archivePlan{arch: a.arch, name: darwin, cpu: a.cpu}
		names = append(names, darwin, linux)
	}
	slices.Sort(names)
	pl.expected = names
	return pl, limits, nil
}

// checkWorkDir requires an existing, empty directory that only the owner can
// use. The caller makes it; the tool never creates it.
func checkWorkDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return refuse(StepPreflight, "work directory %q is not an absolute path", dir)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("preflight: stat work directory: %w", err)
	}
	if !info.IsDir() {
		return refuse(StepPreflight, "work directory %q is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		return refuse(StepPreflight, "work directory %q has mode %04o, want 0700", dir, perm)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("preflight: read work directory: %w", err)
	}
	if len(entries) != 0 {
		return refuse(StepPreflight, "work directory %q is not empty", dir)
	}
	return nil
}
