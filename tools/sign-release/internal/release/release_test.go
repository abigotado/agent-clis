package release

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/macho"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/config"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
	"github.com/abigotado/agent-clis/tools/sign-release/machodigest"
)

func TestRunHappyPath(t *testing.T) {
	s := newScenario(t)
	res, err := s.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.ReleaseID != testRelID || res.Tag != testTag || res.Commit != testCommit {
		t.Fatalf("Result = {%d %q %q}, want {%d %q %q}", res.ReleaseID, res.Tag, res.Commit, testRelID, testTag, testCommit)
	}
	if len(res.AssetIDs) != 6 {
		t.Fatalf("AssetIDs has %d entries, want 6", len(res.AssetIDs))
	}
	work := s.params.WorkDir
	for _, tc := range []struct {
		name string
		art  Artifact
		cpu  macho.Cpu
		idx  int
		arch string
	}{
		{"amd64", res.AMD64, macho.CpuAmd64, 0, "amd64"},
		{"arm64", res.ARM64, macho.CpuArm64, 1, "arm64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.art.ArchiveName != s.darwin[tc.idx] || tc.art.ArchivePath != filepath.Join(work, s.darwin[tc.idx]) {
				t.Fatalf("archive = %q at %q", tc.art.ArchiveName, tc.art.ArchivePath)
			}
			if tc.art.BinaryPath != filepath.Join(work, tc.arch, testCLI) {
				t.Fatalf("BinaryPath = %q", tc.art.BinaryPath)
			}
			bin, err := os.ReadFile(tc.art.BinaryPath)
			if err != nil {
				t.Fatalf("read binary: %v", err)
			}
			if !bytes.Equal(bin, thinBinary(tc.cpu)) {
				t.Fatal("extracted binary differs from the archived one")
			}
			info, err := os.Stat(tc.art.BinaryPath)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("binary mode = %v (err %v), want 0600 so it cannot be executed", info.Mode(), err)
			}
			var want bytes.Buffer
			if err := machodigest.Write(&want, bin); err != nil {
				t.Fatalf("machodigest.Write() error = %v", err)
			}
			got, err := os.ReadFile(tc.art.StreamPath)
			if err != nil || !bytes.Equal(got, want.Bytes()) {
				t.Fatalf("stream file differs from the machodigest stream (err %v)", err)
			}
			if tc.art.StreamPath != strings.TrimSuffix(tc.art.ArchivePath, ".tar.gz")+".machostream" {
				t.Fatalf("StreamPath = %q", tc.art.StreamPath)
			}
		})
	}
}

// TestRunCommandsAreExact pins every argv, in order: the release list, each
// asset download by ID, the tag ref read, and the four attestation verifies.
func TestRunCommandsAreExact(t *testing.T) {
	s := newScenario(t)
	res, err := s.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	work := s.params.WorkDir
	download := func(name string) []string {
		return []string{testGH, "api", "--hostname", "github.com", "-H", "Accept: application/octet-stream", fmt.Sprintf("repos/abigotado/agent-clis/releases/assets/%d", s.assetID(name))}
	}
	verify := func(file string) []string {
		return []string{
			testGH, "attestation", "verify", file,
			"--repo", "abigotado/agent-clis",
			"--signer-workflow", "abigotado/agent-clis/.github/workflows/release.yaml",
			"--source-ref", "refs/tags/youtrack-agent-cli/v0.13.0",
			"--source-digest", testCommit,
			"--deny-self-hosted-runners",
			"--format", "json",
			"--hostname", "github.com",
		}
	}
	want := [][]string{
		{testGH, "auth", "status", "--hostname", "github.com"},
		{testGH, "api", "--hostname", "github.com", "--paginate", "repos/abigotado/agent-clis/releases"},
		download("checksums-darwin.txt"),
		download("youtrack-agent-cli_0.13.0_darwin_amd64.tar.gz"),
		download("youtrack-agent-cli_0.13.0_darwin_arm64.tar.gz"),
		{testGH, "api", "--hostname", "github.com", "repos/abigotado/agent-clis/git/ref/tags/youtrack-agent-cli/v0.13.0"},
		verify(filepath.Join(work, "youtrack-agent-cli_0.13.0_darwin_amd64.tar.gz")),
		verify(filepath.Join(work, "youtrack-agent-cli_0.13.0_darwin_arm64.tar.gz")),
		verify(filepath.Join(work, "youtrack-agent-cli_0.13.0_darwin_amd64.machostream")),
		verify(filepath.Join(work, "youtrack-agent-cli_0.13.0_darwin_arm64.machostream")),
	}
	if len(s.calls) != len(want) {
		t.Fatalf("got %d commands, want %d:\n%q", len(s.calls), len(want), s.calls)
	}
	for i := range want {
		if !slices.Equal(s.calls[i], want[i]) {
			t.Errorf("command %d = %q\nwant        %q", i, s.calls[i], want[i])
		}
	}
	if res.AMD64.StreamPath != want[8][3] || res.ARM64.StreamPath != want[9][3] {
		t.Errorf("verified streams are not the Result's stream paths")
	}
}

// TestRunPinsRepositoryAndNeverExecutesFiles proves from the runner records
// that every gh call names the configured repository and that no command's
// program is a downloaded or extracted file.
func TestRunPinsRepositoryAndNeverExecutesFiles(t *testing.T) {
	s := newScenario(t)
	if _, err := s.run(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	work := s.params.WorkDir
	for _, argv := range s.calls {
		if argv[0] != testGH {
			t.Errorf("program %q is not gh", argv[0])
		}
		if strings.HasPrefix(argv[0], work) {
			t.Errorf("program %q is a file under the work directory", argv[0])
		}
		host := slices.Index(argv, "--hostname")
		if host < 0 || host+1 >= len(argv) || argv[host+1] != "github.com" {
			t.Errorf("command %q does not pin --hostname github.com", argv)
		}
		pinned := slices.Equal(argv[1:3], []string{"auth", "status"}) ||
			strings.HasPrefix(argv[len(argv)-1], "repos/"+testRepo+"/") ||
			slices.Contains(argv, "--repo") && argv[slices.Index(argv, "--repo")+1] == testRepo
		if !pinned {
			t.Errorf("command %q does not name the repository %s", argv, testRepo)
		}
	}
}

func TestRunAnnotatedTagIsDereferenced(t *testing.T) {
	s := newScenario(t)
	tagSHA := strings.Repeat("b", 40)
	s.tagRefOut = fmt.Sprintf(`{"ref":"refs/tags/%s","object":{"sha":%q,"type":"tag"}}`, testTag, tagSHA)
	s.tagObjects[tagSHA] = fmt.Sprintf(`{"sha":%q,"object":{"sha":%q,"type":"commit"}}`, tagSHA, testCommit)
	res, err := s.run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.Commit != testCommit {
		t.Fatalf("Commit = %q, want the dereferenced %q", res.Commit, testCommit)
	}
	deref := []string{testGH, "api", "--hostname", "github.com", "repos/abigotado/agent-clis/git/tags/" + tagSHA}
	if !slices.ContainsFunc(s.calls, func(c []string) bool { return slices.Equal(c, deref) }) {
		t.Fatalf("no dereference call %q in %q", deref, s.calls)
	}
	// Every verify must carry the commit, not the tag object.
	for _, c := range s.calls {
		if slices.Contains(c, "verify") && c[slices.Index(c, "--source-digest")+1] != testCommit {
			t.Errorf("verify used --source-digest %q, want the commit", c[slices.Index(c, "--source-digest")+1])
		}
	}
}

func certWith(mod func(*certificateJSON)) string {
	c := goodCertificate(testCommit, "refs/tags/"+testTag)
	mod(&c)
	return "[" + verifyEntry(c) + "]"
}

func TestRunRefusals(t *testing.T) {
	amd64Stream := "youtrack-agent-cli_0.13.0_darwin_amd64.machostream"
	arm64Stream := "youtrack-agent-cli_0.13.0_darwin_arm64.machostream"
	amd64Archive := "youtrack-agent-cli_0.13.0_darwin_amd64.tar.gz"
	arm64Archive := "youtrack-agent-cli_0.13.0_darwin_arm64.tar.gz"
	otherCommit := strings.Repeat("c", 40)
	goodRef := "refs/tags/" + testTag
	tests := []struct {
		name   string
		mutate func(*scenario)
		step   Step
		reason string
	}{
		{name: "no release has the tag", mutate: func(s *scenario) { s.rel.TagName = "youtrack-agent-cli/v9.9.9" }, step: StepResolve, reason: "no release has tag"},
		{name: "two releases have the tag", mutate: func(s *scenario) { s.others = append(s.others, s.rel) }, step: StepResolve, reason: "2 releases have tag"},
		{name: "the release is not a draft", mutate: func(s *scenario) { s.rel.Draft = false }, step: StepResolve, reason: "not a draft"},
		{name: "a release with the tag but a non-positive id", mutate: func(s *scenario) { s.rel.ID = 0 }, step: StepResolve, reason: "invalid id"},
		{name: "a linux archive is missing", mutate: func(s *scenario) { s.dropAsset("youtrack-agent-cli_0.13.0_linux_arm64.tar.gz") }, step: StepResolve, reason: "lacks the asset"},
		{name: "the darwin checksums are missing", mutate: func(s *scenario) { s.dropAsset("checksums-darwin.txt") }, step: StepResolve, reason: "lacks the asset"},
		{name: "an extra asset", mutate: func(s *scenario) { s.rel.Assets = append(s.rel.Assets, assetJSON{ID: 999, Name: "extra.txt", Size: 1}) }, step: StepResolve, reason: "unexpected asset"},
		{name: "an asset listed twice", mutate: func(s *scenario) { s.rel.Assets = append(s.rel.Assets, s.rel.Assets[0]) }, step: StepResolve, reason: "more than once"},
		{name: "a darwin archive reports a size over the limit", mutate: func(s *scenario) { s.setReportedSize(amd64Archive, 2<<20) }, step: StepDownload, reason: "reports 2097152 bytes, over the limit"},
		{name: "the checksums file reports a size over the limit", mutate: func(s *scenario) { s.setReportedSize("checksums-darwin.txt", 1<<20) }, step: StepDownload, reason: "reports 1048576 bytes, over the limit"},
		{name: "a darwin archive delivers more bytes than the limit but reports less", mutate: func(s *scenario) {
			s.files[arm64Archive] = bytes.Repeat([]byte{1}, 2<<20)
			s.setReportedSize(arm64Archive, 10)
		}, step: StepDownload, reason: "delivered 2097152 bytes, over the limit"},
		{name: "a darwin archive delivers other bytes than reported", mutate: func(s *scenario) { s.setReportedSize(arm64Archive, int64(len(s.files[arm64Archive]))-1) }, step: StepDownload, reason: "the release reports"},
		{name: "an archive does not match its checksum", mutate: func(s *scenario) {
			b := slices.Clone(s.files[amd64Archive])
			b[len(b)/2] ^= 0xff
			s.files[amd64Archive] = b
		}, step: StepChecksum, reason: "sha256 of"},
		{name: "the checksums file lists an extra name", mutate: func(s *scenario) {
			s.files["checksums-darwin.txt"] = append(s.files["checksums-darwin.txt"], []byte(sumLine("extra.tar.gz", []byte("x")))...)
			s.syncSize("checksums-darwin.txt")
		}, step: StepChecksum, reason: "unexpected name"},
		{name: "the checksums file omits an archive", mutate: func(s *scenario) {
			s.files["checksums-darwin.txt"] = []byte(sumLine(amd64Archive, s.files[amd64Archive]))
			s.syncSize("checksums-darwin.txt")
		}, step: StepChecksum, reason: "does not list"},
		{name: "the checksums file has a malformed line", mutate: func(s *scenario) {
			s.files["checksums-darwin.txt"] = []byte(strings.Replace(string(s.files["checksums-darwin.txt"]), "  ", " ", 1))
			s.syncSize("checksums-darwin.txt")
		}, step: StepChecksum, reason: "is not `<64 lowercase hex>  <name>`"},
		{name: "a symbolic link in an archive", mutate: func(s *scenario) {
			link := tarEntry{hdr: tar.Header{Name: "LICENSE", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}
			s.replaceArchive(0, makeTarGz(t, link, regular("README.md", nil), regular(testCLI, thinBinary(macho.CpuAmd64))))
		}, step: StepExtract, reason: "is a link"},
		{name: "the amd64 archive holds an arm64 binary", mutate: func(s *scenario) { s.replaceArchive(0, goodArchive(t, macho.CpuArm64)) }, step: StepMachO, reason: "built for CPU"},
		{name: "the arm64 archive holds an amd64 binary", mutate: func(s *scenario) { s.replaceArchive(1, goodArchive(t, macho.CpuAmd64)) }, step: StepMachO, reason: "built for CPU"},
		{name: "the tag ref answers for another ref", mutate: func(s *scenario) {
			s.tagRefOut = fmt.Sprintf(`{"ref":"refs/tags/other","object":{"sha":%q,"type":"commit"}}`, testCommit)
		}, step: StepAttest, reason: "tag ref answered for"},
		{name: "the tag points at a tree", mutate: func(s *scenario) {
			s.tagRefOut = fmt.Sprintf(`{"ref":%q,"object":{"sha":%q,"type":"tree"}}`, goodRef, testCommit)
		}, step: StepAttest, reason: "want a commit"},
		{name: "the tag points at a malformed object id", mutate: func(s *scenario) {
			s.tagRefOut = fmt.Sprintf(`{"ref":%q,"object":{"sha":"abc","type":"commit"}}`, goodRef)
		}, step: StepAttest, reason: "malformed object id"},
		{name: "attestation of the amd64 archive exits non-zero", mutate: func(s *scenario) {
			s.verifyErr[amd64Archive] = &runner.ExitError{Program: testGH, Code: 1}
		}, step: StepAttest, reason: "did not verify"},
		{name: "attestation of the arm64 stream exits non-zero", mutate: func(s *scenario) {
			s.verifyErr[arm64Stream] = &runner.ExitError{Program: testGH, Code: 1}
		}, step: StepAttest, reason: "did not verify"},
		{name: "an archive attests another commit", mutate: func(s *scenario) {
			s.verifyOut[arm64Archive] = goodVerifyJSON(otherCommit, goodRef)
		}, step: StepAttest, reason: "source commit"},
		{name: "a stream attests another commit", mutate: func(s *scenario) {
			s.verifyOut[amd64Stream] = goodVerifyJSON(otherCommit, goodRef)
		}, step: StepAttest, reason: "source commit"},
		{name: "both archives attest the same commit but not the tag's", mutate: func(s *scenario) {
			s.verifyOut[amd64Archive] = goodVerifyJSON(otherCommit, goodRef)
			s.verifyOut[arm64Archive] = goodVerifyJSON(otherCommit, goodRef)
		}, step: StepAttest, reason: "source commit"},
		{name: "the two archives attest different commits", mutate: func(s *scenario) {
			s.verifyOut[amd64Archive] = goodVerifyJSON(otherCommit, goodRef)
			s.verifyOut[arm64Archive] = goodVerifyJSON(strings.Repeat("d", 40), goodRef)
		}, step: StepAttest, reason: "source commit"},
		{name: "an archive attests another source ref", mutate: func(s *scenario) {
			s.verifyOut[amd64Archive] = goodVerifyJSON(testCommit, "refs/heads/main")
		}, step: StepAttest, reason: "source ref"},
		{name: "a stream attests another source ref", mutate: func(s *scenario) {
			s.verifyOut[arm64Stream] = goodVerifyJSON(testCommit, "refs/tags/youtrack-agent-cli/v0.12.0")
		}, step: StepAttest, reason: "source ref"},
		{name: "a second attestation names another commit", mutate: func(s *scenario) {
			one := goodVerifyJSON(testCommit, goodRef)
			two := goodVerifyJSON(otherCommit, goodRef)
			s.verifyOut[amd64Archive] = "[" + strings.TrimSuffix(strings.TrimPrefix(one, "["), "]") + "," + strings.TrimSuffix(strings.TrimPrefix(two, "["), "]") + "]"
		}, step: StepAttest, reason: "source commit"},
		{name: "the certificate issuer is not GitHub Actions", mutate: func(s *scenario) {
			s.verifyOut[amd64Archive] = certWith(func(c *certificateJSON) { c.Issuer = "https://accounts.example.com" })
		}, step: StepAttest, reason: "certificate issuer"},
		{name: "the build signer URI names another workflow", mutate: func(s *scenario) {
			s.verifyOut[amd64Archive] = certWith(func(c *certificateJSON) {
				c.BuildSignerURI = "https://github.com/" + testRepo + "/.github/workflows/other.yaml@refs/tags/" + testTag
			})
		}, step: StepAttest, reason: "build signer URI"},
		{name: "the build signer URI names another ref", mutate: func(s *scenario) {
			s.verifyOut[arm64Stream] = certWith(func(c *certificateJSON) {
				c.BuildSignerURI = "https://github.com/" + testRepo + "/.github/workflows/release.yaml@refs/heads/main"
			})
		}, step: StepAttest, reason: "build signer URI"},
		{name: "the build signer digest is another commit", mutate: func(s *scenario) {
			s.verifyOut[amd64Stream] = certWith(func(c *certificateJSON) { c.BuildSignerDigest = otherCommit })
		}, step: StepAttest, reason: "build signer digest"},
		{name: "the runner is self-hosted", mutate: func(s *scenario) {
			s.verifyOut[arm64Archive] = certWith(func(c *certificateJSON) { c.RunnerEnvironment = "self-hosted" })
		}, step: StepAttest, reason: "runner environment"},
		{name: "the source repository is another one", mutate: func(s *scenario) {
			s.verifyOut[amd64Archive] = certWith(func(c *certificateJSON) { c.SourceRepositoryURI = "https://github.com/someone/else" })
		}, step: StepAttest, reason: "source repository URI"},
		{name: "a certificate member is absent", mutate: func(s *scenario) {
			s.verifyOut[amd64Archive] = certWith(func(c *certificateJSON) { c.RunnerEnvironment = "" })
		}, step: StepAttest, reason: "runner environment"},
		{name: "verify prints no attestation", mutate: func(s *scenario) { s.verifyOut[amd64Archive] = "[]" }, step: StepAttest, reason: "no verified attestation"},
		{name: "verify prints something that is not an array", mutate: func(s *scenario) { s.verifyOut[amd64Archive] = `{"ok":true}` }, step: StepAttest, reason: "not a JSON array"},
		{name: "verify prints data after the array", mutate: func(s *scenario) {
			s.verifyOut[amd64Archive] = goodVerifyJSON(testCommit, goodRef) + "[]"
		}, step: StepAttest, reason: "data after the array"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			tc.mutate(s)
			_, err := s.run()
			if err == nil {
				t.Fatal("Run() error = nil, want a refusal")
			}
			wantRefusal(t, err, tc.step, tc.reason)
		})
	}
}

// TestRunRefusalStopsBeforeLaterCommands shows a refusal ends the run: a
// failed checksum means nothing is verified, and a failed attestation of the
// first file means the second is never asked.
func TestRunRefusalStopsBeforeLaterCommands(t *testing.T) {
	t.Run("checksum mismatch makes no attestation call", func(t *testing.T) {
		s := newScenario(t)
		b := slices.Clone(s.files[s.darwin[0]])
		b[len(b)/2] ^= 0xff
		s.files[s.darwin[0]] = b
		if _, err := s.run(); err == nil {
			t.Fatal("Run() error = nil")
		}
		for _, c := range s.calls {
			if slices.Contains(c, "attestation") || slices.Contains(c, "repos/"+testRepo+"/git/ref/tags/"+testTag) {
				t.Errorf("command %q ran after a checksum refusal", c)
			}
		}
	})
	t.Run("a refused binary leaves no stream behind", func(t *testing.T) {
		s := newScenario(t)
		s.replaceArchive(0, goodArchive(t, macho.CpuArm64))
		if _, err := s.run(); err == nil {
			t.Fatal("Run() error = nil")
		}
		if _, err := os.Stat(filepath.Join(s.params.WorkDir, strings.TrimSuffix(s.darwin[0], ".tar.gz")+".machostream")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stream file exists after a refusal (err %v)", err)
		}
	})
	t.Run("a failing first verify stops the rest", func(t *testing.T) {
		s := newScenario(t)
		s.verifyErr[s.darwin[0]] = &runner.ExitError{Program: testGH, Code: 1}
		if _, err := s.run(); err == nil {
			t.Fatal("Run() error = nil")
		}
		verifies := 0
		for _, c := range s.calls {
			if slices.Contains(c, "verify") {
				verifies++
			}
		}
		if verifies != 1 {
			t.Fatalf("%d verify calls, want 1", verifies)
		}
	})
}

func wantFieldError(t *testing.T, err error) {
	t.Helper()
	var fe *config.FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error = %v, want a *config.FieldError", err)
	}
}

// TestPreflightRunsNoCommand shows that nothing reaches the runner until the
// configuration, readiness to sign and the signing expectation have passed.
func TestPreflightRunsNoCommand(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*scenario)
		check  func(*testing.T, error)
	}{
		{name: "empty cert_sha1", mutate: func(s *scenario) {
			cli := s.params.Config.CLIs[testCLI]
			cli.CertSHA1 = ""
			s.params.Config.CLIs[testCLI] = cli
		}, check: func(t *testing.T, err error) {
			var nr *config.NotReadyError
			if !errors.As(err, &nr) {
				t.Fatalf("error = %v, want *config.NotReadyError", err)
			}
		}},
		{name: "malformed cert_sha1", mutate: func(s *scenario) {
			cli := s.params.Config.CLIs[testCLI]
			cli.CertSHA1 = "abc"
			s.params.Config.CLIs[testCLI] = cli
		}, check: wantFieldError},
		{name: "unknown CLI", mutate: func(s *scenario) { s.params.CLI = "nope" }, check: wantFieldError},
		{name: "version with a leading v", mutate: func(s *scenario) { s.params.Version = "v0.13.0" }, check: wantFieldError},
		{name: "archive entries without the binary", mutate: func(s *scenario) {
			cli := s.params.Config.CLIs[testCLI]
			cli.Assets.ArchiveEntries = []string{"LICENSE", "README.md"}
			s.params.Config.CLIs[testCLI] = cli
		}, check: func(t *testing.T, err error) { wantRefusal(t, err, StepPreflight, "does not list the binary") }},
		{name: "relative gh path", mutate: func(s *scenario) { s.params.GH = "gh" }, check: func(t *testing.T, err error) { wantRefusal(t, err, StepPreflight, "not absolute") }},
		{name: "work directory that is not empty", mutate: func(s *scenario) {
			if err := os.WriteFile(filepath.Join(s.params.WorkDir, "stale"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, check: func(t *testing.T, err error) { wantRefusal(t, err, StepPreflight, "not empty") }},
		{name: "work directory open to others", mutate: func(s *scenario) {
			if err := os.Chmod(s.params.WorkDir, 0o755); err != nil {
				t.Fatal(err)
			}
		}, check: func(t *testing.T, err error) { wantRefusal(t, err, StepPreflight, "want 0700") }},
		{name: "relative work directory", mutate: func(s *scenario) { s.params.WorkDir = "work" }, check: func(t *testing.T, err error) { wantRefusal(t, err, StepPreflight, "absolute") }},
		{name: "a non-positive limit", mutate: func(s *scenario) { s.params.Limits.MaxEntry = -1 }, check: func(t *testing.T, err error) { wantRefusal(t, err, StepPreflight, "MaxEntry") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			tc.mutate(s)
			_, err := s.run()
			if err == nil {
				t.Fatal("Run() error = nil, want a refusal")
			}
			if tc.check != nil {
				tc.check(t, err)
			}
			if len(s.calls) != 0 {
				t.Fatalf("runner got %d commands before preflight passed: %q", len(s.calls), s.calls)
			}
		})
	}
}

func TestRunStopsWhenGHIsNotAuthenticated(t *testing.T) {
	s := newScenario(t)
	s.authErr = &runner.ExitError{Program: testGH, Code: 1}
	_, err := s.run()
	var exit *runner.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("error = %v, want the gh exit error", err)
	}
	if len(s.calls) != 1 {
		t.Fatalf("%d commands ran after a failed gh auth status, want only that one: %q", len(s.calls), s.calls)
	}
}

func TestRunRefusesTagChainsThatNeverReachACommit(t *testing.T) {
	first := strings.Repeat("b", 40)
	s := newScenario(t)
	s.tagRefOut = fmt.Sprintf(`{"ref":%q,"object":{"sha":%q,"type":"tag"}}`, "refs/tags/"+testTag, first)
	// An annotated tag that names itself: following it would never end.
	s.tagObjects[first] = fmt.Sprintf(`{"object":{"sha":%q,"type":"tag"}}`, first)
	_, err := s.run()
	if err == nil {
		t.Fatal("Run() error = nil, want a refusal")
	}
	wantRefusal(t, err, StepAttest, "nests more than")
}

func TestRunRefusesBadTagAnswers(t *testing.T) {
	first := strings.Repeat("b", 40)
	annotated := func(s *scenario, second string) {
		s.tagRefOut = fmt.Sprintf(`{"ref":%q,"object":{"sha":%q,"type":"tag"}}`, "refs/tags/"+testTag, first)
		s.tagObjects[first] = second
	}
	tests := []struct {
		name   string
		mutate func(*scenario)
		reason string // empty: a plain decode error, not a refusal
	}{
		{name: "tag ref that is not JSON", mutate: func(s *scenario) { s.tagRefOut = "<html>rate limited</html>" }},
		{name: "second hop with a malformed sha", mutate: func(s *scenario) { annotated(s, `{"object":{"sha":"xyz","type":"commit"}}`) }, reason: "malformed object id"},
		{name: "second hop that is a tree", mutate: func(s *scenario) {
			annotated(s, fmt.Sprintf(`{"object":{"sha":%q,"type":"tree"}}`, testCommit))
		}, reason: "want a commit"},
		{name: "second hop that is not JSON", mutate: func(s *scenario) { annotated(s, "not json") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			tc.mutate(s)
			_, err := s.run()
			if err == nil {
				t.Fatal("Run() error = nil, want an error")
			}
			var ref *Refusal
			if tc.reason != "" {
				wantRefusal(t, err, StepAttest, tc.reason)
			} else if errors.As(err, &ref) {
				t.Fatalf("a body that is not JSON was reported as a refusal: %v", err)
			}
			for _, c := range s.calls {
				if slices.Contains(c, "attestation") {
					t.Errorf("command %q ran after a bad tag answer", c)
				}
			}
		})
	}
}

func workDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

// TestProvenanceComesBeforeParsing shows that nothing is extracted, parsed or
// written until both archive attestations verify, and that a refused archive
// leaves neither members nor streams of the other one.
func TestProvenanceComesBeforeParsing(t *testing.T) {
	downloads := func(s *scenario) []string {
		names := []string{s.checksum, s.darwin[0], s.darwin[1]}
		slices.Sort(names)
		return names
	}
	t.Run("a failed archive attestation leaves only the downloads", func(t *testing.T) {
		for _, failing := range []int{0, 1} {
			s := newScenario(t)
			s.verifyErr[s.darwin[failing]] = &runner.ExitError{Program: testGH, Code: 1}
			_, err := s.run()
			wantRefusal(t, err, StepAttest, "did not verify")
			if got, want := workDirNames(t, s.params.WorkDir), downloads(s); !slices.Equal(got, want) {
				t.Fatalf("failing archive %d: work dir holds %q, want only %q", failing, got, want)
			}
		}
	})
	t.Run("an unparseable archive with a failed attestation is refused as unattested", func(t *testing.T) {
		s := newScenario(t)
		s.replaceArchive(0, []byte("not even gzip"))
		s.verifyErr[s.darwin[0]] = &runner.ExitError{Program: testGH, Code: 1}
		_, err := s.run()
		wantRefusal(t, err, StepAttest, "did not verify")
	})
	t.Run("a refused second archive leaves nothing of the first", func(t *testing.T) {
		s := newScenario(t)
		s.replaceArchive(1, goodArchive(t, macho.CpuAmd64))
		_, err := s.run()
		wantRefusal(t, err, StepMachO, "built for CPU")
		if got, want := workDirNames(t, s.params.WorkDir), downloads(s); !slices.Equal(got, want) {
			t.Fatalf("work dir holds %q, want only %q", got, want)
		}
	})
}

func TestRunReportsCancellationNotVerificationFailure(t *testing.T) {
	s := newScenario(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.onVerify = cancel
	s.verifyErr[s.darwin[0]] = &runner.ExitError{Program: testGH, Code: 1}
	_, err := s.runCtx(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	var ref *Refusal
	if errors.As(err, &ref) {
		t.Fatalf("cancelled run reported as a refusal: %v", err)
	}
}

// TestPreflightRefusesAHandBuiltConfig shows Run validates the Config itself:
// a value no config.json could hold stops before any command.
func TestPreflightRefusesAHandBuiltConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*scenario)
		field  string
	}{
		{name: "archive entry with a parent reference", mutate: func(s *scenario) {
			cli := s.params.Config.CLIs[testCLI]
			cli.Assets.ArchiveEntries = []string{"../x", testCLI}
			s.params.Config.CLIs[testCLI] = cli
		}, field: "archive_entries"},
		{name: "repository with a query separator", mutate: func(s *scenario) { s.params.Config.Repository = "abigotado/agent-clis?x=1" }, field: "repository"},
		{name: "repository with a fragment separator", mutate: func(s *scenario) { s.params.Config.Repository = "abigotado/agent-clis#x" }, field: "repository"},
		{name: "signer workflow with a parent reference", mutate: func(s *scenario) { s.params.Config.SignerWorkflow = "../release.yaml" }, field: "signer_workflow"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			tc.mutate(s)
			_, err := s.run()
			var fe *config.FieldError
			if !errors.As(err, &fe) || !strings.Contains(fe.Field, tc.field) {
				t.Fatalf("error = %v, want a *config.FieldError on %s", err, tc.field)
			}
			if len(s.calls) != 0 {
				t.Fatalf("runner got commands from an invalid config: %q", s.calls)
			}
		})
	}
}
