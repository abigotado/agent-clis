package release

import (
	"bytes"
	"context"
	"path/filepath"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/codesign"
	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
	"github.com/abigotado/agent-clis/tools/sign-release/machodigest"
)

// CodesignPath is the one codesign the tool starts.
const CodesignPath = "/usr/bin/codesign"

// signArgv is the exact command that signs one binary. Every flag value is its
// own element. The requirement is Requirement() as it is: it already starts
// with the "=" codesign takes as "the text follows". Only the leaf-pinned
// designated requirement is accepted, so the signature cannot carry an
// implicit one.
func signArgv(exp codesign.Expectation, bin string) ([]string, error) {
	req, err := exp.Requirement()
	if err != nil {
		return nil, err
	}
	return []string{
		CodesignPath, "--force",
		"--sign", exp.CertSHA1,
		"--options", "runtime",
		"--timestamp",
		"--identifier", exp.Identifier,
		"--requirements", req,
		bin,
	}, nil
}

// codesignVerifyArgv takes the bare expression: codesign rejects
// "designated =>" after -R, which only a requirement set carries.
func codesignVerifyArgv(expr, bin string) []string {
	return []string{CodesignPath, "--verify", "--strict", "-R=" + expr, bin}
}

// The other three inspections of a signed binary. -dvv prints to stderr, the
// last two print to stdout.
func codesignDetailsArgv(bin string) []string {
	return []string{CodesignPath, "-dvv", bin}
}

func codesignRequirementsArgv(bin string) []string {
	return []string{CodesignPath, "-d", "-r-", bin}
}

func codesignEntitlementsArgv(bin string) []string {
	return []string{CodesignPath, "-d", "--entitlements", "-", bin}
}

// streamOf returns the machodigest stream of a binary.
func streamOf(step Step, name string, binary []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := machodigest.Write(&buf, binary); err != nil {
		return nil, refuse(step, "%s: %v", name, err)
	}
	return buf.Bytes(), nil
}

// signAndVerify signs one extracted binary in place and returns the signed
// bytes once every check passed. The binary stays mode 0600: codesign rewrites
// the Mach-O file and does not need the execute bit, the archive modes are set
// from the tar header and not from this file, and a binary that cannot be
// executed here cannot be started by accident. Nothing here runs the binary.
func signAndVerify(ctx context.Context, r runner.Runner, pl plan, limits Limits, art Artifact) ([]byte, error) {
	bin := art.BinaryPath
	if !filepath.IsAbs(bin) || filepath.Clean(bin) != bin {
		return nil, refuse(StepSign, "binary path %q is not a clean absolute path", bin)
	}
	// The file on disk must still be the attested one before it is signed.
	before, err := readRegular(StepSign, bin, limits.MaxEntry)
	if err != nil {
		return nil, err
	}
	pre, err := streamOf(StepSign, art.ArchiveName, before)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pre, art.stream) {
		return nil, refuse(StepSign, "%s: the extracted binary no longer matches the attested machodigest stream", art.ArchiveName)
	}

	argv, err := signArgv(pl.exp, bin)
	if err != nil {
		return nil, refuse(StepSign, "%s: %v", art.ArchiveName, err)
	}
	if _, _, err := runStep(ctx, r, StepSign, "codesign sign "+art.ArchiveName, argv, nil); err != nil {
		return nil, err
	}

	signed, err := readRegular(StepVerify, bin, limits.MaxEntry)
	if err != nil {
		return nil, err
	}
	if err := verifySigned(ctx, r, pl, art.ArchiveName, bin); err != nil {
		return nil, err
	}
	// codesign verified the file as it is now; the bytes kept for the archive
	// must be those bytes.
	after, err := readRegular(StepVerify, bin, limits.MaxEntry)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(signed, after) {
		return nil, refuse(StepVerify, "%s: the signed binary changed while it was being verified", art.ArchiveName)
	}

	// R14: signing may change the signature and nothing else.
	post, err := streamOf(StepVerify, art.ArchiveName, signed)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(post, art.stream) {
		return nil, refuse(StepVerify, "%s: the machodigest stream of the signed binary differs from the attested stream; signing changed more than the signature", art.ArchiveName)
	}
	return signed, nil
}

// verifySigned runs the four inspections and feeds them to codesign.Verify.
// The parsers read text a program printed, so the cryptographic check is the
// first one: a non-zero `--verify` is a refusal.
func verifySigned(ctx context.Context, r runner.Runner, pl plan, name, bin string) error {
	expr, err := pl.exp.Expression()
	if err != nil {
		return refuse(StepVerify, "%s: %v", name, err)
	}
	if _, _, err := runStep(ctx, r, StepVerify, "codesign verify "+name, codesignVerifyArgv(expr, bin), nil); err != nil {
		return err
	}
	_, details, err := runStep(ctx, r, StepVerify, "codesign -dvv "+name, codesignDetailsArgv(bin), nil)
	if err != nil {
		return err
	}
	requirements, _, err := runStep(ctx, r, StepVerify, "codesign -d -r- "+name, codesignRequirementsArgv(bin), nil)
	if err != nil {
		return err
	}
	entitlements, _, err := runStep(ctx, r, StepVerify, "codesign -d --entitlements "+name, codesignEntitlementsArgv(bin), nil)
	if err != nil {
		return err
	}
	out := codesign.Outputs{Details: string(details), Requirements: string(requirements), Entitlements: string(entitlements)}
	if err := codesign.Verify(pl.exp, out); err != nil {
		return refuse(StepVerify, "%s: %v", name, err)
	}
	return nil
}
