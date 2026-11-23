package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// maxTagDepth bounds how many annotated tags are followed to a commit.
const maxTagDepth = 5

type objectJSON struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type refJSON struct {
	Ref    string     `json:"ref"`
	Object objectJSON `json:"object"`
}

type tagJSON struct {
	Object objectJSON `json:"object"`
}

// tagCommit reads the commit the tag points at, following annotated tags.
func tagCommit(ctx context.Context, r runner.Runner, gh string, pl plan) (string, error) {
	stdout, _, err := r.Run(ctx, apiArgv(gh, "repos/"+pl.repo+"/git/ref/tags/"+pl.tag), nil)
	if err != nil {
		return "", fmt.Errorf("read tag ref: %w", err)
	}
	var ref refJSON
	if err := json.Unmarshal(stdout, &ref); err != nil {
		return "", fmt.Errorf("decode tag ref: %w", err)
	}
	if ref.Ref != "refs/tags/"+pl.tag {
		return "", refuse(StepAttest, "tag ref answered for %q, want %q", ref.Ref, "refs/tags/"+pl.tag)
	}
	obj := ref.Object
	for depth := 0; ; depth++ {
		if !commitPattern.MatchString(obj.SHA) {
			return "", refuse(StepAttest, "tag %q points at the malformed object id %q", pl.tag, obj.SHA)
		}
		switch obj.Type {
		case "commit":
			return obj.SHA, nil
		case "tag":
		default:
			return "", refuse(StepAttest, "tag %q points at a %q object, want a commit", pl.tag, obj.Type)
		}
		if depth >= maxTagDepth {
			return "", refuse(StepAttest, "tag %q nests more than %d annotated tags", pl.tag, maxTagDepth)
		}
		stdout, _, err := r.Run(ctx, apiArgv(gh, "repos/"+pl.repo+"/git/tags/"+obj.SHA), nil)
		if err != nil {
			return "", fmt.Errorf("read annotated tag %s: %w", obj.SHA, err)
		}
		var tag tagJSON
		if err := json.Unmarshal(stdout, &tag); err != nil {
			return "", fmt.Errorf("decode annotated tag %s: %w", obj.SHA, err)
		}
		obj = tag.Object
	}
}

// verifyArgv is the exact command that verifies one file.
func verifyArgv(gh string, pl plan, file, commit string) []string {
	return []string{
		gh, "attestation", "verify", file,
		"--repo", pl.repo,
		"--signer-workflow", pl.signer,
		"--source-ref", "refs/tags/" + pl.tag,
		"--source-digest", commit,
		"--deny-self-hosted-runners",
		"--predicate-type", predicateType,
		"--format", "json",
		"--hostname", ghHost,
	}
}

// predicateType is the only predicate the tool accepts: SLSA build provenance.
const predicateType = "https://slsa.dev/provenance/v1"

// certificateJSON is verificationResult.signature.certificate as gh
// (sigstore-go) prints it. Only the members the tool compares are read.
type certificateJSON struct {
	Issuer                 string `json:"issuer"`
	BuildSignerURI         string `json:"buildSignerURI"`
	BuildSignerDigest      string `json:"buildSignerDigest"`
	BuildConfigURI         string `json:"buildConfigURI"`
	RunnerEnvironment      string `json:"runnerEnvironment"`
	SourceRepositoryURI    string `json:"sourceRepositoryURI"`
	SourceRepositoryDigest string `json:"sourceRepositoryDigest"`
	SourceRepositoryRef    string `json:"sourceRepositoryRef"`
}

// statementJSON is verificationResult.statement, the in-toto statement gh
// verified: what the attestation is about.
type statementJSON struct {
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

type verifyResult struct {
	VerificationResult struct {
		Signature struct {
			Certificate certificateJSON `json:"certificate"`
		} `json:"signature"`
		Statement statementJSON `json:"statement"`
	} `json:"verificationResult"`
}

// oidcIssuer is the issuer of GitHub Actions workflow identities.
const oidcIssuer = "https://token.actions.githubusercontent.com"

// checkCertificate requires every compared member to equal its exact expected
// value. gh enforces the same through its flags; this repeats it on the
// output, so a gh that ignored a flag still cannot pass a wrong attestation.
func checkCertificate(i int, file string, c certificateJSON, pl plan, commit string) error {
	ref := "refs/tags/" + pl.tag
	for _, f := range []struct{ name, got, want string }{
		{"certificate issuer", c.Issuer, oidcIssuer},
		{"build signer URI", c.BuildSignerURI, "https://github.com/" + pl.signer + "@" + ref},
		{"build signer digest", c.BuildSignerDigest, commit},
		{"build config URI", c.BuildConfigURI, c.BuildSignerURI},
		{"runner environment", c.RunnerEnvironment, "github-hosted"},
		{"source repository URI", c.SourceRepositoryURI, "https://github.com/" + pl.repo},
		{"source ref", c.SourceRepositoryRef, ref},
		{"source commit", c.SourceRepositoryDigest, commit},
	} {
		if f.got != f.want {
			return refuse(StepAttest, "attestation %d of %s names the %s %q, want %q", i, file, f.name, f.got, f.want)
		}
	}
	return nil
}

// checkStatement binds an attestation to the bytes the tool uses: the
// predicate is SLSA provenance and one subject carries the sha256 of data, the
// copy held in memory that the later steps work from, not the file gh read.
func checkStatement(i int, file string, st statementJSON, data []byte) error {
	if st.PredicateType != predicateType {
		return refuse(StepAttest, "attestation %d of %s has the predicate type %q, want %q", i, file, st.PredicateType, predicateType)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	for _, subject := range st.Subject {
		if subject.Digest["sha256"] == want {
			return nil
		}
	}
	return refuse(StepAttest, "attestation %d of %s has no subject with the sha256 %s of the bytes in use", i, file, want)
}

// verifyFile runs gh attestation verify for file and requires every verified
// attestation to match the expected certificate and to be about data, the
// bytes the tool holds for that file.
func verifyFile(ctx context.Context, r runner.Runner, gh string, pl plan, file, commit string, data []byte) error {
	stdout, _, err := r.Run(ctx, verifyArgv(gh, pl, file, commit), nil)
	if err != nil {
		// A cancelled run reports as cancelled, not as a failed verification.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("verify attestation of %s: %w", file, ctxErr)
		}
		var exit *runner.ExitError
		if errors.As(err, &exit) {
			return refuse(StepAttest, "attestation of %s did not verify (%v)", file, err)
		}
		return fmt.Errorf("verify attestation of %s: %w", file, err)
	}
	dec := jsontext.NewDecoder(bytes.NewReader(stdout))
	var results []verifyResult
	if err := json.UnmarshalDecode(dec, &results); err != nil {
		return refuse(StepAttest, "attestation output of %s is not a JSON array: %v", file, err)
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return refuse(StepAttest, "attestation output of %s has data after the array", file)
	}
	if len(results) == 0 {
		return refuse(StepAttest, "attestation output of %s holds no verified attestation", file)
	}
	for i, res := range results {
		if err := checkCertificate(i, file, res.VerificationResult.Signature.Certificate, pl, commit); err != nil {
			return err
		}
		if err := checkStatement(i, file, res.VerificationResult.Statement, data); err != nil {
			return err
		}
	}
	return nil
}
