//go:build darwin && cgo && keychainintegration

package secretstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/agent-clis/core/secretstore/internal/kctest"
)

// t.Cleanup does not run on a test timeout panic or SIGINT, so a killed run can
// leave a scratch keychain file in TMPDIR and the process's prompt switch off;
// see the note in keychain_integration_darwin_test.go for what to do then.
//
// This file builds and signs the binaries TestKeychainAcrossBinaries runs.
//
// The access check of a keychain item is the designated requirement of the
// binary that asks. To test what the backend does when the asking binary is a
// rebuild of the one that wrote the item, or a different one, the test needs
// binaries with chosen designated requirements:
//
//	A1, A2  same signer, same identifier, different content: a rebuild, at a
//	        new path, the way a Homebrew upgrade replaces a binary
//	B       a different signer with the same identifier
//	ad hoc  no signer
//
// Signing comes in three ways, tried in this order; the first that works is
// used and recorded in the test log.
//
//  1. Two throwaway identities, RSA 2048 keys with self-signed certificates that
//     carry the code signing extended key usage and last one day, generated in
//     Go and imported with SecItemImport into a scratch signing keychain, which
//     is separate from the item keychain and never on the search list.
//  2. The same two identities, imported as a PKCS#12 file that
//     /usr/bin/openssl writes with the legacy algorithms SecItemImport reads.
//  3. Ad hoc signatures with a designated requirement of the identifier alone.
//     There is no second certificate then, so B differs by identifier, and the
//     row "a different certificate with the same identifier" cannot run: it is
//     skipped with the reason logged, and under CI a notice is printed. This is
//     the accepted gap of the plan when the signer API is not usable on a runner.
//
// SECRETSTORE_REQUIRE_CERT_SIGNING=1 turns the third way into a failure, for a
// local run that must exercise the certificate rows. CI does not set it.
//
// An identity signs through the SecCodeSigner interface: /usr/bin/codesign
// refuses a self-signed identity that is not trusted and on the search list.
// Every signature carries the hardened runtime flag, which the test asserts.

// markerLinkerVariable is the variable -X sets in each helper build.
var markerLinkerVariable = reflect.TypeFor[kctest.Keychain]().PkgPath() + "." + kctest.MarkerVariable

const (
	helperBuildTimeout    = 5 * time.Minute
	codesignPath          = "/usr/bin/codesign"
	opensslPath           = "/usr/bin/openssl"
	requireCertSigningEnv = "SECRETSTORE_REQUIRE_CERT_SIGNING"
)

// testBinary is one signed copy of the helper test binary.
type testBinary struct {
	name string
	path string
	// marker is the build marker the binary must report.
	marker string
}

// binarySet is the signed binaries and what is known about how they were signed.
type binarySet struct {
	a1, a2, b, adhoc testBinary
	// certificates says B has a different certificate than A. When false B has a
	// different identifier instead.
	certificates bool
	method       string
}

// identity is a throwaway signing identity.
type identity struct {
	commonName string
	keyPEM     []byte
	certPEM    []byte
}

func newIdentity(commonName string) (identity, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return identity{}, fmt.Errorf("generate an RSA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return identity{}, fmt.Errorf("generate a serial number: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return identity{}, fmt.Errorf("create the certificate: %w", err)
	}
	return identity{
		commonName: commonName,
		keyPEM:     pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		certPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// toPKCS12 packs the identity with /usr/bin/openssl, using the legacy
// algorithms SecItemImport can read. The password goes in on standard input.
func (id identity) toPKCS12(ctx context.Context, dir, password string) ([]byte, error) {
	keyFile := filepath.Join(dir, "key.pem")
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(keyFile, id.keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write the key: %w", err)
	}
	if err := os.WriteFile(certFile, id.certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write the certificate: %w", err)
	}
	cmd := exec.CommandContext(ctx, opensslPath, "pkcs12", "-export",
		"-inkey", keyFile, "-in", certFile, "-passout", "stdin",
		"-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run openssl pkcs12: %w", err)
	}
	return out, nil
}

func randomHexString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(b)
}

// buildHelperBinary compiles this package's test binary, with the tag and
// without the race detector, into out. The race detector would make the two
// builds differ from the binary under test in ways that do not matter and would
// slow every helper run. marker goes into the binary through the linker.
func buildHelperBinary(t *testing.T, out, marker string) {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		unusable(t, "finding the go tool to build the helper binaries", err)
	}
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read the working directory: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), helperBuildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool, "test", "-c", "-race=false", "-tags", "keychainintegration",
		"-ldflags=-X "+markerLinkerVariable+"="+marker, "-o", out, ".")
	cmd.Dir = pkgDir
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		unusable(t, "building a helper binary", fmt.Errorf("%w\n%s", err, tail(output.Bytes(), 4096)))
	}
}

// tail returns the last n bytes of b as a string.
func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(src), err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatalf("create the directory of %s: %v", dst, err)
	}
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// codesign runs /usr/bin/codesign with args.
func codesign(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, codesignPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign: %w\n%s", err, tail(out, 2048))
	}
	return nil
}

// signingKeychain creates a scratch keychain for signing identities, in its own
// directory, and registers its deletion. It is not the item keychain.
func signingKeychain(t *testing.T, config kctest.Config) (*kctest.Keychain, error) {
	t.Helper()
	kc, err := kctest.Create(t.TempDir())
	if err != nil {
		return nil, fmt.Errorf("create the signing keychain: %w", err)
	}
	t.Cleanup(func() {
		if err := kc.Delete(); err != nil {
			t.Errorf("delete the signing keychain: %v", err)
		}
	})
	after, err := kctest.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("read the keychain configuration after creating the signing keychain: %w", err)
	}
	if !config.Equal(after) || slices.Contains(after.SearchList, kc.Path()) || after.Default == kc.Path() {
		t.Fatalf("creating the signing keychain changed the user's keychain configuration or put it on the search list: before %s, after %s", config, after)
	}
	return kc, nil
}

// signWithCertificates imports identities A and B by the way and signs the
// copies. It returns an error, with whatever it created cleaned up by the
// test's cleanup, when the way does not work on this machine.
func signWithCertificates(t *testing.T, way string, config kctest.Config, copies map[string]string, identifierA string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	kc, err := signingKeychain(t, config)
	if err != nil {
		return err
	}
	ids := map[string]identity{}
	for _, which := range []string{"A", "B"} {
		id, err := newIdentity("secretstore test signer " + which + " " + randomHexString(t, 4))
		if err != nil {
			return err
		}
		ids[which] = id
		switch way {
		case "pem":
			if err := kc.ImportPEM(id.keyPEM); err != nil {
				return fmt.Errorf("import the private key of %s: %w", which, err)
			}
			if err := kc.ImportPEM(id.certPEM); err != nil {
				return fmt.Errorf("import the certificate of %s: %w", which, err)
			}
		case "pkcs12":
			password := randomHexString(t, 8)
			p12, err := id.toPKCS12(ctx, t.TempDir(), password)
			if err != nil {
				return err
			}
			if err := kc.ImportPKCS12(p12, password); err != nil {
				return fmt.Errorf("import the PKCS#12 identity of %s: %w", which, err)
			}
		default:
			return fmt.Errorf("unknown import way %q", way)
		}
	}
	for _, c := range []struct{ name, signer, identifier string }{
		{"a1", "A", identifierA},
		{"a2", "A", identifierA},
		{"b", "B", identifierA},
	} {
		if err := kc.Sign(ids[c.signer].commonName, copies[c.name], c.identifier); err != nil {
			return fmt.Errorf("sign %s as %s: %w", c.name, c.signer, err)
		}
	}
	return nil
}

// signAdHoc signs A1, A2 and B ad hoc, each with a designated requirement of its
// identifier alone, so a rebuild keeps it. B gets another identifier.
func signAdHoc(t *testing.T, copies map[string]string, identifierA string) error {
	t.Helper()
	for _, c := range []struct{ name, identifier string }{
		{"a1", identifierA},
		{"a2", identifierA},
		{"b", identifierA + ".other"},
	} {
		err := codesign(t.Context(), "--force", "--sign", "-", "--options", "runtime",
			"--identifier", c.identifier, "-r", `=designated => identifier "`+c.identifier+`"`, copies[c.name])
		if err != nil {
			return fmt.Errorf("sign %s ad hoc: %w", c.name, err)
		}
	}
	return nil
}

// newBinarySet builds, copies and signs the helper binaries. config is the
// user's keychain configuration, which signing must leave as it is.
func newBinarySet(t *testing.T, config kctest.Config) binarySet {
	t.Helper()
	build := t.TempDir()
	raw1 := filepath.Join(build, "build-1.test")
	raw2 := filepath.Join(build, "build-2.test")
	buildHelperBinary(t, raw1, "1")
	buildHelperBinary(t, raw2, "2")

	// Paths shaped like a Homebrew Cellar, so a rebuild lands at a new path.
	root := t.TempDir()
	set := binarySet{
		a1:    testBinary{name: "A1", path: filepath.Join(root, "cellar", "1", "bin", "secretstore.test"), marker: "1"},
		a2:    testBinary{name: "A2", path: filepath.Join(root, "cellar", "2", "bin", "secretstore.test"), marker: "2"},
		b:     testBinary{name: "B", path: filepath.Join(root, "foreign", "bin", "secretstore.test"), marker: "1"},
		adhoc: testBinary{name: "ad hoc", path: filepath.Join(root, "adhoc", "bin", "secretstore.test"), marker: "1"},
	}
	identifierA := "secretstore.test." + randomHexString(t, 6)

	place := func() map[string]string {
		copyExecutable(t, raw1, set.a1.path)
		copyExecutable(t, raw2, set.a2.path)
		copyExecutable(t, raw1, set.b.path)
		return map[string]string{"a1": set.a1.path, "a2": set.a2.path, "b": set.b.path}
	}

	var failures []string
	for _, way := range []struct {
		name string
		sign func(copies map[string]string) error
	}{
		{"self-signed identities imported with SecItemImport", func(c map[string]string) error {
			return signWithCertificates(t, "pem", config, c, identifierA)
		}},
		{"self-signed identities imported as PKCS#12", func(c map[string]string) error {
			return signWithCertificates(t, "pkcs12", config, c, identifierA)
		}},
	} {
		if err := way.sign(place()); err != nil {
			failures = append(failures, way.name+": "+err.Error())
			t.Logf("signing with %s failed: %v", way.name, err)
			continue
		}
		set.certificates = true
		set.method = way.name
		break
	}
	if !set.certificates {
		if os.Getenv(requireCertSigningEnv) == "1" {
			t.Fatalf("signing with certificates is required but did not work:\n%s", strings.Join(failures, "\n"))
		}
		if err := signAdHoc(t, place(), identifierA); err != nil {
			unusable(t, "signing the helper binaries", errors.Join(append(stringsAsErrors(failures), err)...))
		}
		set.method = "ad hoc signatures with an identifier-only requirement"
		reason := "no signing certificate could be used on this machine; the row \"a different certificate, same identifier\" did not run"
		t.Logf("%s", reason)
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			fmt.Printf("::notice title=keychain integration::%s\n", reason)
		}
	}
	t.Logf("helper binaries signed with: %s", set.method)

	// The plain copy: signed ad hoc by itself, with the requirement a cdhash gives.
	copyExecutable(t, raw1, set.adhoc.path)
	if err := codesign(t.Context(), "--force", "--sign", "-", set.adhoc.path); err != nil {
		unusable(t, "signing the ad hoc helper binary", err)
	}
	set.assertPremises(t, identifierA)
	return set
}

func stringsAsErrors(messages []string) []error {
	errs := make([]error, 0, len(messages))
	for _, m := range messages {
		errs = append(errs, errors.New(m))
	}
	return errs
}

// assertPremises checks that the binaries are what the rows assume, so a row
// cannot pass because two binaries turned out to be the same thing.
func (s binarySet) assertPremises(t *testing.T, identifierA string) {
	t.Helper()
	sig := map[string]kctest.Signature{}
	for _, b := range []testBinary{s.a1, s.a2, s.b, s.adhoc} {
		got, err := kctest.CodeSignature(b.path)
		if err != nil {
			t.Fatalf("read the signature of %s: %v", b.name, err)
		}
		sig[b.name] = got
	}
	a1, a2, b, adhoc := sig["A1"], sig["A2"], sig["B"], sig["ad hoc"]

	for _, name := range []string{"A1", "A2", "B"} {
		if !sig[name].Runtime() {
			t.Errorf("%s is signed without the hardened runtime flag (flags 0x%x)", name, sig[name].Flags)
		}
	}
	if a1.Identifier != identifierA || a2.Identifier != identifierA {
		t.Errorf("A1 and A2 identifiers are %q and %q, want %q", a1.Identifier, a2.Identifier, identifierA)
	}
	if a1.CDHash == "" || a1.CDHash == a2.CDHash {
		t.Errorf("A1 and A2 code directory hashes are %q and %q, want two different ones: it is not a rebuild", a1.CDHash, a2.CDHash)
	}
	if a1.Requirement == "" || a1.Requirement != a2.Requirement {
		t.Errorf("A1 requirement %q, A2 requirement %q, want the same one: a rebuild must satisfy what the item trusts", a1.Requirement, a2.Requirement)
	}
	if b.Requirement == a1.Requirement {
		t.Errorf("B has the same designated requirement as A: %q", b.Requirement)
	}
	if !adhoc.AdHoc() || adhoc.HasCertificates {
		t.Errorf("the ad hoc binary is not ad hoc: flags 0x%x, certificates %t", adhoc.Flags, adhoc.HasCertificates)
	}
	if adhoc.Requirement == a1.Requirement || adhoc.Requirement == b.Requirement {
		t.Errorf("the ad hoc binary shares a designated requirement with A or B: %q", adhoc.Requirement)
	}
	if s.certificates {
		if !a1.HasCertificates || !b.HasCertificates || a1.LeafName == "" || a1.LeafName == b.LeafName {
			t.Errorf("A and B do not have two different certificates: A %q, B %q", a1.LeafName, b.LeafName)
		}
		if b.Identifier != identifierA {
			t.Errorf("B identifier is %q, want the same as A, %q", b.Identifier, identifierA)
		}
	} else if b.Identifier == identifierA {
		t.Errorf("B has A's identifier %q in the ad hoc fallback, where it must differ", b.Identifier)
	}
}
