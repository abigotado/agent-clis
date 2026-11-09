//go:build darwin && cgo && macos_identity_readonly

package readonlycli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const identityModule = "github.com/abigotado/youtrack-agent-cli"

var identityOwnedClosure = map[string]bool{
	identityModule + "/assets":                 true,
	identityModule + "/cmd/youtrack-agent-cli": true,
	identityModule + "/internal/endpoint":      true,
	identityModule + "/internal/errx":          true,
	identityModule + "/internal/lockfile":      true,
	identityModule + "/internal/output":        true,
	identityModule + "/internal/profile":       true,
	identityModule + "/internal/protocolvalue": true,
	identityModule + "/internal/readonlycli":   true,
	identityModule + "/internal/skills":        true,
}

type identityPackageInfo struct {
	ImportPath string
	Imports    []string
}

func TestIdentityOwnedClosureHasNoDirectNetworkImports(t *testing.T) {
	command := exec.Command("go", "list", "-json", "-tags", "macos_identity_readonly", "-deps", "./cmd/youtrack-agent-cli")
	command.Dir = identityRepositoryRoot(t)
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("go list identity closure: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	seen := make(map[string]bool, len(identityOwnedClosure))
	for {
		var value identityPackageInfo
		err := decoder.Decode(&value)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode identity closure: %v", err)
		}
		if !strings.HasPrefix(value.ImportPath, identityModule+"/") {
			continue
		}
		if err := validateIdentityPackageImports(value); err != nil {
			t.Fatal(err)
		}
		seen[value.ImportPath] = true
	}
	for packagePath := range identityOwnedClosure {
		if !seen[packagePath] {
			t.Errorf("identity closure omitted %s", packagePath)
		}
	}
}

func TestIdentityNetworkImportGuardRejectsDirectImports(t *testing.T) {
	for _, imported := range []string{"net", "net/http", "crypto/tls"} {
		err := validateIdentityPackageImports(identityPackageInfo{
			ImportPath: identityModule + "/internal/endpoint",
			Imports:    []string{imported},
		})
		if err == nil {
			t.Errorf("direct import %q was accepted", imported)
		}
	}
}

func validateIdentityPackageImports(value identityPackageInfo) error {
	if !identityOwnedClosure[value.ImportPath] {
		return fmt.Errorf("identity closure contains unapproved owned package %s", value.ImportPath)
	}
	for _, imported := range value.Imports {
		switch imported {
		case "net", "net/http", "crypto/tls":
			return fmt.Errorf("identity package %s directly imports %s", value.ImportPath, imported)
		}
	}
	return nil
}

func identityRepositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("repository root not found")
		}
		directory = parent
	}
}
