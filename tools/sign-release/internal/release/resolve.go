package release

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/abigotado/agent-clis/tools/sign-release/internal/runner"
)

const (
	// maxPages bounds the pages of the release list gh may print.
	maxPages = 200
	// maxReleases bounds the releases read across all pages.
	maxReleases = 10000
	// maxAssets bounds the assets of one release.
	maxAssets = 100
)

type releaseJSON struct {
	ID      int64       `json:"id"`
	TagName string      `json:"tag_name"`
	Draft   bool        `json:"draft"`
	Assets  []assetJSON `json:"assets"`
}

type assetJSON struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// asset is a release asset the tool may download.
type asset struct {
	ID   int64
	Name string
	Size int64
}

// resolved is the release the tool will work on.
type resolved struct {
	id     int64
	assets map[string]asset
}

// ghHost is the host every gh call is pinned to, so neither GH_HOST nor a saved
// default can send a call elsewhere.
const ghHost = "github.com"

// apiArgv is a gh api command pinned to the host. flags come before the path.
func apiArgv(gh, path string, flags ...string) []string {
	argv := []string{gh, "api", "--hostname", ghHost}
	argv = append(argv, flags...)
	return append(argv, path)
}

func ghAuthStatus(ctx context.Context, r runner.Runner, gh string) error {
	// gh auth status takes no --repo; the host is pinned so a saved default
	// host cannot answer for github.com.
	if _, _, err := r.Run(ctx, []string{gh, "auth", "status", "--hostname", ghHost}, nil); err != nil {
		return fmt.Errorf("gh auth status: %w", err)
	}
	return nil
}

func listReleases(ctx context.Context, r runner.Runner, gh, repo string) ([]releaseJSON, error) {
	stdout, _, err := r.Run(ctx, apiArgv(gh, "repos/"+repo+"/releases", "--paginate"), nil)
	if err != nil {
		return nil, fmt.Errorf("list releases: %w", err)
	}
	return parseReleasePages(stdout)
}

// parseReleasePages reads the concatenated JSON arrays that gh api --paginate
// prints, one per page. Anything but arrays of release objects is refused.
func parseReleasePages(data []byte) ([]releaseJSON, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	var all []releaseJSON
	pages := 0
	for {
		kind := dec.PeekKind()
		if kind == 0 {
			if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("read release list: %w", err)
			}
			break
		}
		if kind != '[' {
			return nil, refuse(StepResolve, "release list holds a %v, want arrays of releases", kind)
		}
		pages++
		if pages > maxPages {
			return nil, refuse(StepResolve, "release list has more than %d pages", maxPages)
		}
		var page []releaseJSON
		if err := json.UnmarshalDecode(dec, &page); err != nil {
			return nil, fmt.Errorf("decode release page: %w", err)
		}
		all = append(all, page...)
		if len(all) > maxReleases {
			return nil, refuse(StepResolve, "release list has more than %d releases", maxReleases)
		}
	}
	if pages == 0 {
		return nil, refuse(StepResolve, "release list is empty, want at least one page")
	}
	return all, nil
}

// resolve selects the one draft release of the tag and checks its asset set.
func resolve(ctx context.Context, r runner.Runner, gh string, pl plan) (resolved, error) {
	releases, err := listReleases(ctx, r, gh, pl.repo)
	if err != nil {
		return resolved{}, err
	}
	var matches []releaseJSON
	for _, rel := range releases {
		if rel.TagName == pl.tag {
			matches = append(matches, rel)
		}
	}
	switch len(matches) {
	case 0:
		return resolved{}, refuse(StepResolve, "no release has tag %q", pl.tag)
	case 1:
	default:
		return resolved{}, refuse(StepResolve, "%d releases have tag %q, want exactly one", len(matches), pl.tag)
	}
	rel := matches[0]
	if !rel.Draft {
		return resolved{}, refuse(StepResolve, "release %d of tag %q is not a draft", rel.ID, pl.tag)
	}
	if rel.ID <= 0 {
		return resolved{}, refuse(StepResolve, "release of tag %q has the invalid id %d", pl.tag, rel.ID)
	}
	assets, err := checkAssets(rel.Assets, pl.expected)
	if err != nil {
		return resolved{}, err
	}
	return resolved{id: rel.ID, assets: assets}, nil
}

// checkAssets requires exactly the expected names, each once.
func checkAssets(got []assetJSON, expected []string) (map[string]asset, error) {
	if len(got) > maxAssets {
		return nil, refuse(StepResolve, "release has %d assets, more than the bound %d", len(got), maxAssets)
	}
	assets := make(map[string]asset, len(got))
	for _, a := range got {
		if !slices.Contains(expected, a.Name) {
			return nil, refuse(StepResolve, "release has the unexpected asset %q", a.Name)
		}
		if _, dup := assets[a.Name]; dup {
			return nil, refuse(StepResolve, "release has the asset %q more than once", a.Name)
		}
		if a.ID <= 0 || a.Size < 0 {
			return nil, refuse(StepResolve, "asset %q has the invalid id %d or size %d", a.Name, a.ID, a.Size)
		}
		assets[a.Name] = asset{ID: a.ID, Name: a.Name, Size: a.Size}
	}
	for _, name := range expected {
		if _, ok := assets[name]; !ok {
			return nil, refuse(StepResolve, "release lacks the asset %q", name)
		}
	}
	return assets, nil
}
