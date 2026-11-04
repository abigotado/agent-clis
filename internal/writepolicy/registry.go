// Package writepolicy stores exact immutable YouTrack project ID+key pairs.
package writepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/abigotado/youtrack-agent-cli/internal/lockfile"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

const (
	registryVersion  = 1
	registryFilename = "write-policies.json"
	maxRegistryBytes = 1 << 20
	maxPolicies      = 1024
	maxProjects      = 256
	maxProjectID     = 128
	maxProjectKey    = 64
)

var (
	projectIDPattern  = regexp.MustCompile(fmt.Sprintf(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,%d}$`, maxProjectID-1))
	projectKeyPattern = regexp.MustCompile(fmt.Sprintf(`^[A-Z][A-Z0-9_]{0,%d}$`, maxProjectKey-1))
	identityPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// ErrNotFound means a profile has no write policy.
	ErrNotFound = errors.New("write policy not found")
	// ErrStale means the policy belongs to different profile metadata.
	ErrStale = errors.New("write policy identity is stale")
	// ErrProjectDenied means the exact project ID+key pair is not allowed.
	ErrProjectDenied = errors.New("project is not allowed for writes")
	// ErrInvalid means policy input is invalid.
	ErrInvalid = errors.New("invalid write policy")
	// ErrCorruptRegistry means the on-disk registry failed strict validation.
	ErrCorruptRegistry = errors.New("write policy registry is corrupt")
	// ErrInsecurePermissions means the registry is accessible too broadly.
	ErrInsecurePermissions = errors.New("write policy registry has insecure permissions")
)

// CommitError reports that the atomic rename completed but a following
// directory durability check failed. Callers must reconcile the persisted
// policy instead of assuming the mutation did not apply.
type CommitError struct {
	Err error
}

func (e *CommitError) Error() string {
	return fmt.Sprintf("write policy committed but durability check failed: %v", e.Err)
}

func (e *CommitError) Unwrap() error { return e.Err }

// WasCommitted identifies a post-rename write-policy failure.
func WasCommitted(err error) bool {
	var committed *CommitError
	return errors.As(err, &committed)
}

// Project is an immutable project entity ID paired with its expected key.
type Project struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// Policy is one profile's identity-bound project allowlist. Identity is a
// lowercase SHA-256 digest of canonical, non-secret profile metadata.
type Policy struct {
	Profile  string    `json:"profile"`
	Identity string    `json:"identity"`
	Revision uint64    `json:"revision"`
	Projects []Project `json:"projects"`
}

type registryFile struct {
	Version  int      `json:"version"`
	Policies []Policy `json:"policies"`
}

// Registry persists policies in a strict atomic 0600 JSON file.
type Registry struct {
	path    string
	openDir func(string) (*os.File, error)
}

// NewRegistry creates a registry at an explicit path.
func NewRegistry(path string) *Registry { return &Registry{path: path} }

// NewDefaultRegistry creates the user-scoped registry beside profiles.json.
func NewDefaultRegistry() (*Registry, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locate user config directory: %w", err)
	}
	return NewRegistry(filepath.Join(dir, "youtrack-agent-cli", registryFilename)), nil
}

// Path returns the registry path.
func (r *Registry) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// IdentityFor returns the fixed identity binding for canonical non-secret
// profile metadata. Profile validation guarantees the capability order.
func IdentityFor(value profile.Profile) string {
	return profile.CredentialIdentity(value)
}

// WithPolicyLock serializes operations for one profile. Callers that also
// need the profile lock must acquire it first.
func (r *Registry) WithPolicyLock(ctx context.Context, name string, fn func() error) error {
	if err := profile.RequireName(name); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("write policy lock callback is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || r.path == "" {
		return errors.New("write policy registry path is empty")
	}
	if err := ensureDir(filepath.Dir(r.path)); err != nil {
		return err
	}
	return lockfile.With(r.path+".profile-"+name, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn()
	})
}

// Get returns one policy without interpreting its identity.
func (r *Registry) Get(ctx context.Context, name string) (Policy, error) {
	if err := profile.RequireName(name); err != nil {
		return Policy{}, err
	}
	if err := ctx.Err(); err != nil {
		return Policy{}, err
	}
	file, err := r.read()
	if err != nil {
		return Policy{}, err
	}
	for _, candidate := range file.Policies {
		if candidate.Profile == name {
			return candidate, nil
		}
	}
	return Policy{}, fmt.Errorf("%w: %s", ErrNotFound, name)
}

// GetBound returns a policy only when it belongs to the exact current profile.
func (r *Registry) GetBound(ctx context.Context, value profile.Profile) (Policy, error) {
	if err := value.Validate(); err != nil {
		return Policy{}, err
	}
	policy, err := r.Get(ctx, value.Name)
	if err != nil {
		return Policy{}, err
	}
	if policy.Identity != IdentityFor(value) {
		return Policy{}, fmt.Errorf("%w: %s", ErrStale, value.Name)
	}
	return policy, nil
}

// RequireProject returns the bound policy only for the exact ID+key pair.
func (r *Registry) RequireProject(ctx context.Context, value profile.Profile, projectID, projectKey string) (Policy, error) {
	if err := validateProject(Project{ID: projectID, Key: projectKey}); err != nil {
		return Policy{}, err
	}
	policy, err := r.GetBound(ctx, value)
	if err != nil {
		return Policy{}, err
	}
	index := sort.Search(len(policy.Projects), func(index int) bool {
		return compareProject(policy.Projects[index], Project{ID: projectID, Key: projectKey}) >= 0
	})
	if index < len(policy.Projects) && policy.Projects[index].ID == projectID && policy.Projects[index].Key == projectKey {
		return policy, nil
	}
	return Policy{}, fmt.Errorf("%w: %s/%s", ErrProjectDenied, projectID, projectKey)
}

// Set replaces one profile's policy after canonicalizing projects.
func (r *Registry) Set(ctx context.Context, value profile.Profile, projects []Project) (Policy, error) {
	if err := value.Validate(); err != nil {
		return Policy{}, err
	}
	if value.CredentialGeneration == "" || !hasMutationCapability(value) {
		return Policy{}, fmt.Errorf("%w: profile must have a current mutation-capable credential", ErrInvalid)
	}
	canonical, err := CanonicalProjects(projects)
	if err != nil {
		return Policy{}, err
	}
	policy := Policy{Profile: value.Name, Identity: IdentityFor(value), Revision: 1, Projects: canonical}
	err = r.mutate(ctx, func(file registryFile) (registryFile, error) {
		for index := range file.Policies {
			if file.Policies[index].Profile == value.Name {
				if file.Policies[index].Revision == ^uint64(0) {
					return file, fmt.Errorf("%w: policy revision is exhausted", ErrInvalid)
				}
				policy.Revision = file.Policies[index].Revision + 1
				file.Policies[index] = policy
				return file, nil
			}
		}
		file.Policies = append(file.Policies, policy)
		return file, nil
	})
	return policy, err
}

// Clear removes one profile's policy. Missing policy is an idempotent success.
func (r *Registry) Clear(ctx context.Context, name string) error {
	if err := profile.RequireName(name); err != nil {
		return err
	}
	return r.mutate(ctx, func(file registryFile) (registryFile, error) {
		for index, candidate := range file.Policies {
			if candidate.Profile == name {
				file.Policies = append(file.Policies[:index:index], file.Policies[index+1:]...)
				break
			}
		}
		return file, nil
	})
}

// CanonicalProjects validates, sorts, and deduplicates exact project pairs.
func CanonicalProjects(projects []Project) ([]Project, error) {
	if len(projects) == 0 || len(projects) > maxProjects {
		return nil, fmt.Errorf("%w: provide 1-%d projects", ErrInvalid, maxProjects)
	}
	seenIDs := make(map[string]string, len(projects))
	seenKeys := make(map[string]string, len(projects))
	canonical := make([]Project, 0, len(projects))
	for _, value := range projects {
		project := Project{ID: strings.TrimSpace(value.ID), Key: strings.TrimSpace(value.Key)}
		if err := validateProject(project); err != nil {
			return nil, err
		}
		if key, exists := seenIDs[project.ID]; exists {
			if key != project.Key {
				return nil, fmt.Errorf("%w: project ID %q is paired with multiple keys", ErrInvalid, project.ID)
			}
			continue
		}
		if id, exists := seenKeys[project.Key]; exists && id != project.ID {
			return nil, fmt.Errorf("%w: project key %q is paired with multiple IDs", ErrInvalid, project.Key)
		}
		seenIDs[project.ID] = project.Key
		seenKeys[project.Key] = project.ID
		canonical = append(canonical, project)
	}
	sort.Slice(canonical, func(i, j int) bool { return compareProject(canonical[i], canonical[j]) < 0 })
	return canonical, nil
}

func validateProject(project Project) error {
	if !projectIDPattern.MatchString(project.ID) {
		return fmt.Errorf("%w: project ID %q is invalid", ErrInvalid, project.ID)
	}
	if !projectKeyPattern.MatchString(project.Key) {
		return fmt.Errorf("%w: project key %q is invalid", ErrInvalid, project.Key)
	}
	return nil
}

func compareProject(left, right Project) int {
	if compared := strings.Compare(left.ID, right.ID); compared != 0 {
		return compared
	}
	return strings.Compare(left.Key, right.Key)
}

func hasMutationCapability(value profile.Profile) bool {
	return value.HasCapability(profile.CapabilityIssueCreate) || value.HasCapability(profile.CapabilityIssueUpdate) || value.HasCapability(profile.CapabilityCommentAdd) || value.HasCapability(profile.CapabilityCommentDelete)
}

func (r *Registry) mutate(ctx context.Context, change func(registryFile) (registryFile, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || r.path == "" {
		return errors.New("write policy registry path is empty")
	}
	if err := ensureDir(filepath.Dir(r.path)); err != nil {
		return err
	}
	return lockfile.With(r.path, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := r.read()
		if err != nil {
			return err
		}
		file, err = change(file)
		if err != nil {
			return err
		}
		if len(file.Policies) > maxPolicies {
			return fmt.Errorf("write policy registry cannot contain more than %d policies", maxPolicies)
		}
		sort.Slice(file.Policies, func(i, j int) bool { return file.Policies[i].Profile < file.Policies[j].Profile })
		for _, policy := range file.Policies {
			if err := validatePolicy(policy); err != nil {
				return fmt.Errorf("%w: %v", ErrCorruptRegistry, err)
			}
		}
		return r.write(file)
	})
}

func (r *Registry) read() (registryFile, error) {
	empty := registryFile{Version: registryVersion, Policies: []Policy{}}
	if r == nil || r.path == "" {
		return empty, errors.New("write policy registry path is empty")
	}
	if err := validateDir(filepath.Dir(r.path)); err != nil {
		return empty, err
	}
	info, err := os.Lstat(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, fmt.Errorf("inspect write policy registry: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return empty, fmt.Errorf("%w: %s must be a regular 0600 file", ErrInsecurePermissions, r.path)
	}
	raw, err := readBoundedRegularFile(r.path, info)
	if err != nil {
		return empty, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var file registryFile
	if err := decoder.Decode(&file); err != nil {
		return empty, fmt.Errorf("%w: decode: %v", ErrCorruptRegistry, err)
	}
	if file.Version != registryVersion || file.Policies == nil {
		return empty, fmt.Errorf("%w: unsupported version or null policies", ErrCorruptRegistry)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return empty, fmt.Errorf("%w: trailing data", ErrCorruptRegistry)
	}
	if len(file.Policies) > maxPolicies {
		return empty, fmt.Errorf("%w: too many policies", ErrCorruptRegistry)
	}
	seen := make(map[string]struct{}, len(file.Policies))
	previous := ""
	for _, policy := range file.Policies {
		if err := validatePolicy(policy); err != nil {
			return empty, fmt.Errorf("%w: %v", ErrCorruptRegistry, err)
		}
		if _, exists := seen[policy.Profile]; exists {
			return empty, fmt.Errorf("%w: duplicate profile %q", ErrCorruptRegistry, policy.Profile)
		}
		if previous != "" && policy.Profile < previous {
			return empty, fmt.Errorf("%w: policies must be sorted by profile", ErrCorruptRegistry)
		}
		seen[policy.Profile] = struct{}{}
		previous = policy.Profile
	}
	return file, nil
}

func readBoundedRegularFile(path string, inspected os.FileInfo) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open write policy registry: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("inspect opened write policy registry: %w", err), wrapIfError("close write policy registry", file.Close()))
	}
	if !os.SameFile(inspected, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 {
		return nil, errors.Join(fmt.Errorf("%w: registry changed during inspection or is not a regular 0600 file", ErrInsecurePermissions), wrapIfError("close write policy registry", file.Close()))
	}
	if opened.Size() > maxRegistryBytes {
		return nil, errors.Join(fmt.Errorf("%w: file exceeds %d bytes", ErrCorruptRegistry, maxRegistryBytes), wrapIfError("close write policy registry", file.Close()))
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxRegistryBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, errors.Join(fmt.Errorf("read write policy registry: %w", readErr), wrapIfError("close write policy registry", closeErr))
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close write policy registry: %w", closeErr)
	}
	if len(raw) > maxRegistryBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrCorruptRegistry, maxRegistryBytes)
	}
	return raw, nil
}

func validatePolicy(policy Policy) error {
	if err := profile.ValidateName(policy.Profile); err != nil {
		return err
	}
	if !identityPattern.MatchString(policy.Identity) {
		return fmt.Errorf("%w: identity must be a lowercase SHA-256 digest", ErrInvalid)
	}
	if policy.Revision == 0 {
		return fmt.Errorf("%w: revision must be positive", ErrInvalid)
	}
	canonical, err := CanonicalProjects(policy.Projects)
	if err != nil {
		return err
	}
	if len(canonical) != len(policy.Projects) {
		return fmt.Errorf("%w: projects must be unique", ErrInvalid)
	}
	for index := range canonical {
		if canonical[index] != policy.Projects[index] {
			return fmt.Errorf("%w: projects must be sorted and canonical", ErrInvalid)
		}
	}
	return nil
}

func ensureDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create write policy directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("secure write policy directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect write policy directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: %s must be a 0700 directory", ErrInsecurePermissions, dir)
	}
	return nil
}

func validateDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect write policy directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: %s must be a 0700 directory", ErrInsecurePermissions, dir)
	}
	return nil
}

func (r *Registry) write(file registryFile) error {
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("encode write policy registry: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maxRegistryBytes {
		return fmt.Errorf("%w: encoded registry exceeds %d bytes", ErrInvalid, maxRegistryBytes)
	}
	dir := filepath.Dir(r.path)
	tmp, err := os.CreateTemp(dir, ".write-policies-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary write policy registry: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup is safe because tmpName is returned by CreateTemp in
	// the already validated policy directory.
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		return errors.Join(fmt.Errorf("secure temporary write policy registry: %w", err), wrapIfError("close temporary write policy registry", tmp.Close()))
	}
	if _, err := tmp.Write(raw); err != nil {
		return errors.Join(fmt.Errorf("write temporary write policy registry: %w", err), wrapIfError("close temporary write policy registry", tmp.Close()))
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync temporary write policy registry: %w", err), wrapIfError("close temporary write policy registry", tmp.Close()))
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary write policy registry: %w", err)
	}
	if err := os.Rename(tmpName, r.path); err != nil {
		return fmt.Errorf("replace write policy registry: %w", err)
	}
	openDir := r.openDir
	if openDir == nil {
		openDir = os.Open
	}
	directory, err := openDir(dir)
	if err != nil {
		return &CommitError{Err: fmt.Errorf("open write policy directory for sync: %w", err)}
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return &CommitError{Err: errors.Join(
			wrapIfError("sync write policy directory", syncErr),
			wrapIfError("close write policy directory", closeErr),
		)}
	}
	return nil
}

func wrapIfError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
