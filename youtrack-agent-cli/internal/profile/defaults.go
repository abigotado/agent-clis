package profile

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

	"github.com/abigotado/youtrack-agent-cli/internal/lockfile"
)

const (
	defaultsFilename = "profile-defaults.json"
	defaultsVersion  = 1
	maxDefaultsBytes = 8 << 10
)

var defaultIdentityPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DefaultSlot names one profile and binds that selection to stable, non-secret
// profile metadata.
type DefaultSlot struct {
	ProfileName           string `json:"profile_name"`
	ProfileIdentitySHA256 string `json:"profile_identity_sha256"`
}

// Defaults contains the independently selectable saved read and write profiles.
// A nil slot is intentionally omitted from the durable JSON document.
type Defaults struct {
	Version int          `json:"version"`
	Read    *DefaultSlot `json:"read,omitempty"`
	Write   *DefaultSlot `json:"write,omitempty"`
}

// DefaultsPath returns the sibling defaults document path.
func (r *Registry) DefaultsPath() string {
	if r == nil || r.path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(r.path), defaultsFilename)
}

// GetDefaults reads the strict non-secret defaults document. A missing file is
// represented by the version-only empty document.
func (r *Registry) GetDefaults(ctx context.Context) (Defaults, error) {
	if err := ctx.Err(); err != nil {
		return Defaults{}, err
	}
	return r.readDefaults()
}

// UpdateDefaults performs one defaults read-modify-write under its distinct
// lock. Callers that bind slots to profiles must acquire sorted profile locks
// before calling this method.
func (r *Registry) UpdateDefaults(ctx context.Context, change func(Defaults) (Defaults, error)) (Defaults, error) {
	if change == nil {
		return Defaults{}, errors.New("profile defaults change is nil")
	}
	if err := ctx.Err(); err != nil {
		return Defaults{}, err
	}
	path := r.DefaultsPath()
	if path == "" {
		return Defaults{}, errors.New("profile registry path is empty")
	}
	if err := ensureRegistryDir(filepath.Dir(path)); err != nil {
		return Defaults{}, err
	}
	var saved Defaults
	err := lockfile.With(path, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := r.readDefaults()
		if err != nil {
			return err
		}
		saved, err = change(current)
		if err != nil {
			return err
		}
		if err := validateDefaults(saved); err != nil {
			return fmt.Errorf("%w: %v", ErrCorruptRegistry, err)
		}
		return r.writeDefaults(saved)
	})
	return saved, err
}

// ClearDefaults clears the requested slots under only the defaults lock. It
// deliberately does not inspect profile or credential state.
func (r *Registry) ClearDefaults(ctx context.Context, clearRead, clearWrite bool) (Defaults, error) {
	return r.UpdateDefaults(ctx, func(current Defaults) (Defaults, error) {
		if clearRead {
			current.Read = nil
		}
		if clearWrite {
			current.Write = nil
		}
		return current, nil
	})
}

func (r *Registry) readDefaults() (Defaults, error) {
	empty := Defaults{Version: defaultsVersion}
	path := r.DefaultsPath()
	if path == "" {
		return empty, errors.New("profile registry path is empty")
	}
	if err := validateRegistryDir(filepath.Dir(path)); err != nil {
		return empty, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, fmt.Errorf("inspect profile defaults: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return empty, fmt.Errorf("%w: %s must be a regular 0600 file", ErrInsecurePermissions, path)
	}
	if info.Size() > maxDefaultsBytes {
		return empty, fmt.Errorf("%w: file exceeds %d bytes", ErrCorruptRegistry, maxDefaultsBytes)
	}
	raw, err := readDefaultsFile(path, info)
	if err != nil {
		return empty, err
	}
	value, err := decodeDefaults(raw)
	if err != nil {
		return empty, err
	}
	return value, nil
}

func readDefaultsFile(path string, inspected os.FileInfo) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open profile defaults: %w", err)
	}
	opened, statErr := file.Stat()
	if statErr != nil {
		closeErr := file.Close()
		return nil, errors.Join(fmt.Errorf("inspect opened profile defaults: %w", statErr), wrapIfError("close profile defaults", closeErr))
	}
	if !os.SameFile(inspected, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 {
		closeErr := file.Close()
		return nil, errors.Join(fmt.Errorf("%w: defaults changed during inspection or are not a regular 0600 file", ErrInsecurePermissions), wrapIfError("close profile defaults", closeErr))
	}
	if opened.Size() > maxDefaultsBytes {
		closeErr := file.Close()
		return nil, errors.Join(fmt.Errorf("%w: file exceeds %d bytes", ErrCorruptRegistry, maxDefaultsBytes), wrapIfError("close profile defaults", closeErr))
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxDefaultsBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, errors.Join(fmt.Errorf("read profile defaults: %w", readErr), wrapIfError("close profile defaults", closeErr))
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close profile defaults: %w", closeErr)
	}
	if len(raw) > maxDefaultsBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrCorruptRegistry, maxDefaultsBytes)
	}
	return raw, nil
}

func decodeDefaults(raw []byte) (Defaults, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return Defaults{}, fmt.Errorf("%w: decode defaults: %v", ErrCorruptRegistry, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return Defaults{}, fmt.Errorf("%w: top-level JSON value must be an object", ErrCorruptRegistry)
	}
	value := Defaults{}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return Defaults{}, fmt.Errorf("%w: decode defaults field: %v", ErrCorruptRegistry, err)
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return Defaults{}, fmt.Errorf("%w: duplicate or invalid defaults field", ErrCorruptRegistry)
		}
		seen[name] = true
		switch name {
		case "version":
			var rawVersion json.RawMessage
			if err := decoder.Decode(&rawVersion); err != nil || bytes.Equal(rawVersion, []byte("null")) || json.Unmarshal(rawVersion, &value.Version) != nil {
				return Defaults{}, fmt.Errorf("%w: version must be an integer", ErrCorruptRegistry)
			}
		case "read", "write":
			slot, err := decodeDefaultSlot(decoder)
			if err != nil {
				return Defaults{}, err
			}
			if name == "read" {
				value.Read = &slot
			} else {
				value.Write = &slot
			}
		default:
			return Defaults{}, fmt.Errorf("%w: unknown defaults field", ErrCorruptRegistry)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return Defaults{}, fmt.Errorf("%w: close defaults object: %v", ErrCorruptRegistry, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Defaults{}, err
	}
	if err := validateDefaults(value); err != nil {
		return Defaults{}, fmt.Errorf("%w: %v", ErrCorruptRegistry, err)
	}
	return value, nil
}

func decodeDefaultSlot(decoder *json.Decoder) (DefaultSlot, error) {
	token, err := decoder.Token()
	if err != nil {
		return DefaultSlot{}, fmt.Errorf("%w: decode default slot: %v", ErrCorruptRegistry, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return DefaultSlot{}, fmt.Errorf("%w: default slot must be an object", ErrCorruptRegistry)
	}
	value := DefaultSlot{}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return DefaultSlot{}, fmt.Errorf("%w: decode default slot field: %v", ErrCorruptRegistry, err)
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return DefaultSlot{}, fmt.Errorf("%w: duplicate or invalid default slot field", ErrCorruptRegistry)
		}
		seen[name] = true
		var rawValue json.RawMessage
		if err := decoder.Decode(&rawValue); err != nil || bytes.Equal(rawValue, []byte("null")) {
			return DefaultSlot{}, fmt.Errorf("%w: default slot value must be a string", ErrCorruptRegistry)
		}
		switch name {
		case "profile_name":
			if err := json.Unmarshal(rawValue, &value.ProfileName); err != nil {
				return DefaultSlot{}, fmt.Errorf("%w: profile_name must be a string", ErrCorruptRegistry)
			}
		case "profile_identity_sha256":
			if err := json.Unmarshal(rawValue, &value.ProfileIdentitySHA256); err != nil {
				return DefaultSlot{}, fmt.Errorf("%w: profile_identity_sha256 must be a string", ErrCorruptRegistry)
			}
		default:
			return DefaultSlot{}, fmt.Errorf("%w: unknown default slot field", ErrCorruptRegistry)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return DefaultSlot{}, fmt.Errorf("%w: close default slot: %v", ErrCorruptRegistry, err)
	}
	if !seen["profile_name"] || !seen["profile_identity_sha256"] {
		return DefaultSlot{}, fmt.Errorf("%w: default slot requires profile_name and profile_identity_sha256", ErrCorruptRegistry)
	}
	return value, nil
}

func validateDefaults(value Defaults) error {
	if value.Version != defaultsVersion {
		return fmt.Errorf("unsupported defaults version")
	}
	for _, slot := range []*DefaultSlot{value.Read, value.Write} {
		if slot == nil {
			continue
		}
		if err := ValidateName(slot.ProfileName); err != nil {
			return err
		}
		if !defaultIdentityPattern.MatchString(slot.ProfileIdentitySHA256) {
			return errors.New("profile_identity_sha256 must be a lowercase SHA-256 digest")
		}
	}
	return nil
}

func (r *Registry) writeDefaults(value Defaults) error {
	path := r.DefaultsPath()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode profile defaults: %w", err)
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".profile-defaults-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary profile defaults: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// A successful rename makes this a harmless ErrNotExist. On failure it
		// prevents a partial defaults document from being mistaken for user data.
		_ = os.Remove(tmpName) // Best-effort cleanup of a private temporary file.
	}()
	if err := tmp.Chmod(0o600); err != nil {
		closeErr := tmp.Close()
		return errors.Join(fmt.Errorf("secure temporary profile defaults: %w", err), closeErr)
	}
	if _, err := tmp.Write(raw); err != nil {
		closeErr := tmp.Close()
		return errors.Join(fmt.Errorf("write temporary profile defaults: %w", err), closeErr)
	}
	if err := tmp.Sync(); err != nil {
		closeErr := tmp.Close()
		return errors.Join(fmt.Errorf("sync temporary profile defaults: %w", err), closeErr)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary profile defaults: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace profile defaults: %w", err)
	}
	openDir := r.openDir
	if openDir == nil {
		openDir = os.Open
	}
	directory, err := openDir(dir)
	if err != nil {
		return &CommitError{Err: fmt.Errorf("open profile defaults directory for sync: %w", err)}
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return &CommitError{Err: errors.Join(
			wrapIfError("sync profile defaults directory", syncErr),
			wrapIfError("close profile defaults directory", closeErr),
		)}
	}
	return nil
}
