package operatorwrite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/lockfile"
	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

// Store keeps immutable plans and permanent consumption markers outside the
// native journal namespace. Successful Claim is the only dispatch permission.
// A failed Claim never permits dispatch, even if a partial marker remains.
type Store struct {
	root      string
	writeFile func(*os.File, []byte) (int, error)
	syncFile  func(*os.File) error
	syncDir   func(*os.File) error
}

func New(root string) *Store {
	if root == "" {
		return &Store{}
	}
	return &Store{root: filepath.Join(root, "operator-writes-v1")}
}
func NewDefault() (*Store, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, localFailure("locate operator-write storage", err)
	}
	return New(filepath.Join(dir, "youtrack-agent-cli")), nil
}
func (s *Store) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

func localFailure(operation string, cause error) error {
	return errx.Internal("%s failed; no write is authorized by this storage failure", operation).
		WithHint("retain the operator-write files; inspect local storage before preparing any new write").Wrap(cause)
}
func consumed() error {
	return errx.Conflict("OPERATOR_PLAN_CONSUMED", "operator-write plan has already been consumed").
		WithHint("do not repeat this plan; use bounded read-only reconciliation")
}

func (s *Store) with(ctx context.Context, id string, fn func(*secureDirectory) error) (err error) {
	if ctx == nil {
		return invalid()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ValidateID(id) != nil || s == nil || s.root == "" {
		return invalid()
	}
	d, err := openDirectory(s.root, true)
	if err != nil {
		return localFailure("open private operator-write storage", err)
	}
	defer func() {
		if e := d.close(); e != nil {
			err = errors.Join(err, localFailure("close operator-write storage", e))
		}
	}()
	// The lock is released before Claim returns and therefore before HTTP.
	err = lockfile.With(filepath.Join(d.path, id), func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(d)
	})
	if err != nil {
		var typed *errx.Error
		if !errors.As(err, &typed) {
			return localFailure("access operator-write storage", err)
		}
	}
	return err
}

func (s *Store) Create(ctx context.Context, p Plan) (Record, error) {
	if err := ValidatePlan(p); err != nil {
		return Record{}, err
	}
	var record Record
	err := s.with(ctx, p.ID, func(d *secureDirectory) error {
		if exists, err := d.exists(p.ID + ".claim"); err != nil {
			return err
		} else if exists {
			return consumed()
		}
		raw, err := json.Marshal(p)
		if err != nil || len(raw) > MaxPlanBytes {
			return invalid()
		}
		if err := d.create(p.ID+".json", raw, s); err != nil {
			return err
		}
		record = Record{Version: Version, Plan: p, State: StatePrepared}
		return nil
	})
	return record, err
}

func (s *Store) Get(ctx context.Context, id string) (Record, error) {
	var record Record
	err := s.with(ctx, id, func(d *secureDirectory) error { var err error; record, err = readRecord(d, id); return err })
	return record, err
}

func readRecord(d *secureDirectory, id string) (Record, error) {
	raw, err := d.read(id+".json", MaxPlanBytes)
	if err != nil {
		return Record{}, err
	}
	p, err := DecodePlan(bytes.NewReader(raw))
	if err != nil || p.ID != id {
		return Record{}, invalid()
	}
	r := Record{Version: Version, Plan: p, State: StatePrepared}
	raw, err = d.read(id+".claim", 4096)
	if errors.Is(err, os.ErrNotExist) {
		// Result without its permanent claim is never a prepared record.
		if exists, e := d.exists(id + ".result"); e != nil {
			return Record{}, e
		} else if exists {
			return Record{}, invalid()
		}
		return r, nil
	}
	if err != nil {
		return Record{}, err
	}
	var a Attempt
	if decode(bytes.NewReader(raw), 4096, &a) != nil || !validAttempt(a, p) {
		return Record{}, invalid()
	}
	r.Attempt = &a
	r.State = StateInFlight
	raw, err = d.read(id+".result", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return Record{}, err
	}
	var result Result
	if decode(bytes.NewReader(raw), 4096, &result) != nil || !validResult(result) {
		return Record{}, invalid()
	}
	r.Result = &result
	r.State = result.State
	return r, nil
}

func validAttempt(a Attempt, p Plan) bool {
	if protocolvalue.ValidateCanonicalBase32ID(a.ID, "YTOA-") != nil || a.PlanSHA256 != p.SHA256 ||
		a.ClaimedAt.Before(p.CreatedAt) || a.ClaimedAt.Location() != time.UTC {
		return false
	}
	return p.Version == PlanVersion2 || p.Version == LegacyPlanVersion1 && a.ClaimedAt.Before(p.ExpiresAt)
}

func (s *Store) Claim(ctx context.Context, id, sha string, now time.Time) (Attempt, error) {
	var attempt Attempt
	err := s.with(ctx, id, func(d *secureDirectory) error {
		// Any marker, including an incomplete/symlinked marker, consumes the plan.
		if exists, err := d.exists(id + ".claim"); err != nil {
			return err
		} else if exists {
			return consumed()
		}
		r, err := readRecord(d, id)
		if err != nil {
			return err
		}
		if r.NonReplayable() {
			return consumed()
		}
		if !protocolvalue.IsSHA256(sha) || sha != r.Plan.SHA256 {
			return errx.OperatorConfirmRequired()
		}
		if err := CheckFresh(r.Plan, now); err != nil {
			return err
		}
		attemptID, err := newID("YTOA-")
		if err != nil {
			return err
		}
		a := Attempt{ID: attemptID, PlanSHA256: sha, ClaimedAt: now.UTC()}
		raw, err := json.Marshal(a)
		if err != nil {
			return invalid()
		}
		if err := d.create(id+".claim", raw, s); err != nil {
			return err
		}
		attempt = a
		return nil
	})
	if err != nil {
		return Attempt{}, err
	}
	return attempt, nil
}

func validResult(r Result) bool {
	if r.State != StateApplied && r.State != StateUnknown && r.State != StateRejected && r.State != StateReconciled && r.State != StateOperatorRequired {
		return false
	}
	return protocolvalue.IsIdentifier(r.Code) && (r.RemoteID == "" || protocolvalue.IsIdentifier(r.RemoteID)) &&
		(r.RemoteReadableID == "" || protocolvalue.IsIdentifier(r.RemoteReadableID)) &&
		(r.EvidenceSHA256 == "" || protocolvalue.IsSHA256(r.EvidenceSHA256))
}

// Finalize never modifies or removes the claim. Reconciliation may advance only
// consumed outcomes and can never restore dispatch eligibility.
func (s *Store) Finalize(ctx context.Context, id string, a Attempt, result Result, now time.Time) (Record, error) {
	if !validResult(result) {
		return Record{}, invalid()
	}
	var record Record
	err := s.with(ctx, id, func(d *secureDirectory) error {
		r, err := readRecord(d, id)
		if err != nil {
			return err
		}
		if r.Attempt == nil || *r.Attempt != a || now.Before(a.ClaimedAt) {
			return invalid()
		}
		if r.Result != nil {
			if *r.Result == result {
				record = r
				return nil
			}
			if (r.State != StateInFlight && r.State != StateUnknown && r.State != StateOperatorRequired) ||
				(result.State != StateReconciled && result.State != StateOperatorRequired) {
				return consumed()
			}
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return invalid()
		}
		if r.Result == nil {
			err = d.create(id+".result", raw, s)
		} else {
			err = d.replace(id+".result", raw, s)
		}
		if err != nil {
			return err
		}
		r.Result = &result
		r.State = result.State
		record = r
		return nil
	})
	return record, err
}

func WriteSnapshot(ctx context.Context, path string, s Snapshot) error {
	if err := ValidateSnapshot(s); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return invalid()
	}
	return writeExport(ctx, path, raw)
}
func WritePlan(ctx context.Context, path string, p Plan) error {
	if err := ValidatePlan(p); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return invalid()
	}
	return writeExport(ctx, path, raw)
}
func writeExport(ctx context.Context, path string, raw []byte) (err error) {
	if ctx == nil || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return invalid()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d, err := openDirectory(filepath.Dir(path), false)
	if err != nil {
		return localFailure("open private export directory", err)
	}
	defer func() {
		if e := d.close(); e != nil {
			err = errors.Join(err, localFailure("close private export directory", e))
		}
	}()
	if err := d.create(filepath.Base(path), raw, nil); err != nil {
		return localFailure("write private exclusive export", err)
	}
	return nil
}

// ValidateExportPath is a read-only early check. The exclusive write repeats
// these checks at export time, so this cannot authorize an overwrite race.
func ValidateExportPath(ctx context.Context, path string) (err error) {
	if ctx == nil || path == "" || filepath.Base(path) == "." || filepath.Base(path) == ".." || filepath.Base(path) == string(filepath.Separator) {
		return invalid()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d, err := openDirectory(filepath.Dir(path), false)
	if err != nil {
		return localFailure("inspect private export directory", err)
	}
	defer func() {
		if e := d.close(); e != nil {
			err = errors.Join(err, localFailure("close private export directory", e))
		}
	}()
	if exists, err := d.exists(filepath.Base(path)); err != nil {
		return localFailure("inspect exclusive export target", err)
	} else if exists {
		return localFailure("inspect exclusive export target", os.ErrExist)
	}
	return nil
}
