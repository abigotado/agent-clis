package arch_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// These checks keep the documented inventories internally consistent. They do
// not validate native authorization, execute a Gate plan, or prove its safety.
func TestGateDocumentContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "docs", "gate1a-artifact-authorization.md"))
	if err != nil {
		t.Fatal(err)
	}
	document := string(raw)
	stages := []struct {
		header string
		prefix string
		count  string
	}{
		{"Gate 1A case", "gate1a.", "Gate 1A"},
		{"Gate 1B coverage family", "gate1b.", ""},
		{"Confirm smoke case", "smoke.confirm.", "Activation smoke / confirm-only"},
		{"Issue-create smoke case", "smoke.issue-create.", "Activation smoke / issue-create"},
		{"Post-grant confirm case", "post-grant.confirm.", "Post-grant / confirm-only"},
		{"Post-grant issue-create case", "post-grant.issue-create.", "Post-grant / issue-create"},
	}
	counts, err := gateContractTable(document, "Plan/capability", 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 5 {
		t.Fatalf("flat-stage count table has %d rows, want 5", len(counts))
	}
	for _, stage := range stages {
		t.Run(stage.header, func(t *testing.T) {
			rows, err := gateContractTable(document, stage.header, 4)
			if err != nil {
				t.Fatal(err)
			}
			ids, err := gateContractCaseList(document, stage.prefix)
			if err != nil {
				t.Fatal(err)
			}
			var tableIDs []string
			for _, row := range rows {
				tableIDs = append(tableIDs, strings.Trim(row[0], "`"))
			}
			if !slices.Equal(ids, tableIDs) {
				t.Fatalf("ordered case list %v differs from table %v", ids, tableIDs)
			}
			if stage.count != "" {
				if err := gateContractCounts(rows, counts, stage.count); err != nil {
					t.Error(err)
				}
			}
			if stage.prefix == "post-grant.issue-create." {
				if err := gateContractPostGrantDenials(rows); err != nil {
					t.Error(err)
				}
			}
		})
	}
	t.Run("busy ends actor phase", func(t *testing.T) {
		rows, err := gateContractTable(document, "Case/phase", 2)
		if err != nil {
			t.Fatal(err)
		}
		if err := gateContractBusyTerminal(rows); err != nil {
			t.Fatal(err)
		}
	})
}

// Only the simple pipe tables used by this contract are accepted. A changed
// table shape must be handled explicitly rather than silently dropping cells.
func gateContractTable(document, heading string, columns int, keyColumns ...int) ([][]string, error) {
	if len(keyColumns) == 0 {
		keyColumns = []int{0}
	}
	lines := strings.Split(document, "\n")
	var rows [][]string
	found := false
	for index, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		cells := gateContractCells(line)
		if cells[0] != heading {
			continue
		}
		if found {
			return nil, fmt.Errorf("duplicate contract table heading %q", heading)
		}
		found = true
		if len(cells) != columns || index+1 >= len(lines) {
			return nil, fmt.Errorf("malformed contract table heading %q", heading)
		}
		separator := gateContractCells(lines[index+1])
		if len(separator) != columns {
			return nil, fmt.Errorf("missing table separator for %q", heading)
		}
		for _, cell := range separator {
			if len(strings.Trim(cell, ":")) < 3 || strings.Trim(cell, "-:") != "" {
				return nil, fmt.Errorf("invalid table separator for %q", heading)
			}
		}
		seen := map[string]bool{}
		for _, row := range lines[index+2:] {
			if !strings.HasPrefix(strings.TrimSpace(row), "|") {
				break
			}
			values := gateContractCells(row)
			if len(values) != columns {
				return nil, fmt.Errorf("%q row has %d columns, want %d", heading, len(values), columns)
			}
			for _, value := range values {
				if value == "" {
					return nil, fmt.Errorf("%q has an empty cell", heading)
				}
			}
			var key []string
			for _, column := range keyColumns {
				key = append(key, values[column])
			}
			rowKey := strings.Join(key, "|")
			if seen[rowKey] {
				return nil, fmt.Errorf("%q has duplicate row %q", heading, values[0])
			}
			seen[rowKey] = true
			rows = append(rows, values)
		}
	}
	if !found || len(rows) == 0 {
		return nil, fmt.Errorf("missing or empty contract table %q", heading)
	}
	return rows, nil
}

func gateContractCells(line string) []string {
	cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for index := range cells {
		cells[index] = strings.TrimSpace(cells[index])
	}
	return cells
}

func gateContractCaseList(document, prefix string) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	for _, line := range strings.Split(document, "\n") {
		number, item, ok := strings.Cut(line, ". ")
		if !ok || !strings.HasPrefix(item, "`"+prefix) {
			continue
		}
		ordinal, err := strconv.Atoi(number)
		if err != nil || ordinal != len(ids)+1 || !strings.HasSuffix(item, "`") || strings.Count(item, "`") != 2 {
			return nil, fmt.Errorf("malformed or duplicate ordered %s case list at %q", prefix, line)
		}
		id := strings.Trim(item, "`")
		if seen[id] {
			return nil, fmt.Errorf("duplicate ordered case %q", id)
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("missing ordered %s case list", prefix)
	}
	return ids, nil
}

func gateContractItems(cell string) ([]string, error) {
	items := strings.Split(cell, ", ")
	seen := map[string]bool{}
	for index, item := range items {
		if len(item) < 3 || !strings.HasPrefix(item, "`") || !strings.HasSuffix(item, "`") || strings.Count(item, "`") != 2 {
			return nil, fmt.Errorf("malformed code list %q", cell)
		}
		items[index] = strings.Trim(item, "`")
		if seen[items[index]] {
			return nil, fmt.Errorf("duplicate code list member %q", items[index])
		}
		seen[items[index]] = true
	}
	return items, nil
}

func gateContractCounts(rows, counts [][]string, name string) error {
	derived := []int{len(rows), 0, len(rows), 2 * len(rows), 0}
	for _, row := range rows {
		steps, err := gateContractItems(row[1])
		if err != nil {
			return err
		}
		assertions, err := gateContractItems(row[2])
		if err != nil {
			return err
		}
		transcripts, err := gateContractItems(row[3])
		if err != nil {
			return err
		}
		derived[1] += len(steps)
		derived[2] += len(steps)
		derived[3] += len(steps) * (2 + len(transcripts))
		derived[4] += len(assertions)
	}
	for _, row := range counts {
		if row[0] != name {
			continue
		}
		for index, want := range derived {
			got, err := strconv.Atoi(row[index+1])
			if err != nil || got != want {
				return fmt.Errorf("%s count column %d is %q, table derives %d", name, index+1, row[index+1], want)
			}
		}
		return nil
	}
	return fmt.Errorf("missing flat-stage count row %q", name)
}

func gateContractPostGrantDenials(rows [][]string) error {
	required := map[string][]string{
		"post-grant.issue-create.update-comment-other-deny":    {"prepare-negatives", "apply-negatives"},
		"post-grant.issue-create.receipt-terminal-replay-deny": {"terminalize", "replay"},
	}
	for _, row := range rows {
		id := strings.Trim(row[0], "`")
		want, ok := required[id]
		if !ok {
			continue
		}
		steps, err := gateContractItems(row[1])
		if err != nil {
			return err
		}
		if !slices.Equal(steps, want) {
			return fmt.Errorf("%s steps %v, want %v", id, steps, want)
		}
		assertions, err := gateContractItems(row[2])
		if err != nil {
			return err
		}
		wantAssertions := []string{".terminal-state", ".replay-denied"}
		if strings.HasSuffix(id, ".update-comment-other-deny") {
			wantAssertions = []string{".zero-mutation-dispatch"}
		}
		for _, assertion := range wantAssertions {
			if !slices.Contains(assertions, assertion) {
				return fmt.Errorf("%s is missing assertion %s", id, assertion)
			}
		}
		delete(required, id)
	}
	if len(required) != 0 {
		return fmt.Errorf("missing post-grant denial cases: %v", required)
	}
	return nil
}

func gateContractBusyTerminal(rows [][]string) error {
	for _, row := range rows {
		busy := map[string]bool{}
		for _, event := range strings.Split(strings.Trim(row[1], "`"), " -> ") {
			actor, name, ok := strings.Cut(event, ":")
			if !ok || actor == "" || name == "" {
				return fmt.Errorf("%s has malformed event %q", row[0], event)
			}
			if busy[actor] {
				return fmt.Errorf("%s continues busy actor %s with %s", row[0], actor, name)
			}
			if name == "coordinator.acquire-busy" || name == "enrollment.busy-before-ledger" {
				busy[actor] = true
			}
		}
	}
	return nil
}

func TestGateAffectedVariantSelectorsAreUnique(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "docs", "gate1b-isolated-subruns.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Families intentionally span rows. The compound key permits that while
	// retaining the table parser's duplicate-row check.
	rows, err := gateContractTable(string(raw), "Family ID", 3, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateContractUniqueSelectors(rows); err != nil {
		t.Fatal(err)
	}
}

func gateContractUniqueSelectors(rows [][]string) error {
	type selector struct {
		family  string
		variant string
	}
	seen := map[selector]bool{}
	for _, row := range rows {
		families, err := gateContractItems(row[0])
		if err != nil {
			return err
		}
		if len(families) != 1 {
			return fmt.Errorf("selector row requires one family, got %v", families)
		}
		variants, err := gateContractItems(row[1])
		if err != nil {
			return err
		}
		for _, variant := range variants {
			key := selector{family: families[0], variant: variant}
			if seen[key] {
				return fmt.Errorf("duplicate selector %s / %s", key.family, key.variant)
			}
			seen[key] = true
		}
	}
	return nil
}

func TestGateContractGuardsRejectRegressions(t *testing.T) {
	t.Run("variant selectors are scoped by family", func(t *testing.T) {
		rows := [][]string{
			{"`family.one`", "`first`, `second`"},
			{"`family.two`", "`first`"},
		}
		if err := gateContractUniqueSelectors(rows); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, []string{"`family.one`", "`second`"})
		if err := gateContractUniqueSelectors(rows); err == nil {
			t.Fatal("accepted overlapping selectors in separate family rows")
		}
	})
	t.Run("flat counts drift", func(t *testing.T) {
		rows := [][]string{{"case", "`prepare`, `apply`", "`.primary`", "`network`"}}
		counts := [][]string{{"stage", "1", "2", "3", "8", "1"}}
		if err := gateContractCounts(rows, counts, "stage"); err != nil {
			t.Fatal(err)
		}
		counts[0][4] = "7"
		if err := gateContractCounts(rows, counts, "stage"); err == nil {
			t.Fatal("accepted incorrect transcript count")
		}
	})
	for _, event := range []string{"coordinator.acquire-busy", "enrollment.busy-before-ledger"} {
		t.Run(event, func(t *testing.T) {
			rows := [][]string{{"phase", "`A:apply.acquire -> R:" + event + " -> A:owner.quiesce`"}}
			if err := gateContractBusyTerminal(rows); err != nil {
				t.Fatal(err)
			}
			rows[0][1] = strings.TrimSuffix(rows[0][1], "`") + " -> R:registry.acquire`"
			if err := gateContractBusyTerminal(rows); err == nil {
				t.Fatal("accepted busy actor retry in same phase")
			}
		})
	}
	t.Run("missing post-grant deny", func(t *testing.T) {
		rows := [][]string{
			{"`post-grant.issue-create.update-comment-other-deny`", "`prepare-negatives`, `apply-negatives`", "`.primary`, `.zero-mutation-dispatch`"},
			{"`post-grant.issue-create.receipt-terminal-replay-deny`", "`terminalize`, `replay`", "`.primary`, `.terminal-state`, `.replay-denied`"},
		}
		if err := gateContractPostGrantDenials(rows); err != nil {
			t.Fatal(err)
		}
		if err := gateContractPostGrantDenials(rows[1:]); err == nil {
			t.Fatal("accepted missing capability denial")
		}
		rows[1][1] = "`consume`, `replay`"
		if err := gateContractPostGrantDenials(rows); err == nil {
			t.Fatal("accepted consuming a dispatch-denied receipt")
		}
	})
	t.Run("malformed tables", func(t *testing.T) {
		valid := "| Case | Steps |\n| --- | --- |\n| one | `run` |\n"
		if _, err := gateContractTable(valid, "Case", 2); err != nil {
			t.Fatal(err)
		}
		for name, document := range map[string]string{
			"missing": "", "duplicate heading": valid + "\n" + valid,
			"duplicate row": valid + "| one | `run` |\n",
			"missing cell":  valid + "| two |\n",
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := gateContractTable(document, "Case", 2); err == nil {
					t.Fatal("accepted malformed contract table")
				}
			})
		}
	})
}
