package coverage

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/attack"
)

// Expectation states. They are the four coverage states the plan's Phase 11
// matrix names, declared per technique:
//
//   - covered: detection content maps to the technique.
//   - partial: content maps, but the coverage is acknowledged incomplete
//     (a command-pattern analytic, one carrier of several). Still covered
//     for the gate, so losing the content is a regression.
//   - gap (planned): no content yet, but it is on the roadmap.
//   - none: no content and none planned in the engine — the technique is
//     owned by the sensor or console, listed so the matrix is honest rather
//     than silently short.
const (
	StateCovered = "covered"
	StatePartial = "partial"
	StateGap     = "gap"
	StateNone    = "none"
)

// Row is one line of an expectation file.
type Row struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Note  string `json:"note,omitempty"`
	Line  int    `json:"line,omitempty"`
}

// covers reports whether the state asserts the content maps to the technique.
func covers(state string) bool { return state == StateCovered || state == StatePartial }

// Gap is a technique the expectation declares as not covered by the engine.
// State is "planned" (on the roadmap) or "none" (owned elsewhere).
type Gap struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	State string `json:"state"`
	Note  string `json:"note,omitempty"`
}

// Expect is the committed coverage expectation: the techniques the content
// is known to cover and the techniques it is known not to. It is the matrix's
// baseline: the gate fails on any difference, in either direction, so a lost
// technique is a regression and a gained one has to be recorded on purpose.
//
// File format, one row per line, "#" comments:
//
//	T1003      covered   heuristic, yara
//	T1082      partial   command-pattern analytic, partial by design
//	T1140      gap       no static decode analytic yet (PLAN Phase 10)
//	T1046      none      network telemetry; the sensor owns it
type Expect struct {
	Rows []Row
}

var validState = map[string]bool{StateCovered: true, StatePartial: true, StateGap: true, StateNone: true}

// ParseExpect reads an expectation file.
func ParseExpect(r io.Reader) (*Expect, error) {
	e := &Expect{}
	seen := map[string]int{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: want \"<technique> covered|partial|gap|none [note]\", got %q", n, line)
		}
		id, state := strings.ToUpper(fields[0]), strings.ToLower(fields[1])
		if !attack.ValidID(id) {
			return nil, fmt.Errorf("line %d: %q is not an ATT&CK technique id", n, fields[0])
		}
		if !validState[state] {
			return nil, fmt.Errorf("line %d: state %q must be one of covered, partial, gap, none", n, fields[1])
		}
		if prev, dup := seen[id]; dup {
			return nil, fmt.Errorf("line %d: %s already listed on line %d", n, id, prev)
		}
		seen[id] = n
		e.Rows = append(e.Rows, Row{ID: id, State: state, Note: strings.Join(fields[2:], " "), Line: n})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return e, nil
}

// LoadExpect reads an expectation file from disk.
func LoadExpect(path string) (*Expect, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	e, err := ParseExpect(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}

// Problem is one disagreement between the matrix and the expectation.
type Problem struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // regression | undeclared | gap-closed
	Text string `json:"text"`
}

// Compare checks the matrix against the expectation, marks partial techniques
// and attaches the declared gaps to the matrix. It returns every
// disagreement, sorted by id.
func Compare(m *Matrix, e *Expect) []Problem {
	var problems []Problem
	declared := map[string]Row{}
	partial := map[string]bool{}
	for _, r := range e.Rows {
		declared[r.ID] = r
		switch {
		case covers(r.State):
			if !m.Covered(r.ID) {
				problems = append(problems, Problem{ID: r.ID, Kind: "regression",
					Text: fmt.Sprintf("%s is declared %s but no detection content maps to it any more", r.ID, r.State)})
			} else if r.State == StatePartial {
				partial[r.ID] = true
			}
		default: // gap or none
			if m.Covered(r.ID) {
				problems = append(problems, Problem{ID: r.ID, Kind: "gap-closed",
					Text: fmt.Sprintf("%s is declared %q but content now maps to it: record it as covered", r.ID, r.State)})
			} else {
				state := StatePlanned
				if r.State == StateNone {
					state = StateNoneS
				}
				m.Gaps = append(m.Gaps, Gap{ID: r.ID, Name: attack.Name(r.ID), State: state, Note: r.Note})
			}
		}
	}
	for i := range m.Techniques {
		m.Techniques[i].Partial = partial[m.Techniques[i].ID]
	}
	for _, t := range m.Techniques {
		if _, ok := declared[t.ID]; !ok {
			problems = append(problems, Problem{ID: t.ID, Kind: "undeclared",
				Text: fmt.Sprintf("%s is covered by %s but not declared in the expectation: record it", t.ID, strings.Join(t.Sources, ", "))})
		}
	}
	sort.Slice(problems, func(i, j int) bool { return problems[i].ID < problems[j].ID })
	sort.Slice(m.Gaps, func(i, j int) bool { return m.Gaps[i].ID < m.Gaps[j].ID })
	return problems
}

// Record renders an expectation that matches the matrix: every covered
// technique as a covered row noting its sources (partial rows of the previous
// expectation keep their state and note where the technique is still
// covered), and every gap/none row of the previous expectation that still has
// no content, with its note. prev may be nil.
func Record(m *Matrix, prev *Expect) []byte {
	prevRows := map[string]Row{}
	if prev != nil {
		for _, r := range prev.Rows {
			prevRows[r.ID] = r
		}
	}
	var b bytes.Buffer
	b.WriteString("# ATT&CK coverage expectation for the shipped detection content.\n")
	b.WriteString("# Re-record with: cau coverage --expect <this file> --record\n")
	b.WriteString("# States: covered | partial (covered, acknowledged incomplete) |\n")
	b.WriteString("#         gap (planned, no content yet) | none (owned by sensor/console).\n")
	b.WriteString("# A covered/partial row that loses its content fails the gate (regression);\n")
	b.WriteString("# a gap/none row that gains content fails it too (record the change on purpose).\n")
	b.WriteString("#\n# technique   state     note\n")
	rows := make([]Row, 0, len(m.Techniques))
	for _, t := range m.Techniques {
		// A partial row stays partial and keeps its note; recording never
		// silently promotes acknowledged-incomplete coverage to full.
		if p, ok := prevRows[t.ID]; ok && p.State == StatePartial {
			rows = append(rows, Row{ID: t.ID, State: StatePartial, Note: p.Note})
			continue
		}
		note := strings.Join(t.Sources, ", ")
		if n := attack.Name(t.ID); n != "" {
			note = n + " (" + note + ")"
		}
		rows = append(rows, Row{ID: t.ID, State: StateCovered, Note: note})
	}
	for _, r := range prev.rowsIf(func(r Row) bool {
		return (r.State == StateGap || r.State == StateNone) && !m.Covered(r.ID)
	}) {
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for _, r := range rows {
		fmt.Fprintf(&b, "%-11s %-9s %s\n", r.ID, r.State, r.Note)
	}
	return b.Bytes()
}

// rowsIf returns the rows matching pred. A nil Expect yields nothing, so
// Record works with no previous expectation.
func (e *Expect) rowsIf(pred func(Row) bool) []Row {
	if e == nil {
		return nil
	}
	var out []Row
	for _, r := range e.Rows {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}
