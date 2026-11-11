package coverage

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/attack"
)

// SARIF coverage rendering. Each ATT&CK technique the matrix knows about —
// detected, partial, planned or none — becomes one SARIF rule and one
// result, so a code-scanning dashboard shows the coverage map and treats the
// gaps as findings. The honesty rule of the text and JSON renderings holds:
// techniques with no content are reported, never padded, and a planned gap
// is a warning rather than a silent absence.
const (
	coverageSARIFSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	coverageSARIFVersion = "2.1.0"
)

type covSARIFLog struct {
	Schema  string        `json:"$schema"`
	Version string        `json:"version"`
	Runs    []covSARIFRun `json:"runs"`
}

type covSARIFRun struct {
	Tool       covSARIFTool           `json:"tool"`
	Results    []covSARIFResult       `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type covSARIFTool struct {
	Driver covSARIFDriver `json:"driver"`
}

type covSARIFDriver struct {
	Name           string         `json:"name"`
	Version        string         `json:"version,omitempty"`
	InformationURI string         `json:"informationUri,omitempty"`
	Rules          []covSARIFRule `json:"rules"`
}

type covSARIFRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription covSARIFText           `json:"shortDescription"`
	FullDescription  covSARIFText           `json:"fullDescription,omitempty"`
	DefaultConfig    covSARIFRuleConfig     `json:"defaultConfiguration"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type covSARIFRuleConfig struct {
	Level string `json:"level"`
}

type covSARIFText struct {
	Text string `json:"text"`
}

type covSARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Kind       string                 `json:"kind"`
	Message    covSARIFText           `json:"message"`
	Locations  []covSARIFLocation     `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// A coverage result is about the detection program, not a file. SARIF allows
// a result to carry a logical location instead of a physical one; the
// technique id is that location.
type covSARIFLocation struct {
	LogicalLocations []covSARIFLogical `json:"logicalLocations"`
}

type covSARIFLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// stateLevel maps a coverage state to a SARIF level and result kind. A
// planned gap is the one state worth a warning; everything else is
// informational, so the dashboard shows the full map without crying wolf.
func stateLevel(state string) (level, kind string) {
	switch state {
	case StatePlanned:
		return "warning", "open"
	case StateNoneS:
		return "note", "informational"
	case StatePartialS:
		return "note", "informational"
	default: // detected
		return "note", "pass"
	}
}

func attackHelpURI(id string) string {
	parent, sub, found := strings.Cut(id, ".")
	if found {
		return "https://attack.mitre.org/techniques/" + parent + "/" + sub + "/"
	}
	return "https://attack.mitre.org/techniques/" + id + "/"
}

// WriteSARIF renders the matrix as a SARIF 2.1.0 log.
func WriteSARIF(w io.Writer, m *Matrix, indent bool) error {
	type techState struct {
		id      string
		state   string
		name    string
		tactics []string
		sources []string
		entries []string
		note    string
	}
	var all []techState
	for _, t := range m.Techniques {
		labels := make([]string, 0, len(t.Entries))
		for _, e := range t.Entries {
			labels = append(labels, e.Label)
		}
		all = append(all, techState{t.ID, t.State(), t.Name, t.Tactics, t.Sources, labels, ""})
	}
	for _, g := range m.Gaps {
		all = append(all, techState{g.ID, g.State, g.Name, attack.Tactics(g.ID), nil, nil, g.Note})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].id < all[j].id })

	counts := map[string]int{}
	for _, ts := range all {
		counts[ts.state]++
	}

	log := covSARIFLog{
		Schema:  coverageSARIFSchema,
		Version: coverageSARIFVersion,
		Runs: []covSARIFRun{{
			Tool: covSARIFTool{Driver: covSARIFDriver{
				Name: m.Tool + " coverage", Version: m.Version,
				InformationURI: "https://attack.mitre.org/",
			}},
			Properties: map[string]interface{}{
				"attack_version": attack.Version,
				"detected":       counts[StateDetected],
				"partial":        counts[StatePartialS],
				"planned":        counts[StatePlanned],
				"none":           counts[StateNoneS],
			},
		}},
	}
	run := &log.Runs[0]
	index := map[string]int{}
	for _, ts := range all {
		level, kind := stateLevel(ts.state)
		name := ts.name
		if name == "" {
			name = ts.id
		}
		ruleID := "coverage/" + ts.id
		if _, ok := index[ruleID]; !ok {
			index[ruleID] = len(run.Tool.Driver.Rules)
			props := map[string]interface{}{"technique": ts.id, "state": ts.state}
			if len(ts.tactics) > 0 {
				props["tactics"] = ts.tactics
			}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, covSARIFRule{
				ID: ruleID, Name: "Coverage_" + strings.ReplaceAll(ts.id, ".", "_"),
				ShortDescription: covSARIFText{Text: fmt.Sprintf("ATT&CK %s: %s", ts.id, name)},
				DefaultConfig:    covSARIFRuleConfig{Level: level},
				HelpURI:          attackHelpURI(ts.id),
				Properties:       props,
			})
		}
		msg := coverageMessage(ts.id, name, ts.state, ts.sources, ts.entries, ts.note)
		resultProps := map[string]interface{}{"state": ts.state}
		if len(ts.sources) > 0 {
			resultProps["sources"] = ts.sources
		}
		if len(ts.entries) > 0 {
			resultProps["content"] = ts.entries
		}
		run.Results = append(run.Results, covSARIFResult{
			RuleID: ruleID, RuleIndex: index[ruleID], Level: level, Kind: kind,
			Message: covSARIFText{Text: msg},
			Locations: []covSARIFLocation{{LogicalLocations: []covSARIFLogical{{
				Name: ts.id, FullyQualifiedName: "attack/" + ts.id, Kind: "namespace",
			}}}},
			Properties: resultProps,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(log)
}

func coverageMessage(id, name, state string, sources, entries []string, note string) string {
	switch state {
	case StateDetected:
		return fmt.Sprintf("%s (%s) is detected by %s: %s.", id, name, strings.Join(sources, ", "), strings.Join(entries, "; "))
	case StatePartialS:
		return fmt.Sprintf("%s (%s) is partially covered by %s (acknowledged incomplete): %s.", id, name, strings.Join(sources, ", "), strings.Join(entries, "; "))
	case StatePlanned:
		msg := fmt.Sprintf("%s (%s) has no detection content yet; it is on the roadmap.", id, name)
		if note != "" {
			msg += " " + note
		}
		return msg
	default: // none
		msg := fmt.Sprintf("%s (%s) is not covered by the engine; it is owned by the sensor or console.", id, name)
		if note != "" {
			msg += " " + note
		}
		return msg
	}
}
