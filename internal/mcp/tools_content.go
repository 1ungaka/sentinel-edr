package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/cau-edr/cau/scanner"
)

// ── yara_test_rule ───────────────────────────────────────────────────────────

func (s *Server) toolYaraTestRule(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Rule  string   `json:"rule"`
		Paths []string `json:"paths"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	if strings.TrimSpace(args.Rule) == "" {
		return toolErr("yara_test_rule: empty rule")
	}

	var warnings []string
	ys, _, err := scanner.LoadYaraRuleFiles(
		[]scanner.RuleSource{{Text: args.Rule, Name: "inline"}},
		scanner.WithWarnFunc(func(f string, a ...interface{}) {
			warnings = append(warnings, fmt.Sprintf(f, a...))
		}),
	)
	if err != nil {
		return jsonResult(map[string]interface{}{
			"compiled": false,
			"error":    err.Error(),
			"warnings": warnings,
		})
	}
	defer ys.Close()

	out := map[string]interface{}{
		"compiled": true,
		"rules":    ys.RuleCount(),
		"warnings": warnings,
	}

	if len(args.Paths) > 0 {
		var tested []map[string]interface{}
		for i, p := range args.Paths {
			if i >= maxListItems {
				out["paths_omitted"] = len(args.Paths) - maxListItems
				break
			}
			entry := map[string]interface{}{"path": p}
			real, _, rerr := s.deps.Sandbox.ResolveFile(p)
			if rerr != nil {
				entry["error"] = rerr.Error()
				tested = append(tested, entry)
				continue
			}
			data, derr := os.ReadFile(real)
			if derr != nil {
				entry["error"] = derr.Error()
				tested = append(tested, entry)
				continue
			}
			matches, merr := ys.ScanMemYara(data)
			if merr != nil {
				entry["error"] = merr.Error()
				tested = append(tested, entry)
				continue
			}
			var names []string
			for _, m := range matches {
				names = append(names, m.RuleName)
			}
			entry["matched"] = len(names) > 0
			if len(names) > 0 {
				entry["rules"] = names
			}
			tested = append(tested, entry)
		}
		out["tested"] = tested
		out["note"] = "match/no-match on the given files only; FP/FN rates require the labelled evaluation corpus (cau eval)"
	}
	return jsonResult(out)
}

// ── generate_yara_rule ───────────────────────────────────────────────────────

var yaraIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var attackID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func (s *Server) toolGenerateYaraRule(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Name        string   `json:"name"`
		Strings     []string `json:"strings"`
		Description string   `json:"description"`
		Technique   string   `json:"technique"`
		ThreatName  string   `json:"threat_name"`
		Condition   string   `json:"condition"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	if !yaraIdent.MatchString(args.Name) {
		return toolErr("generate_yara_rule: %q is not a valid YARA identifier", args.Name)
	}
	if len(args.Strings) == 0 {
		return toolErr("generate_yara_rule: at least one string is required")
	}
	if args.Technique != "" && !attackID.MatchString(args.Technique) {
		return toolErr("generate_yara_rule: %q is not an ATT&CK technique id (T1234 or T1234.001)", args.Technique)
	}

	desc := strings.TrimSpace(args.Description)
	if desc == "" {
		desc = "TODO: describe what this rule detects and how to triage a hit"
	}
	family := strings.TrimSpace(args.ThreatName)
	if family == "" {
		family = "TODO-family"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "rule %s\n{\n", args.Name)
	b.WriteString("    meta:\n")
	fmt.Fprintf(&b, "        description = %q\n", desc)
	b.WriteString("        author = \"cau-mcp generate_yara_rule\"\n")
	b.WriteString("        threat_level = 3\n")
	fmt.Fprintf(&b, "        family = %q\n", family)
	if args.Technique != "" {
		fmt.Fprintf(&b, "        mitre_attack = %q\n", args.Technique)
	}
	b.WriteString("    strings:\n")
	var warnings []string
	for i, str := range args.Strings {
		if len(str) < 4 {
			warnings = append(warnings, fmt.Sprintf("string %d (%q) is short; short strings drive false positives", i, str))
		}
		fmt.Fprintf(&b, "        $s%d = %q ascii wide\n", i, str)
	}
	cond := strings.TrimSpace(args.Condition)
	if cond == "" {
		cond = "all of them"
	}
	fmt.Fprintf(&b, "    condition:\n        %s\n}\n", cond)

	src := b.String()

	// Validate the draft compiles before returning it.
	ys, _, err := scanner.LoadYaraRuleFiles(
		[]scanner.RuleSource{{Text: src, Name: "generated"}},
		scanner.WithWarnFunc(func(f string, a ...interface{}) {
			warnings = append(warnings, fmt.Sprintf(f, a...))
		}),
	)
	compiled := err == nil
	if ys != nil {
		ys.Close()
	}
	out := map[string]interface{}{
		"rule":     src,
		"compiled": compiled,
		"warnings": warnings,
	}
	if err != nil {
		out["error"] = err.Error()
	}
	if args.Technique == "" {
		out["note"] = "no technique given: add a mitre_attack meta or the rule lands as unmapped in the coverage matrix"
	}
	return jsonResult(out)
}

// ── list_signatures ──────────────────────────────────────────────────────────

func (s *Server) toolListSignatures(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Type  string `json:"type"`
		Limit int    `json:"limit"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	if s.deps.SigDB == nil {
		return toolErr("list_signatures: no signature database loaded")
	}
	limit := args.Limit
	if limit <= 0 || limit > maxListItems {
		limit = maxListItems
	}
	var wantType string
	if args.Type != "" {
		t, err := scanner.NormalizeHashType(args.Type)
		if err != nil {
			return toolErr("list_signatures: %v", err)
		}
		wantType = t
	}

	all := s.deps.SigDB.Signatures()
	sort.Slice(all, func(i, j int) bool { return all[i].Hash < all[j].Hash })
	var listed []map[string]string
	matched := 0
	for _, sig := range all {
		if wantType != "" && sig.HashType != wantType {
			continue
		}
		matched++
		if len(listed) < limit {
			listed = append(listed, map[string]string{
				"type":        sig.HashType,
				"hash":        sig.Hash,
				"threat_name": sig.ThreatName,
			})
		}
	}
	out := map[string]interface{}{
		"total":         s.deps.SigDB.Count(),
		"count_by_type": s.deps.SigDB.CountByType(),
		"listed":        listed,
	}
	if matched > len(listed) {
		out["omitted"] = matched - len(listed)
	}
	return jsonResult(out)
}

// ── add_signature ────────────────────────────────────────────────────────────

func (s *Server) toolAddSignature(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Hash       string `json:"hash"`
		Type       string `json:"type"`
		ThreatName string `json:"threat_name"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	if s.deps.SigDB == nil || s.deps.SigDBPath == "" {
		return toolErr("add_signature: no writable signature database is configured")
	}
	ht := args.Type
	if ht == "" {
		if t, ok := scanner.HashTypeFor(args.Hash); ok {
			ht = t
		} else {
			return toolErr("add_signature: cannot infer hash type from length; pass type")
		}
	}
	normType, normHash, err := scanner.ValidateHash(ht, args.Hash)
	if err != nil {
		return toolErr("add_signature: %v", err)
	}
	// Persist to the file (fail-closed on duplicates/conflicts there first).
	if err := scanner.AddSignature(s.deps.SigDBPath, normType, normHash, args.ThreatName); err != nil {
		return toolErr("add_signature: %v", err)
	}
	// Reflect it in the live database so the running server detects it too.
	if err := s.deps.SigDB.Add(scanner.Signature{HashType: normType, Hash: normHash, ThreatName: args.ThreatName}); err != nil {
		// The file write already succeeded; report the live-add problem but
		// do not pretend the signature was not persisted.
		return jsonResult(map[string]interface{}{
			"persisted":   true,
			"live_update": false,
			"warning":     err.Error(),
			"type":        normType,
			"hash":        normHash,
		})
	}
	return jsonResult(map[string]interface{}{
		"persisted":   true,
		"live_update": true,
		"type":        normType,
		"hash":        normHash,
		"threat_name": strings.TrimSpace(args.ThreatName),
		"total":       s.deps.SigDB.Count(),
	})
}
