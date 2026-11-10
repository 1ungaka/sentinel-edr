package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/s-b-repo/cau/internal/coverage"
	"github.com/s-b-repo/cau/internal/frameworks"
	"github.com/s-b-repo/cau/scanner"
)

// maxListItems bounds every list a tool returns so a scan of a large tree or a
// long rule set cannot blow out the agent's context. Truncation is always
// reported (a "truncated" / "omitted" field), never silent.
const maxListItems = 50

// ── tool result envelope ─────────────────────────────────────────────────────

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// jsonResult marshals payload to indented JSON and wraps it as a successful
// tool result.
func jsonResult(payload interface{}) (interface{}, *rpcError) {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, errf(codeInternalError, "marshal result: %v", err)
	}
	return toolResult{Content: []toolContent{{Type: "text", Text: string(b)}}}, nil
}

// toolErr wraps a message as an MCP tool error (isError:true) rather than a
// protocol error, which is how MCP surfaces tool failures to the agent.
func toolErr(format string, a ...interface{}) (interface{}, *rpcError) {
	return toolResult{
		Content: []toolContent{{Type: "text", Text: fmt.Sprintf(format, a...)}},
		IsError: true,
	}, nil
}

// ── tool descriptors ─────────────────────────────────────────────────────────

type toolDesc struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func obj(schema string) json.RawMessage { return json.RawMessage(schema) }

// tools is the registry, in list order.
func (s *Server) toolDescs() []toolDesc {
	return []toolDesc{
		{
			Name:        "scan_file",
			Description: "Scan one file with every configured detector and return a bounded verdict summary (verdict, per-detector scores, top findings). The path must be inside a configured scan root.",
			InputSchema: obj(`{"type":"object","properties":{"path":{"type":"string","description":"path to the file, inside a scan root"}},"required":["path"]}`),
		},
		{
			Name:        "scan_dir",
			Description: "Scan a directory tree and return aggregate counts plus a bounded list of non-clean files. Refuses trees larger than the sandbox file cap.",
			InputSchema: obj(`{"type":"object","properties":{"path":{"type":"string","description":"directory path, inside a scan root"}},"required":["path"]}`),
		},
		{
			Name:        "scan_hash",
			Description: "Look up a file hash (MD5/SHA1/SHA256) in the signature database. No file access.",
			InputSchema: obj(`{"type":"object","properties":{"hash":{"type":"string"},"type":{"type":"string","enum":["MD5","SHA1","SHA256"],"description":"optional; inferred from length when omitted"}},"required":["hash"]}`),
		},
		{
			Name:        "explain_verdict",
			Description: "Scan a file and explain the verdict: which detectors fired, their score against their threshold, matched YARA rules with meta, top heuristic categories, and the fusion lattice's corroborating techniques.",
			InputSchema: obj(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`),
		},
		{
			Name:        "yara_test_rule",
			Description: "Compile a YARA rule from source and report compile diagnostics. Optionally scan given sandboxed paths and report which match. Does not promote the rule into the shipped ruleset.",
			InputSchema: obj(`{"type":"object","properties":{"rule":{"type":"string","description":"YARA rule source"},"paths":{"type":"array","items":{"type":"string"},"description":"optional files to test the rule against, inside a scan root"}},"required":["rule"]}`),
		},
		{
			Name:        "generate_yara_rule",
			Description: "Draft a well-formed YARA rule skeleton from string literals and metadata, satisfying the linter's required-meta and string-quality checks. A detection-authoring aid; the author still reviews and tests it.",
			InputSchema: obj(`{"type":"object","properties":{"name":{"type":"string","description":"rule identifier"},"strings":{"type":"array","items":{"type":"string"},"description":"ASCII string literals to match"},"description":{"type":"string","description":"what the rule detects and how to triage a hit; the draft carries a placeholder and a warning without it"},"technique":{"type":"string","description":"ATT&CK technique id, e.g. T1059.001"},"threat_name":{"type":"string","description":"the rule family; the evaluation harness groups per-family recall by it"},"condition":{"type":"string","description":"optional; defaults to 'all of them'"}},"required":["name","strings"]}`),
		},
		{
			Name:        "list_signatures",
			Description: "List hash signatures (bounded) with per-type counts. No file access.",
			InputSchema: obj(`{"type":"object","properties":{"type":{"type":"string","enum":["MD5","SHA1","SHA256"]},"limit":{"type":"integer"}}}`),
		},
		{
			Name:        "add_signature",
			Description: "Add a hash signature to the live database and persist it to the signature file. Validates hash type and length. Modifies local detection content only.",
			InputSchema: obj(`{"type":"object","properties":{"hash":{"type":"string"},"type":{"type":"string","enum":["MD5","SHA1","SHA256"]},"threat_name":{"type":"string"}},"required":["hash","threat_name"]}`),
		},
		{
			Name:        "mitre_coverage",
			Description: "Report ATT&CK coverage derived from the shipped content: covered technique count, per-source summary, and declared gaps. Gaps are published, never padded. With frameworks=true, also the Unified Kill Chain sequencing view (every UKC phase, with the covered techniques that land in it; empty phases are listed as gaps).",
			InputSchema: obj(`{"type":"object","properties":{"technique":{"type":"string","description":"optional; report only this technique id"},"frameworks":{"type":"boolean","description":"optional; add the Unified Kill Chain phase view (cau coverage --frameworks)"}}}`),
		},
		{
			Name:        "honesty_index",
			Description: "Build the honesty index (cau honesty): what the shipped content covers against its committed expectation, what a recorded evaluation report measured (with the synthetic-corpus caveat), and whether the content matches its integrity baseline. Each section carries a state (measured, not-measured, mismatch, no-baseline, tampered, error) and its caveats; there is no overall score. Reads only operator-configured paths (--expect, --eval, --manifest), never a client path. The per-detector table and other lists are capped; the cut is reported.",
			InputSchema: obj(`{"type":"object","properties":{}}`),
		},
		{
			Name:        "eval_report",
			Description: "Summarise an evaluation report written by 'cau eval run --out' at a sandboxed path: totals, precision/recall/FPR, per-detector rows, corpus name and class (synthetic smoke corpus or unclassified), error/skip counts and whether the headline totals follow from the sample records. The per-sample list is omitted unless include_samples is set, and then capped. Does not re-run the evaluation.",
			InputSchema: obj(`{"type":"object","properties":{"path":{"type":"string","description":"report JSON, inside a scan root"},"include_samples":{"type":"boolean","description":"optional; include a capped list of per-sample rows"},"limit":{"type":"integer","description":"optional; max samples and detector rows to list (capped server-side)"}},"required":["path"]}`),
		},
		{
			Name:        "peel_file",
			Description: "Peel the obfuscation chain of one sandboxed file under the peeler's budget: outcome, score against threshold, max depth, primary and deepest chain signatures, findings, archive statistics and budget spend. The decoded bytes of any layer are never returned.",
			InputSchema: obj(`{"type":"object","properties":{"path":{"type":"string","description":"path to the file, inside a scan root"}},"required":["path"]}`),
		},
		{
			Name:        "firmware_image",
			Description: "Inventory a UEFI firmware image (a flash dump or capsule) at a sandboxed path, within the firmware size cap: volumes, module count and the first modules (GUID, type, name, PE presence, nesting depth), checksum validity, LZMA sections opened and failed, findings, and, when the server holds a compiled ruleset, rule matches over the executable module bodies. Module bodies are inventoried, never disassembled or executed.",
			InputSchema: obj(`{"type":"object","properties":{"path":{"type":"string","description":"firmware image, inside a scan root"}},"required":["path"]}`),
		},
		{
			Name:        "boot_scan",
			Description: "Scan boot-chain surfaces given explicitly, each confined to the scan roots: disk images (MBR/GPT structure, boot code, partitions), a mounted EFI System Partition directory (.efi inventory, signature presence), an efivarfs directory (Secure Boot state, boot entries, key databases) and a sysfs root (ACPI/WPBT/option ROM/ESRT inventory). There is no auto-discovery: the live host's /sys/firmware/efi/efivars and /sys are reachable only when the operator put them under --root. Signatures are reported present or absent, never verified. At least one input is required.",
			InputSchema: obj(`{"type":"object","properties":{"disks":{"type":"array","items":{"type":"string"},"description":"disk image files inside a scan root (only their boot sectors and partition tables are read)"},"esp":{"type":"string","description":"a mounted EFI System Partition directory inside a scan root"},"efivars":{"type":"string","description":"an efivarfs directory inside a scan root"},"sysfs":{"type":"string","description":"a sysfs root inside a scan root, for the firmware inventory"},"dbx_reference":{"type":"string","description":"optional; a dbx revocation list file inside a scan root to compare the host dbx against"}}}`),
		},
		{
			Name:        "hardware_identity",
			Description: "Capture the hardware-identity snapshot (cau hwanchor) from a sysfs root inside a scan root: DMI/SMBIOS fields, physical interfaces and their address assignment, TPM presence and PCR 0-7, hardware RNG state, and the anchors that could not be established. Read-only. redact defaults to true: serials, the product UUID and MAC addresses are replaced by digests; pass redact=false only when the identity values themselves are needed. The live host's /sys is reachable only when the operator put it under --root.",
			InputSchema: obj(`{"type":"object","properties":{"sysfs":{"type":"string","description":"a sysfs root inside a scan root"},"redact":{"type":"boolean","description":"optional; default true. false returns raw serials and MAC addresses"}},"required":["sysfs"]}`),
		},
	}
}

func (s *Server) onToolsList() (interface{}, *rpcError) {
	return map[string]interface{}{"tools": s.toolDescs()}, nil
}

// ── dispatch ─────────────────────────────────────────────────────────────────

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) onToolsCall(raw json.RawMessage) (interface{}, *rpcError) {
	var p toolCallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errf(codeInvalidParams, "invalid tools/call params: %v", err)
	}
	switch p.Name {
	case "scan_file":
		return s.toolScanFile(p.Arguments)
	case "scan_dir":
		return s.toolScanDir(p.Arguments)
	case "scan_hash":
		return s.toolScanHash(p.Arguments)
	case "explain_verdict":
		return s.toolExplainVerdict(p.Arguments)
	case "yara_test_rule":
		return s.toolYaraTestRule(p.Arguments)
	case "generate_yara_rule":
		return s.toolGenerateYaraRule(p.Arguments)
	case "list_signatures":
		return s.toolListSignatures(p.Arguments)
	case "add_signature":
		return s.toolAddSignature(p.Arguments)
	case "mitre_coverage":
		return s.toolMitreCoverage(p.Arguments)
	case "honesty_index":
		return s.toolHonestyIndex(p.Arguments)
	case "eval_report":
		return s.toolEvalReport(p.Arguments)
	case "peel_file":
		return s.toolPeelFile(p.Arguments)
	case "firmware_image":
		return s.toolFirmwareImage(p.Arguments)
	case "boot_scan":
		return s.toolBootScan(p.Arguments)
	case "hardware_identity":
		return s.toolHardwareIdentity(p.Arguments)
	default:
		return nil, errf(codeInvalidParams, "unknown tool: %s", p.Name)
	}
}

func unmarshalArgs(raw json.RawMessage, dst interface{}) *rpcError {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return errf(codeInvalidParams, "invalid arguments: %v", err)
	}
	return nil
}

// ── summaries ────────────────────────────────────────────────────────────────

type fileSummary struct {
	Path     string               `json:"path"`
	Size     int64                `json:"size"`
	SHA256   string               `json:"sha256,omitempty"`
	Verdict  string               `json:"verdict"`
	Hash     *hashHit             `json:"hash_match,omitempty"`
	Yara     []string             `json:"yara_rules,omitempty"`
	YaraMore int                  `json:"yara_rules_omitted,omitempty"`
	Scores   map[string]scoreView `json:"detector_scores,omitempty"`
	Warnings []string             `json:"warnings,omitempty"`
	Error    string               `json:"error,omitempty"`
}

type hashHit struct {
	Type       string `json:"type"`
	ThreatName string `json:"threat_name"`
}

type scoreView struct {
	Score     int  `json:"score"`
	Threshold int  `json:"threshold"`
	Breached  bool `json:"breached"`
}

func (s *Server) summarize(r scanner.ScanResult, h *scanner.HeuristicResult) fileSummary {
	fs := fileSummary{
		Path:    r.FilePath,
		Size:    r.Size,
		SHA256:  r.SHA256,
		Verdict: string(r.Verdict),
	}
	if r.Error != nil {
		fs.Error = r.Error.Error()
	}
	fs.Warnings = r.Warnings
	if r.Detected {
		fs.Hash = &hashHit{Type: r.MatchType, ThreatName: r.ThreatName}
	}
	for i, m := range r.YaraMatches {
		if i >= maxListItems {
			fs.YaraMore = len(r.YaraMatches) - maxListItems
			break
		}
		fs.Yara = append(fs.Yara, m.RuleName)
	}
	fs.Scores = map[string]scoreView{}
	if h != nil && h.Skipped == "" && h.Error == nil {
		fs.Scores["heuristics"] = scoreView{h.Score, effThreshold(h.Threshold, scanner.HeuristicThreshold), h.Score >= effThreshold(h.Threshold, scanner.HeuristicThreshold)}
	}
	if r.Static != nil && r.Static.Skipped == "" {
		th := r.Static.EffectiveThreshold()
		fs.Scores["static"] = scoreView{r.Static.Score, th, r.Static.Score >= th}
	}
	if r.Stego != nil {
		fs.Scores["stego"] = scoreView{r.Stego.Score, r.Stego.Threshold, r.Stego.Score >= r.Stego.Threshold}
	}
	if r.EncChain != nil {
		fs.Scores["encchain"] = scoreView{r.EncChain.Score, r.EncChain.Threshold, r.EncChain.Score >= r.EncChain.Threshold}
	}
	if r.LNK != nil {
		fs.Scores["lnk"] = scoreView{r.LNK.Score, r.LNK.EffectiveThreshold(), r.LNK.Detected()}
	}
	if r.OLE != nil {
		fs.Scores["ole"] = scoreView{r.OLE.Score, r.OLE.EffectiveThreshold(), r.OLE.Detected()}
	}
	if r.PDF != nil {
		fs.Scores["pdf"] = scoreView{r.PDF.Score, r.PDF.EffectiveThreshold(), r.PDF.Detected()}
	}
	if r.ISO != nil {
		fs.Scores["iso"] = scoreView{r.ISO.Score, r.ISO.EffectiveThreshold(), r.ISO.Detected()}
	}
	if r.LinuxPkg != nil {
		fs.Scores["linuxpkg"] = scoreView{r.LinuxPkg.Score, r.LinuxPkg.EffectiveThreshold(), r.LinuxPkg.Detected()}
	}
	if r.Peel != nil {
		fs.Scores["peel"] = scoreView{r.Peel.Score, r.Peel.EffectiveThreshold(), r.Peel.Detected()}
	}
	if len(fs.Scores) == 0 {
		fs.Scores = nil
	}
	return fs
}

func effThreshold(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// ── scan_file ────────────────────────────────────────────────────────────────

func (s *Server) toolScanFile(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Path string `json:"path"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	real, _, err := s.deps.Sandbox.ResolveFile(args.Path)
	if err != nil {
		return toolErr("scan_file: %v", err)
	}
	r, h := s.deps.Engine.ScanFile(real)
	r.FilePath = args.Path // report the path the caller gave, not the resolved realpath
	return jsonResult(s.summarize(r, h))
}

// ── scan_dir ─────────────────────────────────────────────────────────────────

type dirSummary struct {
	Path       string        `json:"path"`
	Files      int           `json:"files_scanned"`
	Malicious  int           `json:"malicious"`
	Suspicious int           `json:"suspicious"`
	Clean      int           `json:"clean"`
	Errors     int           `json:"errors"`
	Flagged    []fileSummary `json:"flagged,omitempty"`
	Omitted    int           `json:"flagged_omitted,omitempty"`
}

func (s *Server) toolScanDir(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Path string `json:"path"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	real, _, err := s.deps.Sandbox.ResolveDir(args.Path)
	if err != nil {
		return toolErr("scan_dir: %v", err)
	}
	results, heurs := s.deps.Engine.ScanDirectory(real, nil)
	byPath := make(map[string]*scanner.HeuristicResult, len(heurs))
	for i := range heurs {
		byPath[heurs[i].FilePath] = &heurs[i]
	}

	sum := dirSummary{Path: args.Path, Files: len(results)}
	for _, r := range results {
		switch r.Verdict {
		case scanner.VerdictMalicious:
			sum.Malicious++
		case scanner.VerdictError:
			sum.Errors++
		default:
			// a clean verdict may still be the SUSPICIOUS tier via fusion/static
			if isSuspicious(r) {
				sum.Suspicious++
			} else {
				sum.Clean++
			}
		}
		if r.Verdict == scanner.VerdictMalicious || isSuspicious(r) || r.Verdict == scanner.VerdictError {
			if len(sum.Flagged) < maxListItems {
				rel := strings.TrimPrefix(r.FilePath, real)
				rel = strings.TrimPrefix(rel, string(os.PathSeparator))
				fsum := s.summarize(r, byPath[r.FilePath])
				fsum.Path = rel
				sum.Flagged = append(sum.Flagged, fsum)
			} else {
				sum.Omitted++
			}
		}
	}
	return jsonResult(sum)
}

// isSuspicious reports whether any sub-threshold detector or the fusion lattice
// placed the result in the SUSPICIOUS tier.
func isSuspicious(r scanner.ScanResult) bool {
	if r.Fusion != nil && r.Fusion.Corroborated {
		return true
	}
	if r.Static != nil && r.Static.Detected() {
		return true
	}
	if r.Stego != nil && r.Stego.Score >= r.Stego.Threshold && r.Stego.Threshold > 0 {
		return true
	}
	if r.EncChain != nil && r.EncChain.Score >= r.EncChain.Threshold && r.EncChain.Threshold > 0 {
		return true
	}
	if r.LNK != nil && r.LNK.Detected() {
		return true
	}
	if r.OLE != nil && r.OLE.Detected() {
		return true
	}
	if r.PDF != nil && r.PDF.Detected() {
		return true
	}
	if r.ISO != nil && r.ISO.Detected() {
		return true
	}
	if r.LinuxPkg != nil && r.LinuxPkg.Detected() {
		return true
	}
	if r.Peel != nil && r.Peel.Detected() {
		return true
	}
	return false
}

// ── scan_hash ────────────────────────────────────────────────────────────────

func (s *Server) toolScanHash(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Hash string `json:"hash"`
		Type string `json:"type"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	if s.deps.SigDB == nil {
		return toolErr("scan_hash: no signature database loaded")
	}
	ht := args.Type
	if ht == "" {
		if t, ok := scanner.HashTypeFor(args.Hash); ok {
			ht = t
		} else {
			return toolErr("scan_hash: cannot infer hash type from length; pass type")
		}
	}
	normType, normHash, err := scanner.ValidateHash(ht, args.Hash)
	if err != nil {
		return toolErr("scan_hash: %v", err)
	}
	sig, found := s.deps.SigDB.Lookup(normHash)
	out := map[string]interface{}{
		"hash":    normHash,
		"type":    normType,
		"matched": found,
	}
	if found {
		out["threat_name"] = sig.ThreatName
	}
	return jsonResult(out)
}

// ── explain_verdict ──────────────────────────────────────────────────────────

func (s *Server) toolExplainVerdict(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Path string `json:"path"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	real, _, err := s.deps.Sandbox.ResolveFile(args.Path)
	if err != nil {
		return toolErr("explain_verdict: %v", err)
	}
	r, h := s.deps.Engine.ScanFile(real)
	r.FilePath = args.Path

	exp := map[string]interface{}{
		"path":    args.Path,
		"verdict": string(r.Verdict),
		"summary": s.summarize(r, h),
	}
	// YARA rules with the meta that drove the verdict.
	var rules []map[string]interface{}
	for i, m := range r.YaraMatches {
		if i >= maxListItems {
			break
		}
		rm := map[string]interface{}{"rule": m.RuleName, "namespace": m.Namespace}
		if len(m.Tags) > 0 {
			rm["tags"] = m.Tags
		}
		if len(m.Metas) > 0 {
			meta := map[string]string{}
			for _, md := range m.Metas {
				meta[md.Identifier] = fmt.Sprint(md.Value)
			}
			rm["meta"] = meta
		}
		rules = append(rules, rm)
	}
	if len(rules) > 0 {
		exp["yara"] = rules
	}
	// Top heuristic categories (by applied contribution).
	if h != nil && len(h.Categories) > 0 {
		cats := append([]scanner.CategoryScore(nil), h.Categories...)
		sort.Slice(cats, func(i, j int) bool { return cats[i].Applied > cats[j].Applied })
		var top []map[string]interface{}
		for i, c := range cats {
			if i >= 10 || c.Applied == 0 {
				break
			}
			entry := map[string]interface{}{"category": c.Category, "score": c.Applied}
			if c.Technique != "" {
				entry["technique"] = c.Technique
			}
			top = append(top, entry)
		}
		if len(top) > 0 {
			exp["heuristic_categories"] = top
		}
	}
	// Fusion corroboration.
	if r.Fusion != nil {
		fz := map[string]interface{}{
			"corroborated": r.Fusion.Corroborated,
			"tier":         r.Fusion.Tier,
		}
		if len(r.Fusion.Techniques) > 0 {
			fz["techniques"] = r.Fusion.Techniques
		}
		exp["fusion"] = fz
	}
	return jsonResult(exp)
}

// ── mitre_coverage ───────────────────────────────────────────────────────────

func (s *Server) buildMatrix() *coverage.Matrix {
	in := coverage.Inputs{
		Tool:       s.deps.Info.Name,
		Version:    s.deps.Info.Version,
		HashCount:  -1,
		FuzzyCount: -1,
	}
	if s.deps.Yara != nil {
		in.Rules = s.deps.Yara.RuleInfos()
		in.YaraLoaded = true
	}
	if s.deps.SigDB != nil {
		in.HashCount = s.deps.SigDB.Count()
	}
	if s.deps.FuzzyDB != nil {
		in.FuzzyCount = s.deps.FuzzyDB.Count()
	}
	return coverage.Build(in)
}

func (s *Server) toolMitreCoverage(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Technique  string `json:"technique"`
		Frameworks bool   `json:"frameworks"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	m := s.buildMatrix()
	if args.Technique != "" {
		for _, t := range m.Techniques {
			if strings.EqualFold(t.ID, args.Technique) {
				out := map[string]interface{}{"covered": true, "technique": t}
				if args.Frameworks {
					out["ukc"] = frameworks.ForTechnique(t.ID)
				}
				return jsonResult(out)
			}
		}
		return jsonResult(map[string]interface{}{"technique": args.Technique, "covered": false})
	}
	out := map[string]interface{}{
		"tool":           m.Tool,
		"version":        m.Version,
		"covered_count":  len(m.Techniques),
		"sources":        m.Sources,
		"covered":        techniqueIDs(m),
		"unmapped_count": len(m.Unmapped),
	}
	if len(m.Gaps) > 0 {
		out["gaps"] = m.Gaps
	}
	if args.Frameworks {
		out["ukc"] = ukcView(techniqueIDs(m))
	}
	return jsonResult(out)
}

// ukcPhase is one row of the Unified Kill Chain view: every phase is listed,
// so an empty one is a visible gap rather than a missing row.
type ukcPhase struct {
	Phase      string   `json:"phase"`
	Stage      string   `json:"stage"`
	Techniques []string `json:"techniques"`
}

// ukcView is the JSON form of `cau coverage --frameworks`: the covered
// techniques mapped phase-wise onto the Unified Kill Chain.
func ukcView(ids []string) map[string]interface{} {
	seq := frameworks.Sequence(ids)
	covered := make(map[string]frameworks.PhaseCoverage, len(seq))
	for _, pc := range seq {
		covered[pc.Phase] = pc
	}
	all := frameworks.Phases()
	phases := make([]ukcPhase, 0, len(all))
	for _, p := range all {
		row := ukcPhase{Phase: p, Stage: frameworks.StageForPhase(p), Techniques: []string{}}
		if pc, ok := covered[p]; ok {
			row.Techniques = pc.Techniques
		}
		phases = append(phases, row)
	}
	return map[string]interface{}{
		"framework":           "Unified Kill Chain",
		"phases":              phases,
		"phases_with_content": len(seq),
		"phases_total":        len(all),
		"note":                "ATT&CK techniques mapped phase-wise by tactic; an empty phase is a gap in the shipped content, not an absence of the phase",
	}
}

func techniqueIDs(m *coverage.Matrix) []string {
	out := make([]string, 0, len(m.Techniques))
	for _, t := range m.Techniques {
		out = append(out, t.ID)
	}
	return out
}
