package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Prompts are reusable instruction templates an MCP client can surface to its
// user. They orchestrate the detection tools; they never ask the model to
// produce evasion or payload content. (The Phase 3 sketch's evasion_assessment
// prompt is intentionally omitted: it belongs to the evasion suite, which this
// repo's scope note keeps out of the engine.)

type promptArg struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type promptDesc struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Arguments   []promptArg `json:"arguments,omitempty"`
}

func (s *Server) promptDescs() []promptDesc {
	return []promptDesc{
		{
			Name:        "triage_sample",
			Description: "Triage a file: scan it, explain the verdict, and summarise the evidence for an analyst.",
			Arguments: []promptArg{
				{Name: "path", Description: "file to triage, inside a scan root", Required: true},
			},
		},
		{
			Name:        "rule_review",
			Description: "Review a proposed YARA rule for false-positive risk and detection quality before it is promoted.",
			Arguments: []promptArg{
				{Name: "rule", Description: "the YARA rule source to review", Required: true},
			},
		},
		{
			Name:        "boot_chain_review",
			Description: "Triage a boot chain: run boot_scan over explicitly given, sandboxed surfaces (disk images, an ESP, efivars, sysfs) and write an analyst summary of the firmware-to-loader chain and its findings.",
			Arguments: []promptArg{
				{Name: "disks", Description: "comma-separated disk image paths inside a scan root", Required: false},
				{Name: "esp", Description: "a mounted EFI System Partition directory inside a scan root", Required: false},
				{Name: "efivars", Description: "an efivarfs directory inside a scan root", Required: false},
				{Name: "sysfs", Description: "a sysfs root inside a scan root", Required: false},
			},
		},
	}
}

func (s *Server) onPromptsList() (interface{}, *rpcError) {
	return map[string]interface{}{"prompts": s.promptDescs()}, nil
}

type promptMessage struct {
	Role    string         `json:"role"`
	Content promptTextPart `json:"content"`
}

type promptTextPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func userMsg(text string) promptMessage {
	return promptMessage{Role: "user", Content: promptTextPart{Type: "text", Text: text}}
}

func (s *Server) onPromptsGet(raw json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errf(codeInvalidParams, "invalid prompts/get params: %v", err)
	}
	switch p.Name {
	case "triage_sample":
		path := p.Arguments["path"]
		target := "the file"
		if path != "" {
			target = fmt.Sprintf("%q", path)
		}
		text := strings.Join([]string{
			fmt.Sprintf("Triage %s using the CAU tools.", target),
			"",
			"1. Call scan_file to get the verdict and per-detector scores.",
			"2. Call explain_verdict to see which detectors fired, the matched YARA rules and their meta, the top heuristic categories, and any fusion corroboration.",
			"3. For each ATT&CK technique the evidence names, optionally call mitre_coverage to confirm it is covered content.",
			"",
			"Then write a short analyst summary: the verdict, the single strongest piece of evidence, the techniques implicated, and a recommended next step. Do not speculate beyond what the tools reported.",
		}, "\n")
		return map[string]interface{}{
			"description": "Triage a sample with the CAU detection tools.",
			"messages":    []promptMessage{userMsg(text)},
		}, nil

	case "rule_review":
		rule := p.Arguments["rule"]
		text := strings.Join([]string{
			"Review this proposed YARA rule for false-positive risk and detection quality before it is promoted into the shipped ruleset.",
			"",
			"Assess:",
			"- String specificity: are any strings short, generic, or common in benign software? Short/narrow strings are the main driver of false positives.",
			"- Condition tightness: would 'any of them' fire too readily? Is an anchor (file magic, section, offset) warranted?",
			"- Required meta: description and threat_level (1-5) are mandatory; author, family and a mitre_attack technique id should be present.",
			"- Coverage: what ATT&CK technique does it add, and is that technique already covered?",
			"",
			"Use yara_test_rule to confirm it compiles and to try it against any sandboxed sample paths the user provides. Note that true FP/FN rates require the labelled evaluation corpus (cau eval), not a single file.",
			"",
			"Rule under review:",
			"```",
			rule,
			"```",
		}, "\n")
		return map[string]interface{}{
			"description": "Assess a proposed YARA rule's false-positive risk and quality.",
			"messages":    []promptMessage{userMsg(text)},
		}, nil

	case "boot_chain_review":
		var inputs []string
		if v := strings.TrimSpace(p.Arguments["disks"]); v != "" {
			var quoted []string
			for _, d := range strings.Split(v, ",") {
				if d = strings.TrimSpace(d); d != "" {
					quoted = append(quoted, fmt.Sprintf("%q", d))
				}
			}
			if len(quoted) > 0 {
				inputs = append(inputs, "disks: ["+strings.Join(quoted, ", ")+"]")
			}
		}
		for _, name := range []string{"esp", "efivars", "sysfs"} {
			if v := strings.TrimSpace(p.Arguments[name]); v != "" {
				inputs = append(inputs, fmt.Sprintf("%s: %q", name, v))
			}
		}
		given := "the boot surfaces the user names (disk images, an EFI System Partition directory, an efivarfs directory, a sysfs root), each inside a scan root"
		if len(inputs) > 0 {
			given = strings.Join(inputs, "; ")
		}
		text := strings.Join([]string{
			"Review a boot chain using the CAU tools. Inputs: " + given + ".",
			"",
			"1. Call boot_scan with exactly those inputs. There is no auto-discovery: a path outside a scan root is refused, and the live host's firmware variables or sysfs are only reachable when the operator placed them under --root.",
			"2. If a sysfs root was given, call hardware_identity with it (leave redact at its default) to pair the boot posture with the platform's DMI, TPM and hardware-RNG state.",
			"3. If a firmware image file was named, call firmware_image on it for the module inventory and rule matches.",
			"",
			"Then write a short analyst summary, in this order:",
			"- Posture: Secure Boot and Setup Mode as reported (unknown is a state; never read it as off), whether a platform key is enrolled, and the db/dbx/MOK sizes.",
			"- Chain: the boot order and entries, the loader each entry points at, and whether that file exists on the ESP, is a PE image with an EFI subsystem, and carries a signature. Signatures are reported present or absent, never verified: the engine holds no trust store, so do not claim a loader is trusted.",
			"- Disks: partition scheme and table integrity, boot code presence and recognised loader family, and any structural anomaly.",
			"- Findings: each scored finding, strongest first, with its evidence; then the informational ones.",
			"- Not inspected: every note the scan returned about what it could not read, and whether any list was truncated.",
			"- Next step: one recommended action (for example compare the boot-entry target digest against a recorded baseline with cau bootscan --check, or verify the loader signature with an external tool).",
			"Do not speculate beyond what the tools reported.",
		}, "\n")
		return map[string]interface{}{
			"description": "Triage a boot chain with the CAU boot-surface tools.",
			"messages":    []promptMessage{userMsg(text)},
		}, nil

	default:
		return nil, errf(codeInvalidParams, "unknown prompt: %s", p.Name)
	}
}
