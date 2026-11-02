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

	default:
		return nil, errf(codeInvalidParams, "unknown prompt: %s", p.Name)
	}
}
