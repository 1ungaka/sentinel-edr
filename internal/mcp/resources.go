package mcp

import (
	"encoding/json"
	"strings"
)

// Resources expose read-only engine state by URI. They are deliberately a
// small set: the signature database summary, the ATT&CK coverage matrix, and
// per-rule metadata. cau://corpus/{sample}/report and cau://model/{name}/card
// from the Phase 3 sketch wait on the evaluation-corpus addressing and the ML
// ladder respectively; they are not advertised until they exist.

type resourceDesc struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MIMEType    string `json:"mimeType"`
}

type resourceTemplateDesc struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MIMEType    string `json:"mimeType"`
}

func (s *Server) onResourcesList() (interface{}, *rpcError) {
	res := []resourceDesc{
		{
			URI:         "cau://signatures",
			Name:        "Signature database summary",
			Description: "Hash-signature counts by type and a bounded sample of entries.",
			MIMEType:    "application/json",
		},
		{
			URI:         "cau://coverage",
			Name:        "ATT&CK coverage matrix",
			Description: "Techniques covered by the shipped content, per-source summary and declared gaps.",
			MIMEType:    "application/json",
		},
	}
	return map[string]interface{}{"resources": res}, nil
}

func (s *Server) onResourceTemplatesList() (interface{}, *rpcError) {
	tpl := []resourceTemplateDesc{
		{
			URITemplate: "cau://rules/{name}",
			Name:        "YARA rule metadata",
			Description: "Namespace, tags, meta and string count for one compiled rule.",
			MIMEType:    "application/json",
		},
	}
	return map[string]interface{}{"resourceTemplates": tpl}, nil
}

type resourceContent struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType"`
	Text     string `json:"text"`
}

func (s *Server) onResourcesRead(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, errf(codeInvalidParams, "invalid resources/read params: %v", err)
	}
	uri := strings.TrimSpace(args.URI)

	switch {
	case uri == "cau://signatures":
		return s.readResource(uri, s.signaturesResource())
	case uri == "cau://coverage":
		m := s.buildMatrix()
		return s.readResource(uri, map[string]interface{}{
			"tool":          m.Tool,
			"version":       m.Version,
			"covered_count": len(m.Techniques),
			"covered":       techniqueIDs(m),
			"sources":       m.Sources,
			"gaps":          m.Gaps,
		})
	case strings.HasPrefix(uri, "cau://rules/"):
		name := strings.TrimPrefix(uri, "cau://rules/")
		return s.readRuleResource(uri, name)
	default:
		return nil, errf(codeInvalidParams, "unknown resource: %s", uri)
	}
}

func (s *Server) signaturesResource() map[string]interface{} {
	if s.deps.SigDB == nil {
		return map[string]interface{}{"loaded": false}
	}
	all := s.deps.SigDB.Signatures()
	sample := make([]map[string]string, 0, maxListItems)
	for i, sig := range all {
		if i >= maxListItems {
			break
		}
		sample = append(sample, map[string]string{"type": sig.HashType, "hash": sig.Hash, "threat_name": sig.ThreatName})
	}
	out := map[string]interface{}{
		"loaded":        true,
		"total":         s.deps.SigDB.Count(),
		"count_by_type": s.deps.SigDB.CountByType(),
		"sample":        sample,
	}
	if len(all) > len(sample) {
		out["sample_omitted"] = len(all) - len(sample)
	}
	return out
}

func (s *Server) readRuleResource(uri, name string) (interface{}, *rpcError) {
	if s.deps.Yara == nil {
		return nil, errf(codeInvalidParams, "no ruleset loaded")
	}
	for _, ri := range s.deps.Yara.RuleInfos() {
		if ri.Name == name {
			return s.readResource(uri, map[string]interface{}{
				"name":      ri.Name,
				"namespace": ri.Namespace,
				"tags":      ri.Tags,
				"meta":      ri.Meta,
				"strings":   ri.Strings,
				"private":   ri.Private,
				"global":    ri.Global,
				"technique": ri.MetaTechnique(),
			})
		}
	}
	return nil, errf(codeInvalidParams, "rule not found: %s", name)
}

func (s *Server) readResource(uri string, payload interface{}) (interface{}, *rpcError) {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, errf(codeInternalError, "marshal resource: %v", err)
	}
	return map[string]interface{}{
		"contents": []resourceContent{{URI: uri, MIMEType: "application/json", Text: string(b)}},
	}, nil
}
