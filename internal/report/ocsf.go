package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/cau-edr/cau/internal/attack"
)

// OCSF (Open Cybersecurity Schema Framework) output: one Detection Finding
// (class_uid 2004) per file the engine reports as suspicious or malicious,
// so a security lake (Matano, Amazon Security Lake, anything OCSF-native)
// ingests findings without a custom parser. The document is a JSON array;
// pipe through `jq -c '.[]'` for NDJSON.
//
// What maps where:
//
//   - severity_id: malicious = High (4), suspicious = Medium (3). Critical is
//     never claimed by a file scanner.
//   - finding_info.analytic: the detector that led (the fusion lattice's
//     first agreed source, else the strongest tier), with the YARA rule or
//     the hash-signature threat as its uid.
//   - finding_info.attacks: the union of ATT&CK techniques every detector
//     attached, with names from the engine's catalog where it knows them.
//   - evidences[0].file: path, size and the digests.
//   - malware: the hash-signature threat and every YARA rule's family.
//   - confidence_id: from the fusion verdict's confidence.
//   - unmapped: the engine-native detail (verdict, scores, thresholds,
//     classes, rule names) so nothing is lost in the mapping.
//
// Clean files and files that could not be scanned are not findings and are
// not emitted; the JSON and SARIF formats carry them.
const (
	OCSFVersion = "1.3.0"

	ocsfCategoryUID  = 2
	ocsfCategoryName = "Findings"
	ocsfClassUID     = 2004
	ocsfClassName    = "Detection Finding"
	ocsfActivityID   = 1 // Create
	ocsfActivityName = "Create"
	ocsfTypeUID      = ocsfClassUID*100 + ocsfActivityID
	ocsfTypeName     = "Detection Finding: Create"
	ocsfStatusNew    = 1
)

// OCSFReporter renders Detection Finding objects.
type OCSFReporter struct {
	cfg config
}

// NewOCSFReporter builds a reporter from the shared options.
func NewOCSFReporter(opts ...Option) *OCSFReporter {
	return &OCSFReporter{cfg: buildConfig(opts)}
}

type ocsfFinding struct {
	ActivityID   int             `json:"activity_id"`
	ActivityName string          `json:"activity_name"`
	CategoryUID  int             `json:"category_uid"`
	CategoryName string          `json:"category_name"`
	ClassUID     int             `json:"class_uid"`
	ClassName    string          `json:"class_name"`
	TypeUID      int             `json:"type_uid"`
	TypeName     string          `json:"type_name"`
	Time         int64           `json:"time"`
	SeverityID   int             `json:"severity_id"`
	Severity     string          `json:"severity"`
	StatusID     int             `json:"status_id"`
	Status       string          `json:"status"`
	IsAlert      bool            `json:"is_alert"`
	ConfidenceID int             `json:"confidence_id"`
	Confidence   string          `json:"confidence,omitempty"`
	Message      string          `json:"message"`
	Metadata     ocsfMetadata    `json:"metadata"`
	FindingInfo  ocsfFindingInfo `json:"finding_info"`
	Evidences    []ocsfEvidence  `json:"evidences"`
	Malware      []ocsfMalware   `json:"malware,omitempty"`
	Unmapped     map[string]any  `json:"unmapped"`
}

type ocsfMetadata struct {
	Version    string      `json:"version"`
	Product    ocsfProduct `json:"product"`
	LoggedTime int64       `json:"logged_time"`
}

type ocsfProduct struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	VendorName string `json:"vendor_name"`
	URLString  string `json:"url_string,omitempty"`
}

type ocsfFindingInfo struct {
	Title       string       `json:"title"`
	UID         string       `json:"uid"`
	Desc        string       `json:"desc,omitempty"`
	Analytic    ocsfAnalytic `json:"analytic"`
	Attacks     []ocsfAttack `json:"attacks,omitempty"`
	Types       []string     `json:"types,omitempty"`
	DataSources []string     `json:"data_sources"`
}

type ocsfAnalytic struct {
	Name   string `json:"name"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type"`
	UID    string `json:"uid,omitempty"`
	Desc   string `json:"desc,omitempty"`
}

type ocsfAttack struct {
	Technique ocsfTechnique `json:"technique"`
	Tactics   []ocsfTactic  `json:"tactics,omitempty"`
	Version   string        `json:"version"`
}

type ocsfTechnique struct {
	UID  string `json:"uid"`
	Name string `json:"name,omitempty"`
}

type ocsfTactic struct {
	Name string `json:"name"`
}

type ocsfEvidence struct {
	File ocsfFile `json:"file"`
}

type ocsfFile struct {
	Name   string     `json:"name"`
	Path   string     `json:"path"`
	TypeID int        `json:"type_id"`
	Type   string     `json:"type"`
	Size   *int64     `json:"size,omitempty"`
	Hashes []ocsfHash `json:"hashes,omitempty"`
}

type ocsfHash struct {
	AlgorithmID int    `json:"algorithm_id"`
	Algorithm   string `json:"algorithm"`
	Value       string `json:"value"`
}

type ocsfMalware struct {
	Name string `json:"name"`
}

// Write encodes the findings to w.
func (r *OCSFReporter) Write(w io.Writer, in Input) error {
	findings := r.Build(in)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if r.cfg.indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("report: encode ocsf: %w", err)
	}
	return nil
}

// Build assembles the findings without encoding them. The slice is never
// nil, so an empty run encodes as "[]".
func (r *OCSFReporter) Build(in Input) []ocsfFinding {
	c := r.cfg
	doc := c.buildDocument(in)
	now := c.now().UTC().UnixMilli()
	out := []ocsfFinding{}
	for _, f := range doc.Files {
		if f.Verdict != JSONVerdictSuspicious && f.Verdict != JSONVerdictMalicious {
			continue
		}
		out = append(out, c.ocsfFinding(doc, f, now))
	}
	return out
}

func (c config) ocsfFinding(doc Document, f File, now int64) ocsfFinding {
	fi := ocsfFinding{
		ActivityID: ocsfActivityID, ActivityName: ocsfActivityName,
		CategoryUID: ocsfCategoryUID, CategoryName: ocsfCategoryName,
		ClassUID: ocsfClassUID, ClassName: ocsfClassName,
		TypeUID: ocsfTypeUID, TypeName: ocsfTypeName,
		Time: now, StatusID: ocsfStatusNew, Status: "New",
		Metadata: ocsfMetadata{
			Version:    OCSFVersion,
			Product:    ocsfProduct{Name: doc.Tool.Name, Version: doc.Tool.Version, VendorName: "CAU", URLString: c.informationURI},
			LoggedTime: now,
		},
		Unmapped: map[string]any{"verdict": f.Verdict, "schema_version": doc.SchemaVersion},
	}
	switch f.Verdict {
	case JSONVerdictMalicious:
		fi.SeverityID, fi.Severity, fi.IsAlert = 4, "High", true
	default:
		fi.SeverityID, fi.Severity = 3, "Medium"
	}

	// Evidence: the file.
	file := ocsfFile{Name: baseName(f.Path), Path: f.Path, TypeID: 1, Type: "Regular File", Size: f.Size}
	if f.Hashes != nil {
		if f.Hashes.MD5 != "" {
			file.Hashes = append(file.Hashes, ocsfHash{1, "MD5", f.Hashes.MD5})
		}
		if f.Hashes.SHA1 != "" {
			file.Hashes = append(file.Hashes, ocsfHash{2, "SHA-1", f.Hashes.SHA1})
		}
		if f.Hashes.SHA256 != "" {
			file.Hashes = append(file.Hashes, ocsfHash{3, "SHA-256", f.Hashes.SHA256})
		}
	}
	fi.Evidences = []ocsfEvidence{{File: file}}

	// Techniques and the leading detector.
	techs := map[string]bool{}
	var sources []string
	var titleParts []string
	analytic := ocsfAnalytic{TypeID: 1, Type: "Rule"}
	if f.HashMatch != nil {
		sources = append(sources, "hash")
		fi.Malware = append(fi.Malware, ocsfMalware{Name: f.HashMatch.Threat})
		titleParts = append(titleParts, "hash signature "+f.HashMatch.Threat)
		fi.Unmapped["hash_match"] = f.HashMatch
	}
	if len(f.Yara) > 0 {
		sources = append(sources, "yara")
		var names []string
		for _, h := range f.Yara {
			names = append(names, h.Rule)
			for _, m := range h.Meta {
				switch m.Key {
				case "mitre_attack", "attack", "technique":
					for _, t := range strings.FieldsFunc(m.Value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
						techs[t] = true
					}
				case "family":
					if m.Value != "" {
						fi.Malware = append(fi.Malware, ocsfMalware{Name: m.Value})
					}
				}
			}
		}
		titleParts = append(titleParts, "YARA "+strings.Join(names, ", "))
		fi.Unmapped["yara_rules"] = names
	}
	if h := f.Heuristics; h != nil && h.Detected {
		sources = append(sources, "heuristic")
		var cats []string
		for _, cat := range h.Categories {
			if cat.Applied > 0 {
				cats = append(cats, cat.Category)
			}
			if cat.Technique != "" && cat.Applied > 0 {
				techs[cat.Technique] = true
			}
		}
		titleParts = append(titleParts, fmt.Sprintf("heuristics %d/%d", h.Score, h.Threshold))
		fi.Unmapped["heuristics"] = map[string]any{"score": h.Score, "threshold": h.Threshold, "categories": cats}
	}
	if s := f.Static; s != nil && s.Detected {
		sources = append(sources, "static")
		var classes []string
		for _, a := range s.Anomalies {
			if a.Score > 0 {
				classes = append(classes, a.Class)
			}
			if a.Technique != "" && a.Score > 0 {
				techs[a.Technique] = true
			}
		}
		for _, m := range s.FuzzyMatches {
			fi.Malware = append(fi.Malware, ocsfMalware{Name: m.Threat})
		}
		titleParts = append(titleParts, fmt.Sprintf("static structure %d/%d", s.Score, s.Threshold))
		fi.Unmapped["static"] = map[string]any{"score": s.Score, "threshold": s.Threshold, "classes": classes}
	}
	if st := f.Stego; st != nil && st.Detected {
		sources = append(sources, "stego")
		var classes []string
		for _, fd := range st.Findings {
			classes = append(classes, fd.Class)
			if fd.Technique != "" {
				techs[fd.Technique] = true
			}
		}
		titleParts = append(titleParts, fmt.Sprintf("invisible codepoints %d/%d", st.Score, st.Threshold))
		fi.Unmapped["stego"] = map[string]any{"score": st.Score, "threshold": st.Threshold, "classes": classes}
	}
	if ec := f.EncChain; ec != nil && ec.Detected {
		sources = append(sources, "encchain")
		var classes []string
		for _, fd := range ec.Findings {
			classes = append(classes, fd.Class)
			if fd.Technique != "" {
				techs[fd.Technique] = true
			}
		}
		titleParts = append(titleParts, fmt.Sprintf("encoded executable %d/%d", ec.Score, ec.Threshold))
		fi.Unmapped["encchain"] = map[string]any{"score": ec.Score, "threshold": ec.Threshold, "classes": classes}
	}
	if lk := f.LNK; lk != nil && lk.Detected {
		sources = append(sources, "lnk")
		var classes []string
		for _, fd := range lk.Findings {
			classes = append(classes, fd.Class)
			if fd.Technique != "" {
				techs[fd.Technique] = true
			}
		}
		titleParts = append(titleParts, fmt.Sprintf("shell link %d/%d", lk.Score, lk.Threshold))
		fi.Unmapped["lnk"] = map[string]any{"score": lk.Score, "threshold": lk.Threshold, "classes": classes}
	}
	if ol := f.OLE; ol != nil && ol.Detected {
		sources = append(sources, "ole")
		var classes []string
		for _, fd := range ol.Findings {
			classes = append(classes, fd.Class)
			if fd.Technique != "" {
				techs[fd.Technique] = true
			}
		}
		titleParts = append(titleParts, fmt.Sprintf("ole macro %d/%d", ol.Score, ol.Threshold))
		fi.Unmapped["ole"] = map[string]any{"score": ol.Score, "threshold": ol.Threshold, "classes": classes}
	}
	if pd := f.PDF; pd != nil && pd.Detected {
		sources = append(sources, "pdf")
		var classes []string
		for _, fd := range pd.Findings {
			classes = append(classes, fd.Class)
			if fd.Technique != "" {
				techs[fd.Technique] = true
			}
		}
		titleParts = append(titleParts, fmt.Sprintf("pdf document %d/%d", pd.Score, pd.Threshold))
		fi.Unmapped["pdf"] = map[string]any{"score": pd.Score, "threshold": pd.Threshold, "classes": classes}
	}
	if is := f.ISO; is != nil && is.Detected {
		sources = append(sources, "iso")
		var classes []string
		for _, fd := range is.Findings {
			classes = append(classes, fd.Class)
			if fd.Technique != "" {
				techs[fd.Technique] = true
			}
		}
		titleParts = append(titleParts, fmt.Sprintf("iso container %d/%d", is.Score, is.Threshold))
		fi.Unmapped["iso"] = map[string]any{"score": is.Score, "threshold": is.Threshold, "classes": classes}
	}
	if fu := f.Fusion; fu != nil {
		for _, t := range fu.Techniques {
			techs[t] = true
		}
		switch fu.Confidence {
		case "low":
			fi.ConfidenceID, fi.Confidence = 1, "Low"
		case "medium":
			fi.ConfidenceID, fi.Confidence = 2, "Medium"
		case "high":
			fi.ConfidenceID, fi.Confidence = 3, "High"
		}
		fusionDetail := map[string]any{"tier": fu.Tier, "score": fu.Score, "confidence": fu.Confidence,
			"agreed": fu.Agreed, "corroborated": fu.Corroborated}
		if len(fu.Novel) > 0 {
			fusionDetail["novel"] = fu.Novel
		}
		fi.Unmapped["fusion"] = fusionDetail
		if fu.Corroborated {
			sources = append(sources, "fusion")
			titleParts = append(titleParts, fmt.Sprintf("fused %.2f/%.2f", fu.Score, fu.Threshold))
		}
	}
	if len(sources) == 0 {
		sources = []string{"engine"}
		titleParts = []string{"detection"}
	}

	// The leading detector: the lattice itself when only corroboration
	// reached the suspicious tier, else the lattice's strongest agreed
	// source, else the first in tier order above.
	lead := sources[0]
	switch {
	case f.Fusion != nil && f.Fusion.Corroborated:
		lead = "fusion"
	case f.Fusion != nil && len(f.Fusion.Agreed) > 0:
		lead = f.Fusion.Agreed[0]
	}
	analytic.Name = c.toolName + "/" + lead
	switch lead {
	case "hash":
		analytic.TypeID, analytic.Type = 5, "Fingerprinting"
		if f.HashMatch != nil {
			analytic.UID = "hash/" + slug(f.HashMatch.Threat)
			analytic.Desc = "exact-content signature: " + f.HashMatch.Type + " " + f.HashMatch.Hash
		}
	case "yara":
		if len(f.Yara) > 0 {
			ns := f.Yara[0].Namespace
			if ns == "" {
				ns = "default"
			}
			analytic.UID = "yara/" + slug(ns) + "/" + f.Yara[0].Rule
			for _, m := range f.Yara[0].Meta {
				if m.Key == "description" {
					analytic.Desc = m.Value
				}
			}
		}
	case "similarity":
		analytic.TypeID, analytic.Type = 5, "Fingerprinting"
		analytic.UID = "static/fuzzy"
	case "fusion":
		analytic.TypeID, analytic.Type = 99, "Other"
		analytic.UID = "fusion/corroborated"
		analytic.Desc = "sub-threshold detectors corroborated each other"
	default:
		analytic.UID = lead + "/score"
	}
	fi.FindingInfo = ocsfFindingInfo{
		Title:       strings.Join(titleParts, "; "),
		UID:         findingUID(f),
		Desc:        c.boundedMessage(fmt.Sprintf("%s: %s", f.Path, strings.Join(titleParts, "; "))),
		Analytic:    analytic,
		Types:       sources,
		DataSources: []string{"file"},
	}
	if f.Fusion != nil && f.Fusion.Explanation != "" {
		fi.FindingInfo.Desc = c.boundedMessage(f.Fusion.Explanation)
	}
	for _, id := range sortedKeys(techs) {
		a := ocsfAttack{Technique: ocsfTechnique{UID: id, Name: attack.Name(id)}, Version: attack.Version}
		for _, t := range attack.Tactics(id) {
			a.Tactics = append(a.Tactics, ocsfTactic{Name: t})
		}
		fi.FindingInfo.Attacks = append(fi.FindingInfo.Attacks, a)
	}
	fi.Message = fi.FindingInfo.Title
	fi.Unmapped["sources"] = sources
	return fi
}

// findingUID is stable across runs for the same content at the same path.
func findingUID(f File) string {
	h := sha256.New()
	h.Write([]byte(f.Path))
	h.Write([]byte{0})
	if f.Hashes != nil {
		h.Write([]byte(f.Hashes.SHA256))
	}
	return "cau:" + hex.EncodeToString(h.Sum(nil))[:32]
}

func baseName(p string) string {
	p = strings.TrimRight(p, "/\\")
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}
