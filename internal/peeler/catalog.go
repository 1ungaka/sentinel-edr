package peeler

// Class describes one finding class the peeler can emit, per technique it is
// evidence for, for the ATT&CK coverage matrix. Field names and tags match the
// sibling detectors' Class types so the matrix builder treats every detector
// alike. Every class carries the NOVEL-012 id because chain depth as a signal
// is detection-first research ahead of a dedicated ATT&CK sub-technique.
type Class struct {
	Class       string `json:"class"`
	Technique   string `json:"technique"`
	Novel       string `json:"novel,omitempty"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
}

// Classes returns the catalog in a stable, report-friendly order. The weights
// mirror the finding scores buildFindings emits for a crossing chain.
func Classes() []Class {
	return []Class{
		{"peel.revealed-executable", Technique, Novel, 60,
			"a PE/ELF executable revealed at the bottom of a multi-layer (depth >= 2) encoding/compression chain"},
		{"peel.revealed-script", Technique, Novel, 40,
			"a script (shebang) revealed at the bottom of a multi-layer (depth >= 2) encoding/compression chain"},
		{"peel.exhausted", Technique, Novel, 30,
			"a layer chain that outlived the per-sample budget wall — rendered first-class as peel-exhausted, never silent-clean"},
	}
}
