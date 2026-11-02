package pdf

// Class describes one finding class the PDF detector can emit, per technique it
// is evidence for, for the ATT&CK coverage matrix. Field names and tags match the
// sibling lnk.Class / ole.Class so the matrix builder treats every detector
// alike. Novel is left empty: every class here maps to an established ATT&CK
// technique.
type Class struct {
	Class       string `json:"class"`
	Technique   string `json:"technique"`
	Novel       string `json:"novel,omitempty"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
}

// Classes returns the catalog in a stable, report-friendly order.
func Classes() []Class {
	return []Class{
		{"pdf.action.openaction", techUserExec, "", weightAutoAction,
			"an automatic action that runs when the file is opened (/OpenAction or /AA)"},
		{"pdf.javascript", techJS, "", weightJavaScript,
			"embedded JavaScript (/JavaScript or /JS)"},
		{"pdf.action.launch", techInterp, "", weightLaunch,
			"a Launch action that runs an external program (/Launch)"},
		{"pdf.embeddedfile", techUserExec, "", weightEmbedded,
			"an embedded file carried in the document (/EmbeddedFile or /EF) — payload carrier"},
		{"pdf.action.remote", techIngress, "", weightRemote,
			"a remote-fetch action (/SubmitForm or remote /GoToR)"},
		{"pdf.uri", techMalLink, "", weightURI,
			"a URI action — network callout / link (/URI)"},
		{"pdf.obfuscation.name", techObfuscation, "", weightNameObf,
			"a sensitive name spelled with #xx hex escapes to evade string matching (e.g. /J#61vaScript)"},
		{"pdf.javascript.heuristic", techObfuscation, "", weightJSHeuristic,
			"embedded JavaScript using exploitation / obfuscation primitives (unescape, eval, fromCharCode, %u heap-spray, util.printf, getAnnots, ...)"},
		{"pdf.evasion.encrypted-autojs", techObfuscation, "", weightEncEvasion,
			"an encrypted document that also auto-runs embedded JavaScript (evasion amplifier)"},
	}
}
