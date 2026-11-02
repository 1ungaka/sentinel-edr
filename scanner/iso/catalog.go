package iso

// Class describes one finding class the ISO detector can emit, per technique it
// is evidence for, for the ATT&CK coverage matrix. Field names and tags match
// the sibling lnk.Class / pdf.Class so the matrix builder treats every detector
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
		{"iso.autorun.inf", techRemovableMedia, "", weightAutorun,
			"autorun.inf in the root directory of the image (autorun abuse on a mounted image)"},
		{"iso.payload.lnk", techUserExec, "", weightLnk,
			"a Windows shortcut (.lnk) carried in the image — a user-execution lure / delivery vector"},
		{"iso.payload.executable", techUserExec, "", weightExecutable,
			"an executable or script file carried in the image (.exe, .dll, .scr, .com, .bat, .cmd, .ps1, .vbs, .js, .jse, .wsf, .hta, .pif, .msi)"},
		{"iso.evasion.hidden-payload", techHideArtifacts, "", weightHiddenPayload,
			"a hidden executable or script — the ISO hidden flag set on a payload, or a payload inside a hidden directory"},
		{"iso.lure.lnk-and-payload", techUserExec, "", weightLure,
			"a shortcut (.lnk) delivered alongside an executable/script payload — the canonical ISO-smuggling lure shape"},
		{"iso.lure.small-image", techUserExec, "", weightSmallImage,
			"a small image carrying a shortcut and a payload — the email-attachment delivery shape (amplifier)"},
	}
}
