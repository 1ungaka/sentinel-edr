package archive

// Class describes one finding class the archive detector can emit, for the
// ATT&CK coverage matrix. Field names and tags match the sibling
// iso.Class / lnk.Class / pdf.Class so the matrix builder treats every detector
// alike. A class with no defensible ATT&CK mapping (a decompression bomb, a
// Zip-Slip path) carries an empty technique on purpose.
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
		{"archive.bomb", "", "", scoreBomb,
			"declared uncompressed size is a decompression-bomb profile (high ratio over a real absolute floor, or very large on its own)"},
		{"archive.path-traversal", "", "", scorePathTraversal,
			"a member name escapes the extraction root (absolute, drive-qualified, or containing \"..\" — Zip-Slip)"},
		{"archive.lure-double-extension", techMasquerade, "", scoreLureDoubleExt,
			"a member wears a benign extension immediately before an executable or script one (invoice.pdf.exe)"},
		{"archive.single-executable", techUserExec, "", scoreSingleExec,
			"the container holds exactly one member and it is an executable (the malspam single-payload lure)"},
		{"archive.executable-member", "", "", scoreExecMember,
			"one or more executable members (by extension or MZ/ELF/Mach-O magic) are carried inside the container"},
		{"archive.script-member", techUserExec, "", scoreScriptMember,
			"one or more script members (.js/.vbs/.hta/.ps1/.bat/.cmd/.wsf/… or a shebang) are carried inside the container"},
		{"archive.encrypted-entry", techObfuscated, "", scoreEncrypted,
			"one or more members are encrypted and cannot be inspected (password-protected malspam shape)"},
		{"archive.nested-archive", techObfuscated, "", scoreNested,
			"a member is itself an archive — a layer that must be unwrapped before its contents can be inspected"},
	}
}
