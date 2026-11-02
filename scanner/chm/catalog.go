package chm

// Class describes one finding class the CHM detector can emit, for the ATT&CK
// coverage matrix. Field names and tags match the sibling iso.Class / lnk.Class
// so the matrix builder treats every detector alike.
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
		{"chm.embedded-executable", techUserExec, "", scoreExecutable,
			"an executable member (.exe/.dll/.scr/.ocx/…) carried in a help file — no legitimate CHM ships a PE"},
		{"chm.multiple-executables", techUserExec, "", scoreManyExec,
			"more than one executable member carried in the CHM"},
		{"chm.embedded-lnk", techUserExec, "", scoreLNK,
			"a Windows shortcut (.lnk) member — a user-execution delivery vector"},
		{"chm.embedded-script", techScripting, "", scoreScript,
			"a dangerous script member (.hta/.vbs/.ps1/.bat/.cmd/.wsf/…); plain .js is excluded as a help-TOC false positive"},
	}
}
