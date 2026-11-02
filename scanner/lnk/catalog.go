package lnk

// Class describes one finding class the .lnk detector can emit, per technique
// it is evidence for, for the ATT&CK coverage matrix. Field names and tags
// match the sibling encchain.Class so the matrix builder treats every detector
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
		{"lnk.command.powershell", techPowerShell, "", weightInterp,
			"arguments invoke PowerShell (powershell / pwsh)"},
		{"lnk.command.cmd", techCmd, "", weightInterp,
			"arguments invoke the Windows command shell (cmd /c, cmd /k)"},
		{"lnk.command.wscript", techScriptHost, "", weightInterp,
			"arguments invoke the Windows Script Host (wscript / cscript)"},
		{"lnk.command.lolbin", techInterp, "", weightInterp,
			"arguments invoke a living-off-the-land binary (mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, installutil, forfiles)"},
		{"lnk.obfuscation.encoded", techObfuscation, "", weightEncoded,
			"encoded or obfuscated command flags in the arguments (-enc, FromBase64String, IEX, DownloadString, -ep bypass)"},
		{"lnk.evasion.hidden-window", techObfuscation, "", weightHidden,
			"a hidden-window flag in the arguments (-w hidden / -windowstyle hidden)"},
		{"lnk.obfuscation.env-var", techObfuscation, "", weightEnvVar,
			"environment-variable obfuscation of the launched path (%comspec%, %systemroot%, %appdata%, %temp%) or an ENVIRONMENT_VARIABLE_DATA_BLOCK resolving to an executable"},
		{"lnk.args.long", techObfuscation, "", weightLongArgs,
			"unusually long command-line arguments (padding / inline obfuscation)"},
		{"lnk.target.executable", techUserExec, "", weightTargetEx,
			"the shortcut target or relative path is an executable or script"},
		{"lnk.lure.icon-mismatch", techUserExec, "", weightIconLure,
			"a document-like icon fronts an interpreter invocation (lure)"},
		{"lnk.overlay.trailing", techObfuscation, "", weightTrailing,
			"large data appended past the parsed shortcut structures (possible embedded payload)"},
	}
}
