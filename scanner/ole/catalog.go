package ole

// Class describes one finding class the OLE/VBA detector can emit, per technique
// it is evidence for, for the ATT&CK coverage matrix. Field names and tags match
// the sibling lnk.Class so the matrix builder treats every detector alike. Novel
// is left empty: every class here maps to an established ATT&CK technique.
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
		{"ole.vba.project", techVBScript, "", weightVBAProject,
			"the document carries a VBA macro project (VBA/Macros storage or _VBA_PROJECT/dir/PROJECT stream)"},
		{"ole.vba.autoexec", techOfficeStartup, "", weightAutoExec,
			"a VBA auto-execution entry point (AutoOpen, Document_Open, Workbook_Open, Auto_Open, ...)"},
		{"ole.exec.powershell", techPowerShell, "", weightShell,
			"the VBA source spawns PowerShell (powershell / pwsh)"},
		{"ole.exec.cmd", techCmd, "", weightShell,
			"the VBA source spawns the Windows command shell (cmd.exe, cmd /c, %COMSPEC%)"},
		{"ole.exec.shell", techVBScript, "", weightShell,
			"the VBA source uses Shell / WScript.Shell / ShellExecute to run a process"},
		{"ole.download", techIngress, "", weightShell,
			"the VBA source uses a network-download primitive (URLDownloadToFile, MSXML2.XMLHTTP, WinHttp, ADODB.Stream)"},
		{"ole.exec.late-binding", techVBScript, "", weightLateBind,
			"the VBA source uses late-binding object creation (CreateObject, GetObject, CallByName)"},
		{"ole.obfuscation.encoded", techObfuscation, "", weightObfusc,
			"the VBA source uses base64 / string-reversal obfuscation (FromBase64String, StrReverse, Xor)"},
		{"ole.vba.obfuscation", techObfuscation, "", weightObfusc,
			"the VBA source builds strings with heavy Chr() obfuscation"},
		{"ole.lure.equation", techExploit, "", weightEmbedded,
			"an Equation Editor native stream (classic exploit carrier)"},
		{"ole.lure.ole10native", techUserExec, "", weightEmbedded,
			"an Ole10Native embedded-object stream (embedded-payload carrier)"},
	}
}
