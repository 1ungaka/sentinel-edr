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
		{"ole.vba.stomp.source-missing", techStomping, "", weightStompMissing,
			"a VBA module stream holds a substantial compiled p-code region but no source: the dir stream's TextOffset is at or past the end of the stream, or no CompressedContainer starts there"},
		{"ole.vba.stomp.source-blank", techStomping, "", weightStompBlank,
			"a VBA module stream holds a substantial compiled p-code region but its source decompresses to Attribute lines and whitespace only"},
		{"ole.vba.stomp.mismatch", techStomping, "", weightStompMismatch,
			"printable string runs in a VBA module's p-code region (or, for a module already found without source, in the project-wide _VBA_PROJECT stream) name an execution or auto-run primitive that occurs nowhere in the source; a heuristic over string runs, not a p-code disassembly"},
		{"ole.lure.equation", techExploit, "", weightEmbedded,
			"an Equation Editor native stream (classic exploit carrier)"},
		{"ole.lure.ole10native", techUserExec, "", weightEmbedded,
			"an Ole10Native embedded-object stream (embedded-payload carrier)"},
	}
}
