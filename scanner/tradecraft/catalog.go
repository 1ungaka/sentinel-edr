package tradecraft

import "sort"

// Finding classes.
const (
	classPEBHash   = "tradecraft.shellcode.peb-walk-api-hash"
	classAPIHash   = "tradecraft.shellcode.api-hash-constants"
	classGetPC     = "tradecraft.shellcode.fpu-getpc-decoder"
	classJmpCall   = "tradecraft.shellcode.jmp-call-pop-decoder"
	classLinuxNet  = "tradecraft.shellcode.linux-socket-syscalls"
	classLinuxExec = "tradecraft.shellcode.linux-execve-shell"

	classPHPRequestExec = "tradecraft.webshell.php-request-exec"
	classPHPTaintExec   = "tradecraft.webshell.php-tainted-exec"
	classPHPEvalDecode  = "tradecraft.webshell.php-eval-decode"
	classASPExec        = "tradecraft.webshell.asp-exec"
	classASPXExec       = "tradecraft.webshell.aspx-exec"
	classJSPExec        = "tradecraft.webshell.jsp-exec"
	classCFMExec        = "tradecraft.webshell.cfm-exec"
	classCGIExec        = "tradecraft.webshell.cgi-exec"

	classRevShellSh      = "tradecraft.netshell.shell"
	classRevShellPHP     = "tradecraft.netshell.php"
	classRevShellPython  = "tradecraft.netshell.python"
	classStagerPython    = "tradecraft.netshell.python-stager"
	classRevShellPerl    = "tradecraft.netshell.perl"
	classRevShellJava    = "tradecraft.netshell.java"
	classRevShellPS      = "tradecraft.netshell.powershell"
	classRevShellRuby    = "tradecraft.netshell.ruby"
	classRevShellTool    = "tradecraft.netshell.relay-tool"
	classRevShellLua     = "tradecraft.netshell.lua"
	classRevShellC       = "tradecraft.netshell.native-source"
	classRevShellManaged = "tradecraft.netshell.socket-to-process"

	classMemLoader         = "tradecraft.memory.alloc-and-run"
	classReflectiveAPI     = "tradecraft.memory.reflective-winapi"
	classPythonExecDecoded = "tradecraft.script.python-exec-decoded"
	classAssemblyLoad      = "tradecraft.memory.assembly-load-decoded"

	classAMSIBypass     = "tradecraft.script.amsi-bypass"
	classDownloadExec   = "tradecraft.script.download-exec"
	classDecodeExec     = "tradecraft.script.decode-exec"
	classCredAccess     = "tradecraft.script.credential-access"
	classTokenTheft     = "tradecraft.script.token-theft"
	classKeylogger      = "tradecraft.script.keylogger"
	classCapture        = "tradecraft.script.screen-audio-capture"
	classLateral        = "tradecraft.script.lateral-execution"
	classDefenseEvasion = "tradecraft.script.defense-evasion"
	classPersistence    = "tradecraft.script.persistence"
	classTimestomp      = "tradecraft.script.timestomp"
	classObfuscation    = "tradecraft.script.obfuscation"
	classProxy          = "tradecraft.script.socket-relay"
	classHiddenExec     = "tradecraft.script.hidden-window"
	classDCOMExec       = "tradecraft.script.dcom-execution"
	classSQLShell       = "tradecraft.script.sql-command-shell"
	classGPPSecrets     = "tradecraft.script.gpp-password-hunt"
	classNTLMCraft      = "tradecraft.script.ntlm-crafting"

	classLOLDownload     = "tradecraft.lolbin.remote-payload"
	classLOLExec         = "tradecraft.lolbin.proxy-execution"
	classLOLProxy        = "tradecraft.lolbin.proxy-capable"
	classLOLDump         = "tradecraft.lolbin.credential-dump"
	classLOLDecode       = "tradecraft.lolbin.encode-decode"
	classInhibitRecovery = "tradecraft.lolbin.inhibit-recovery"
	classGlobObfuscation = "tradecraft.script.shell-obfuscation"
	classC2Service       = "tradecraft.script.third-party-channel"
	// LOLC2 — a specific abusable SaaS API path, not just naming the host.
	// Scores higher than classC2Service because the path is the giveaway.
	classC2APIAbuse = "tradecraft.c2service.saas-api-call"

	// ArcticFox bypass primitives (docs/Detection-Bypasses.md). Each names a
	// concrete evasion technique the engine would otherwise miss.
	classBypassMemFD          = "tradecraft.bypass.memfd-exec"
	classBypassProcRename     = "tradecraft.bypass.proc-name-camouflage"
	classBypassLDPreload      = "tradecraft.bypass.ld-preload-shim"
	classBypassPAMBackdoor    = "tradecraft.bypass.pam-exec-backdoor"
	classBypassSystemdHijack  = "tradecraft.bypass.systemd-unit-hijack"
	classBypassSelfDelete     = "tradecraft.bypass.self-delete"
	classBypassGithubDeadDrop = "tradecraft.bypass.github-deaddrop"
	classBypassICMPC2         = "tradecraft.bypass.icmp-channel"
	classBypassDNSC2          = "tradecraft.bypass.dns-txt-channel"
	classBypassOpenRedirect   = "tradecraft.bypass.open-redirect-channel"
	classBypassDomainFront    = "tradecraft.bypass.domain-fronting"
	classBypassProcHide       = "tradecraft.bypass.proc-self-exe-unlink"
)

type catalogEntry struct {
	score     int
	technique string
	detail    string
}

// catalog is the single table of what each class means. A score of 8 or more is
// a verdict by itself: the behaviour has no ordinary use. Below that a class is
// something admin scripts also do, and it takes two to reach the threshold.
var catalog = map[string]catalogEntry{
	classPEBHash:   {9, "T1027.007", "code walks the PEB module list and hashes export names: how shellcode finds APIs with no import table"},
	classAPIHash:   {9, "T1027.007", "immediates match ROR13 hashes of network and process APIs: API calls with the names removed"},
	classGetPC:     {8, "T1027.013", "x87 fnstenv GetPC followed by an in-place xor: a self-decoding stub"},
	classJmpCall:   {8, "T1027.013", "jmp/call/pop control flow into an xor body: a self-decoding stub"},
	classLinuxNet:  {9, "T1059.004", "hand-loaded Linux socket syscalls in a small blob: a bind or reverse shell stub"},
	classLinuxExec: {8, "T1059.004", "a hand-built execve of a shell in a small blob"},

	classPHPRequestExec: {9, "T1505.003", "an HTTP request parameter is passed straight to a PHP execution function"},
	classPHPTaintExec:   {9, "T1505.003", "an HTTP request parameter flows through variables into a PHP execution function"},
	classPHPEvalDecode:  {9, "T1505.003", "PHP evaluates a decoded or decompressed string"},
	classASPExec:        {9, "T1505.003", "classic ASP runs WScript.Shell with an HTTP request present"},
	classASPXExec:       {9, "T1505.003", "an ASP.NET page starts a process"},
	classJSPExec:        {9, "T1505.003", "a JSP page runs a command with an HTTP parameter present"},
	classCFMExec:        {9, "T1505.003", "a ColdFusion page runs cfexecute from form or URL input"},
	classCGIExec:        {8, "T1505.003", "a CGI script runs a command from its query input"},

	classRevShellSh:      {9, "T1059.004", "a shell is wired to a network socket"},
	classRevShellPHP:     {9, "T1505.003", "PHP opens a socket and runs a shell"},
	classRevShellPython:  {9, "T1059.006", "Python duplicates a socket onto a shell"},
	classStagerPython:    {9, "T1059.006", "Python receives code over a socket and executes it"},
	classRevShellPerl:    {9, "T1059", "Perl wires a socket to a shell"},
	classRevShellJava:    {9, "T1059", "Java pipes a process through a socket"},
	classRevShellPS:      {9, "T1059.001", "PowerShell drives a command interpreter over a TCP stream"},
	classRevShellRuby:    {9, "T1059", "Ruby wires a socket to a shell"},
	classRevShellTool:    {9, "T1059.004", "a relay tool binds a shell to the network"},
	classRevShellLua:     {9, "T1059", "Lua runs commands around a socket"},
	classRevShellC:       {9, "T1059", "source code connects a socket to a shell's standard streams"},
	classRevShellManaged: {8, "T1059", "a program opens a socket and drives a shell or redirected process"},

	classMemLoader:         {8, "T1620", "script allocates memory through native APIs and starts a thread in it: an in-memory loader"},
	classReflectiveAPI:     {4, "T1106", "script reaches native APIs by reflection instead of declaring them"},
	classPythonExecDecoded: {8, "T1027", "Python executes a decoded or decompressed string"},
	classAssemblyLoad:      {8, "T1620", "script loads a .NET assembly from decoded bytes, in memory"},

	classAMSIBypass:     {9, "T1562.001", "script tampers with the Antimalware Scan Interface"},
	classDownloadExec:   {8, "T1059.001", "script downloads text and executes it"},
	classDecodeExec:     {8, "T1027", "script decodes a blob and executes it"},
	classCredAccess:     {6, "T1003", "script touches credential stores or LSASS"},
	classTokenTheft:     {6, "T1134", "script duplicates or impersonates a logon token"},
	classKeylogger:      {8, "T1056.001", "script polls or hooks the keyboard and tracks the focused window"},
	classCapture:        {4, "T1113", "script captures the screen or the microphone"},
	classLateral:        {6, "T1021", "script executes on a remote host through WMI, DCOM, the service manager or SQL"},
	classDefenseEvasion: {6, "T1562.001", "script disables defences or clears event logs"},
	classPersistence:    {4, "T1547.001", "script installs an autostart entry"},
	classTimestomp:      {3, "T1070.006", "script rewrites file timestamps"},
	classObfuscation:    {3, "T1027.010", "script builds its command text at run time"},
	classProxy:          {4, "T1090", "script accepts inbound connections on a raw socket"},
	classHiddenExec:     {3, "T1564.003", "script hides the window of what it starts"},
	classDCOMExec:       {8, "T1021.003", "script runs a command through a DCOM object's shell method"},
	classSQLShell:       {8, "T1059", "script enables or drives xp_cmdshell on a SQL server"},
	classGPPSecrets:     {8, "T1552.006", "script searches SYSVOL for Group Policy passwords"},
	classNTLMCraft:      {4, "T1550.002", "script builds NTLM authentication messages by hand"},

	classLOLDownload:     {8, "T1105", "a system binary fetches or runs a remote payload"},
	classLOLExec:         {8, "T1218", "a system binary is used to proxy execution through a script handler or abuse flag"},
	classLOLProxy:        {4, "T1218", "a binary known to proxy execution is invoked with arguments"},
	classLOLDump:         {8, "T1003", "a system tool dumps credential stores or process memory"},
	classLOLDecode:       {6, "T1140", "a system binary encodes or decodes a file"},
	classInhibitRecovery: {8, "T1490", "script destroys backups or boot recovery"},
	classGlobObfuscation: {6, "T1027.010", "shell text hides a command behind globs or IFS expansion"},
	classC2Service:       {3, "T1102", "script names a webhook, tunnel, paste, file-drop or trusted-SaaS host used as a command channel"},
	classC2APIAbuse:      {5, "T1102", "script calls a specific abusable SaaS API endpoint from the LOLC2 / LOLFSaaS catalogues: a trusted host used for command and control"},

	classBypassMemFD:          {8, "T1620", "memfd_create or shm_open is paired with fexecve / execveat / /proc/self/fd exec: an anonymous in-memory executable"},
	classBypassProcRename:     {6, "T1036.005", "prctl(PR_SET_NAME) is paired with a socket or exec call: kernel-level process-name camouflage"},
	classBypassLDPreload:      {6, "T1574.006", "code writes /etc/ld.so.preload or resolves symbols through dlsym(RTLD_NEXT): a shared-library hook is being installed"},
	classBypassPAMBackdoor:    {8, "T1556.003", "pam_exec.so is added to a PAM stack, or pam_unix.so is overwritten: the authentication stack is being backdoored"},
	classBypassSystemdHijack:  {6, "T1543.002", "systemctl edit --full, a .service.d drop-in override, or systemd-run --user is used to persist by riding on a real unit's identity"},
	classBypassSelfDelete:     {4, "T1070.004", "the process deletes its own binary, often via /proc/self/exe: forensic artifact removal"},
	classBypassGithubDeadDrop: {5, "T1102.002", "code fetches a markdown or raw blob from the GitHub Contents API with cache-busting parameters: a repository README used as a dead-drop channel"},
	classBypassICMPC2:         {6, "T1095", "a raw ICMP socket is created and its echo payload is read or written: a non-IP-layer command channel"},
	classBypassDNSC2:          {6, "T1071.004", "code queries DNS TXT or NULL records and decodes the answer: a DNS command channel"},
	classBypassOpenRedirect:   {3, "T1001.003", "code embeds a search-engine or trusted-site open-redirect URL that carries a non-ASCII or encoded payload: a redirect-shaped heartbeat"},
	classBypassDomainFront:    {4, "T1090.004", "a TLS client is told to send one SNI while the HTTP Host header targets a different backend: domain fronting"},
	classBypassProcHide:       {4, "T1070.004", "code unlinks /proc/self/exe or renames its own binary while still running: leaves the (deleted) suffix behind on purpose"},
}

// Class describes one finding class for the ATT&CK coverage matrix. Field names
// and tags match the sibling detectors so the matrix treats them alike.
type Class struct {
	Class       string `json:"class"`
	Technique   string `json:"technique"`
	Novel       string `json:"novel,omitempty"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
}

// Classes returns the catalog in a stable order.
func Classes() []Class {
	keys := make([]string, 0, len(catalog))
	for k := range catalog {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Class, 0, len(keys))
	for _, k := range keys {
		c := catalog[k]
		out = append(out, Class{Class: k, Technique: c.technique, Weight: c.score, Description: c.detail})
	}
	return out
}
