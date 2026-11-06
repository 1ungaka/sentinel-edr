package tradecraft

// This file extends the tradecraft catalog with behaviour drawn from the
// living-off-the-land projects the engine already leans on elsewhere:
//
//   - GTFOBins (https://gtfobins.github.io): Unix binaries whose own features
//     break a shell out, or escalate when they run as root. The signal is the
//     escape syntax, not the binary's name, so a benign `find -exec rm` or a
//     plain `sudo sh -c` matches nothing.
//
//   - LOLBAS (https://lolbas-project.github.io): Windows system binaries that
//     fetch or proxy execution. These add the shapes missing from the main
//     lolbin vectors in script.go.
//
//   - revshells / HackTricks reverse-shell corpora: a few socket-to-shell
//     shapes the netshell vectors did not yet carry.
//
// Everything registers through init so the single scanScript loop over `vectors`
// and the single `catalog` map stay authoritative; nothing here changes how a
// match is scored or reported.

// Unix living-off-the-land (GTFOBins) finding classes.
const (
	classGTFOShell = "tradecraft.gtfobins.shell-breakout"
	classGTFOSudo  = "tradecraft.gtfobins.sudo-privesc"
	classGTFOSUID  = "tradecraft.gtfobins.suid-privesc"
)

func init() {
	// A shell breakout on its own is evidence, not a verdict: a pentester's tty
	// upgrade and a restricted-shell escape share the same syntax. Running one of
	// these as root (sudo) or off a setuid bit is the privilege boundary being
	// crossed, so those convict alone.
	catalog[classGTFOShell] = catalogEntry{6, "T1059.004", "a utility is driven to break out an interactive shell: a GTFOBins editor, pager, debugger or interpreter escape"}
	catalog[classGTFOSudo] = catalogEntry{8, "T1548.003", "a utility is run under sudo with a shell-spawning argument: GTFOBins sudo privilege escalation"}
	catalog[classGTFOSUID] = catalogEntry{8, "T1548.001", "a setuid breakout: a privileged shell kept with -p, or the setuid bit being set on a shell"}

	vectors = append(vectors, extraVectors...)
}

// gtfoBreak is the set of shell-spawning idioms a GTFOBins entry uses, the thing
// that makes `sudo <binary>` a root shell. Each is specific enough that an
// ordinary invocation of the same tool does not match.
const gtfoBreak = `-exec\s+(?:/usr/bin/|/bin/)?(?:ba|z|da)?sh\b` +
	`|BEGIN\s*\{\s*system\s*\(` +
	`|--interactive\b` +
	`|--checkpoint-action=exec` +
	`|-c\s*['"]?\s*:?!\s*(?:/bin/)?(?:ba|z|da)?sh` +
	`|-ex\s*['"]?\s*!\s*(?:/bin/)?(?:ba|z|da)?sh` +
	`|os\.system\(\s*['"]/bin/` +
	`|pty\.spawn\(\s*['"]?/bin/` +
	`|\bexec\s+['"]/bin/(?:ba|z|da)?sh` +
	`|/bin/(?:ba|z|da)?sh\s+-p\b`

var extraVectors = []vector{
	// ── GTFOBins: sudo privilege escalation ──
	// sudo on the same line as a shell-spawning idiom. Plain `sudo sh -c`,
	// `sudo -i`, `sudo <pkg-manager> install` carry none of these.
	v(classGTFOSudo, "sudo", `\bsudo\b[^\n]{0,160}?(?:`+gtfoBreak+`)`),

	// ── GTFOBins: setuid breakouts ──
	// A shell asked to keep its effective uid (-p), explicitly pathed or reached
	// through find -exec, is the setuid escalation idiom; `ssh -p 22` has no path
	// and does not match.
	v(classGTFOSUID, "-p", `(?:-exec\s+(?:/(?:usr/)?bin/)?|/(?:usr/)?bin/)(?:ba|z|da)?sh\s+-p\b`),
	// Building a setuid shell: the setuid bit set on a shell, a copied shell in a
	// world-writable directory, or a name like rootbash. `chmod 755`, `chmod +s`
	// on a non-shell, and four-digit modes without the setuid bit do not match.
	v(classGTFOSUID, "chmod", `\bchmod\s+(?:[ugoa]*\+s|[0-7]*[4-7][0-7]{3})\b[^\n]{0,80}(?:/bin/(?:ba|z|da)?sh|/tmp/\S*(?:ba|z|da)?sh|/dev/shm/\S*(?:ba|z|da)?sh|rootbash|rootsh)`),

	// ── GTFOBins: restricted-shell / interpreter breakouts (no privilege needed) ──
	v(classGTFOShell, ":!", `:!\s*(?:/bin/|/usr/bin/)?(?:ba|z|da)?sh\b`),                                                       // vi/vim/ex/less bang-escape
	v(classGTFOShell, "pty.spawn", `\bpty\.spawn\(\s*['"]?(?:/bin/|/usr/bin/)?(?:ba|z|da)?sh\b`),                               // python tty shell
	v(classGTFOShell, "--interactive", `\bnmap\b[^\n]{0,40}--interactive\b`),                                                   // nmap interactive mode
	v(classGTFOShell, "awk", `\b[gmn]?awk\b[^\n]{0,60}BEGIN\s*\{\s*system\s*\(\s*['"](?:/bin/)?(?:ba|z|da)?sh`),                // awk BEGIN{system("/bin/sh")}
	v(classGTFOShell, "gdb", `\bgdb\b[^\n]{0,80}-(?:ex|eval-command)\s*['"]?\s*(?:!\s*(?:/bin/)?(?:ba|z|da)?sh|shell\b)`),      // gdb -ex '!sh' / shell
	v(classGTFOShell, "exec", `\b(?:perl|ruby)\b[^\n]{0,40}\s-e\s*['"][^\n'"]{0,80}\bexec\s*['"(]?\s*['"]/bin/(?:ba|z|da)?sh`), // perl/ruby -e 'exec "/bin/sh"'

	// ── Additional reverse / bind shells ──
	// BusyBox telnetd exposing a shell, and socat's SYSTEM: address (a sibling of
	// the EXEC: forms the netshell vector already carries).
	v(classRevShellTool, "telnetd", `\btelnetd\b[^\n]{0,60}-l\s+(?:/bin/)?(?:ba|z|da)?sh\b`),
	v(classRevShellTool, "socat", `\bsocat\b[^\n]{0,160}\b(?:TCP[46]?|TCP-LISTEN|OPENSSL|SSL|UDP)[:-][^\n]{0,160}\bSYSTEM:`+socatShell+
		`|\bsocat\b[^\n]{0,160}\bSYSTEM:`+socatShell+`[^\n]{0,160}\b(?:TCP[46]?|TCP-LISTEN|OPENSSL|SSL)[:-]`),

	// ── Windows LOLBAS: remote-payload download, shapes missing from script.go ──
	v(classLOLDownload, "certreq", `\bcertreq(?:\.exe)?\b[^\n]{0,80}-Post\b[^\n]{0,80}https?://`),
	v(classLOLDownload, "gfxdownloadwrapper", `\bGfxDownloadWrapper(?:\.exe)?\b[^\n]{0,120}https?://`),
	v(classLOLDownload, "imewdbld", `\bimewdbld(?:\.exe)?\b[^\n]{0,80}https?://`),
	v(classLOLDownload, "appinstaller", `ms-appinstaller:[^\n]{0,80}https?://|\bAppInstaller(?:\.exe)?\b[^\n]{0,80}https?://`),
	v(classLOLDownload, "diantz", `\bdiantz(?:\.exe)?\b[^\n]{0,80}\\\\\d{1,3}\.`),

	// ── Windows LOLBAS: proxy execution, shapes missing from script.go ──
	v(classLOLExec, "workflow.compiler", `\bMicrosoft\.Workflow\.Compiler(?:\.exe)?\s+\S`),
	v(classLOLExec, "agentexecutor", `\bAgentExecutor(?:\.exe)?\b[^\n]{0,40}-powershell\b`),
	v(classLOLExec, "register-cimprovider", `\bRegister-CimProvider\b[^\n]{0,80}-(?:Path|DLL)\b[^\n]{0,60}\.dll`),
	v(classLOLExec, "devinit", `\bdevinit(?:\.exe)?\b[^\n]{0,80}(?:https?://|-t\s+\S+-install)`),
	v(classLOLExec, "tracker", `\btracker(?:\.exe)?\b[^\n]{0,60}/d\b[^\n]{0,60}\.dll`),
	v(classLOLExec, "mftrace", `\bmftrace(?:\.exe)?\b[^\n]{0,40}(?:cmd|powershell|\.exe)`),
	v(classLOLExec, "protocolhandler", `\bProtocolHandler(?:\.exe)?\b[^\n]{0,40}["']?\S+\.(?:docx?|url|htm)`),

	// ── Windows LOLBAS: more binaries merely capable of proxying execution ──
	// Weak tier: corroborating only. The `.exe` suffix is required, as in the
	// sibling vector, so a bare Unix `winget`/`wt` in prose does not match.
	v(classLOLProxy, "", `\b(?:ie4uinit|CustomShellHost|pcwrun|workfolders|settingsynchost|onedrivestandaloneupdater|winget|wt|provlaunch|offlinescannershell|dmcertinst)(?:\.exe)\s+[-/]?\S`),
}
