package tradecraft

import (
	"regexp"
	"strings"
)

// maxScriptBytes bounds the regular-expression pass. Larger text is not a
// script anyone wrote; it is data, and it still reaches the carrier decoders.
const maxScriptBytes = 4 << 20

// vector is one behaviour. Every pattern in all must match the file, so a vector
// can require a source and a sink. hint is a lower-case literal the text must
// contain, which keeps the common case to one substring search.
type vector struct {
	class string
	hint  string
	all   []*regexp.Regexp
}

func rx(p string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + p) }

func v(class, hint string, patterns ...string) vector {
	re := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		re[i] = rx(p)
	}
	return vector{class, hint, re}
}

// Shared fragments.
const (
	reqSuper  = `\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b`
	phpSink   = `(?:^|[^>\w:$])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert|eval)\s*\(`
	shellPath = `/bin/(?:ba|z|da)?sh\b|cmd\.exe|powershell\.exe`
	// socat's EXEC runs anything; only a shell makes it a network shell.
	socatShell = `['"]?(?:/\S*/)?(?:(?:ba|z|da)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?)\b`
)

var vectors = []vector{
	// ── Web shells ──
	v(classPHPRequestExec, "$_", phpSink+`\s*(?:[a-z_0-9]+\s*\(\s*)*`+reqSuper),
	// Backticks run commands in PHP, but they are also the markup of every
	// docblock, so one only counts where an expression can start.
	v(classPHPRequestExec, "$_", "(?:<\\?=|<\\?php\\s|=\\s*|\\(\\s*|\\becho\\s+|\\bprint\\s+|\\breturn\\s+)`[^`\n]{0,120}\\$_(?:GET|POST|REQUEST|COOKIE)\\b"),
	v(classPHPEvalDecode, "eval", `\b(?:eval|assert)\s*\(\s*(?:gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|rawurldecode|hex2bin|strrev)\s*\(`),
	v(classASPExec, "wscript.shell", `WScript\.Shell`, `\.(?:Exec|Run)\s*\(`, `\bRequest(?:\.Form|\.QueryString)?\s*[(.]`),
	v(classASPXExec, "<%@", `<%@\s*(?:Page|Control|WebHandler)`, `\bProcess(?:StartInfo|\.Start)\b`, `\bRequest[.\[]|\.Text\b`),
	v(classJSPExec, "getparameter", `<%`, `Runtime\.getRuntime\(\)\.exec|\bProcessBuilder\b`, `request\.getParameter`),
	v(classCFMExec, "cfexecute", `<cfexecute\b`, `#\s*(?:form|url)\.|<cfform|<form`),
	v(classCGIExec, "content", `Content-type:`, `\$ENV\{\s*['"]?QUERY_STRING|\bparam\s*\(|cgi\.FieldStorage`,
		"`[^`\n]*\\$\\w+[^`\n]*`|\\bsystem\\s*\\(|\\bexec\\s*\\(|\\bopen\\s*\\([^\\n]*\\||os\\.popen|subprocess\\."),

	// ── Network shells ──
	v(classRevShellSh, "", `(?:ba|z|da)?sh\s+-i\b[^\n]{0,80}/dev/(?:tcp|udp)/|/dev/(?:tcp|udp)/[^\n]{0,80}(?:0>&1|<&1)|&>\s*/dev/(?:tcp|udp)/|\bexec\s+\d+<>\s*/dev/(?:tcp|udp)/|\bsh\s+<&\d+\s+>&\d+|mkfifo\b[^\n]{0,120}\|\s*(?:/bin/)?(?:ba|z|da)?sh\b|\bmkfifo\b[^\n]{0,160}(?:/bin/)?sh\b[^\n]{0,60}\|\s*(?:nc|ncat|netcat|telnet|openssl\s+s_client)\b`),
	v(classRevShellTool, "", `\b(?:nc|ncat|netcat)(?:\.exe)?\b[^\n]{0,80}\s-[ec]\s+(?:["']?(?:/bin/)?(?:ba|z|da)?sh\b|["']?cmd\b|["']?powershell\b)`+
		`|\bsocat\b[^\n]{0,160}\b(?:TCP[46]?|TCP-LISTEN|OPENSSL|SSL|UDP)[:-][^\n]{0,160}\bEXEC:`+socatShell+`|\bsocat\b[^\n]{0,160}\bEXEC:`+socatShell+`[^\n]{0,160}\b(?:TCP[46]?|TCP-LISTEN|OPENSSL|SSL)[:-]`+
		`|\bcurl\b[^\n]{0,40}telnet://[^\n]{0,60}|\bsocket\s+-\w*p\s+['"]?/bin/`+
		`|\btelnet\s+\S+\s+\d+\s*(?:<[^\n|]{0,60})?\|[^\n]{0,40}sh\b|\bopenssl\s+s_client\b[^\n]{0,120}\|\s*(?:/bin/)?(?:ba|z|da)?sh\b`+
		`|(?:/bin/)?(?:ba|z|da)?sh\b[^\n|]{0,60}\|\s*(?:nc|ncat|netcat|telnet|openssl\s+s_client)\b`+
		`|\brcat\s+(?:connect|listen)\b[^\n]{0,40}\s(?:-s|--shell)\b|\bzmodload\s+zsh/net/tcp\b[^\n]{0,200}\bztcp\b`+
		`|\bxterm\s+-display\s+[\w.:-]+:\d|\bwhois\s+-h\s+\S+\s+-p\s+\d+\s+["'`+"`"+`]?\s*(?:\$\(|`+"`"+`)`+
		`|\bfinger\s+\S*@\S+\s*\|\s*(?:/bin/)?(?:ba)?sh\b`),
	v(classRevShellTool, "/inet", `/inet[46]?/(?:tcp|udp)/\d+/`, `\|&`),
	v(classRevShellPHP, "sock", `\b(?:fsockopen|pfsockopen|stream_socket_client|socket_create|socket_connect)\s*\(`,
		`\b(?:proc_open|shell_exec|passthru|popen|system|exec)\s*\(`, shellPath+`|disable_functions`),
	v(classRevShellPython, "socket", `\bsocket\.(?:socket|create_connection)\b`, `\bos\.dup2\b|\bpty\.spawn\b|\bsubprocess\.(?:Popen|call|run)\b`, shellPath),
	v(classStagerPython, "socket", `\.socket\s*\(`, `\.recv\(`, `\bexec\s*\(|\bPopen\s*\(\s*\w+\s*,\s*shell\s*=\s*True|\bos\.(?:system|popen)\s*\(\s*\w+\s*\)`),
	v(classRevShellPerl, "socket", `\buse\s+(?:IO::)?Socket\b|\bsocket\s*\(`, `\bopen\s*\(?\s*STD(?:IN|OUT|ERR)\s*,\s*["'][<>+]*&|\bexec\s*[({"']`, shellPath),
	v(classRevShellJava, "socket", `\bnew\s+(?:java\.net\.)?Socket\s*\(`, `Runtime\.getRuntime\(\)\.exec|\bProcessBuilder\b`, `getInputStream`),
	v(classRevShellPS, "getstream", `Net\.Sockets\b`, `\.GetStream\(\)`, `\biex\b|Invoke-Expression|cmd\.exe|powershell\.exe`),
	v(classRevShellRuby, "tcp", `\bTCP(?:Socket|Server)\b`, `\bexec\b|\bIO\.popen\b|\bspawn\s*\(|\bsystem\s*\(`, `\.(?:gets|accept|reopen)\b|=>\s*TCPSocket|`+shellPath),
	v(classRevShellLua, "socket", `require\s*\(?\s*["']socket["']`, `\bio\.popen\b|\bos\.execute\b`),
	v(classRevShellC, "socket", `\bsocket\s*\(`, `\bdup2\s*\(`, `\bexec[lv]p?e?\s*\(`, `/bin/(?:ba|z|da)?sh`),
	v(classRevShellC, "wsasocket", `\bWSASocket[AW]?\b`, `\bCreateProcess[AW]?\b`, `\bhStd(?:Input|Output)\b`),
	v(classRevShellManaged, "", `\bTcpClient\b|\bSocket\.connect\b|\bnet\.Dial\b|\bTcpStream::connect\b|\bnet\.(?:Socket|connect)\b|require\(\s*["']net["']\s*\)`,
		`\bProcess\.[Ss]tart\b|\bProcessStartInfo\b|\.StartInfo\b|\bexec\.Command\b|\bCommand::new\b|\bchild_process\b`,
		shellPath+`|\bRedirectStandard(?:Input|Output)\b`),
	v(classRevShellManaged, "sockets", `\busing\s+Sockets\b`, `\bconnect\s*\(`, `\brun\s*\(\s*pipeline\s*\(`),
	v(classRevShellManaged, "socket", `\[socket\s+\S+\s+\d+\]`, `\bexec\s+\$\w+`),

	// ── In-memory execution ──
	v(classMemLoader, "virtualalloc", `\bVirtualAlloc(?:Ex)?\b`, `\b(?:CreateThread|CreateRemoteThread|QueueUserAPC|NtCreateThreadEx|EnumWindows)\b`,
		`DllImport|Declare\s+(?:PtrSafe\s+)?Function|GetDelegateForFunctionPointer|Add-Type|GetProcAddress`),
	v(classReflectiveAPI, "", `Win32\.UnsafeNativeMethods|GetDelegateForFunctionPointer|DefineDynamicAssembly|DefinePInvokeMethod|GetNestedType\(\s*['"]NativeMethods`),
	v(classAssemblyLoad, "assembly", `Reflection\.Assembly\]::Load\(`, `FromBase64String|GzipStream|DeflateStream|DownloadData`),
	v(classPythonExecDecoded, "exec", `\b(?:exec|eval)\s*\([^\n]{0,200}(?:b64decode|decompress|fromhex|unhexlify|marshal\.loads)`),

	// ── Living off the land. A binary's name proves nothing, so each entry is
	// the abuse: a remote target on a binary with no business fetching one, a
	// script protocol handler, a credential dump, recovery being destroyed. The
	// weak tier is what is merely capable of proxying execution.
	v(classLOLDownload, "", `\bcertutil(?:\.exe)?\b[^\n]{0,80}[-/](?:urlcache|verifyctl)\b|\bbitsadmin(?:\.exe)?\b[^\n]{0,80}/(?:transfer|addfile)\b`+
		// Binary, switches only, then the target: prose naming a tool beside a
		// link is not a command.
		`|\b(?:mshta|regsvr32|rundll32|wscript|cscript|cmstp|msdt|mmc|pcalua|forfiles|installutil|regasm|regsvcs|msbuild|ieexec|desktopimgdownldr|expand|extrac32|esentutl|makecab|cmdl32|mpcmdrun|hh)(?:\.exe)?(?:\s+[-/]\S+){0,6}\s+["']?(?:https?://|ftp://|\\\\\d{1,3}\.\d)`),
	v(classLOLExec, "", `\brundll32(?:\.exe)?\b[^\n]{0,80}(?:javascript:|vbscript:|mshtml|advpack\.dll[^\n]{0,40}(?:RegisterOCX|LaunchINFSection)|setupapi\.dll[^\n]{0,40}InstallHinfSection|zipfldr[^\n]{0,40}RouteTheCall|shell32\.dll[^\n]{0,40}ShellExec_RunDLL|pcwutl|shdocvw)`+
		`|\bregsvr32(?:\.exe)?\b[^\n]{0,80}/i:|\bmshta(?:\.exe)?\b[^\n]{0,40}(?:vbscript:|javascript:|about:)`+
		`|\bwmic(?:\.exe)?\b[^\n]{0,120}(?:process\s+call\s+create|/format:)|\binstallutil(?:\.exe)?\b[^\n]{0,80}/logfile=`+
		`|\bcmstp(?:\.exe)?\b[^\n]{0,60}\.inf\b|\bforfiles(?:\.exe)?\b[^\n]{0,120}/c\s+["']?cmd|\bmavinject(?:\.exe)?\b[^\n]{0,60}/injectrunning`+
		`|ms-msdt:|\bmsdt(?:\.exe)?\b[^\n]{0,80}/(?:cab|af)\b|\bconhost(?:\.exe)?\b[^\n]{0,40}--headless|\bodbcconf(?:\.exe)?\b[^\n]{0,80}[/-][af]\b`+
		`|\bwuauclt(?:\.exe)?\b[^\n]{0,60}/UpdateDeploymentProvider\b|\bftp(?:\.exe)?\s+-s:|\bdnscmd(?:\.exe)?\b[^\n]{0,60}/serverlevelplugindll`),
	// url.dll,FileProtocolHandler is how scripts open a browser on Windows
	// (measured: xdg-open), so it can only corroborate.
	v(classLOLProxy, "", `\brundll32(?:\.exe)?\b[^\n]{0,80}url\.dll[^\n]{0,40}(?:OpenURL|FileProtocolHandler)`),
	v(classLOLProxy, "", `\b(?:pcalua|scriptrunner|syncappvpublishingserver|msiexec|verclsid|xwizard|ttdinject|tttracer|runscripthelper|presentationhost|dfsvc|msxsl|appvlp|bginfo|cdb|csi|rcsi|fsi|ntsd|sqlps|infdefaultinstall|atbroker|dxcap|gpscript|pnputil|diskshadow|csc|vbc|jsc|msconfig|regini|wsreset|fltmc|sdbinst|stordiag|wab|wlrmdr|remote|tar|at|schtasks|sc)(?:\.exe)\s+[-/]\S`),
	v(classLOLDump, "", `\breg(?:\.exe)?\s+save\s+["']?hklm\\(?:sam|security|system)\b|\bntdsutil(?:\.exe)?\b[^\n]{0,160}\bifm\b|\bvssadmin(?:\.exe)?\s+create\s+shadow\b`+
		`|\bcomsvcs(?:\.dll)?[^\n]{0,40}MiniDump\b|\bprocdump(?:64)?(?:\.exe)?\b[^\n]{0,60}\blsass|\besentutl(?:\.exe)?\b[^\n]{0,120}/vss\b|\bsqldumper(?:\.exe)?\b|\brdrleakdiag(?:\.exe)?\b|\bcreatedump(?:\.exe)?\b[^\n]{0,60}\s-[nfu]`),
	v(classLOLDecode, "", `\bcertutil(?:\.exe)?\b[^\n]{0,60}[-/](?:decode|decodehex|encode)\b`),
	v(classInhibitRecovery, "", `\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b|\bwbadmin(?:\.exe)?\s+delete\b|\bbcdedit(?:\.exe)?\b[^\n]{0,60}(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)`),

	// ── Evasive shell text and third-party command channels ──
	v(classDecodeExec, "", `\bbase64\s+(?:--decode|-d|-D)\b[^\n]{0,120}\|\s*(?:/bin/)?(?:ba|z|da)?sh\b|\bxxd\s+-r\b[^\n]{0,120}\|\s*(?:/bin/)?(?:ba|z|da)?sh\b|\|\s*rev\s*\|\s*(?:/bin/)?(?:ba|z|da)?sh\b`),
	v(classGlobObfuscation, "", `(?:^|[\s;|&(])/[?*]{1,3}/(?:[a-z]*[?*]+[a-z?*]*/)*[a-z]*[?*]+[a-z?*]*|[a-z]\$\{IFS\}[/\w$-]|\$IFS\$\d`),
	// A command channel is a named third-party service, so this is the one place
	// a literal host list is the right shape: the service is the indicator. Four
	// groups — chat webhooks, reverse tunnels, paste/file drops and out-of-band
	// interaction hosts — all score low, because naming one corroborates and does
	// not convict. Kept out on purpose: raw.githubusercontent, gist, s3 and the
	// like, which carry far more benign traffic than malicious.
	v(classC2Service, "",
		// Chat / webhook sinks.
		`discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/`+
			`|hooks\.zapier\.com/|\.ifttt\.com/trigger/|chat\.googleapis\.com/v1/spaces`+
			`|\.webhook\.office\.com/|outlook\.office\.com/webhook|open\.feishu\.cn/open-apis/bot`+
			`|qyapi\.weixin\.qq\.com/cgi-bin/webhook|oapi\.dingtalk\.com/robot/send|\bhookbin\.com\b|\.webhookrelay\.com\b`+
			// Reverse tunnels / ingress brokers.
			`|\.trycloudflare\.com|\.cfargotunnel\.com|\.ngrok(?:-free)?\.(?:io|app|dev)\b|\.serveo\.net|\.loca\.lt\b`+
			`|\.pinggy\.(?:io|link)\b|\.lhr\.life\b|\blocalhost\.run\b|\.bore\.pub\b|\.tunnelmole\.|\.telebit\.io\b`+
			`|\.packetriot\.(?:net|com)\b|\.loophole\.site\b|\.devtunnels\.ms\b|\.githubpreview\.dev\b|\.app\.github\.dev\b`+
			`|\.pagekite\.me\b|\.portmap\.(?:io|host)\b|\.tunnelto\.dev\b|\.localxpose\.io\b|\.loclx\.io\b|\.zrok\.io\b`+
			`|\.expose\.sh\b|\.sharedwithexpose\.com\b|\.jprq\.(?:io|live)\b`+
			// Paste / file drops.
			`|pastebin\.com/raw|paste\.ee/r/|\brentry\.co/|\bhastebin\.com/raw|\bhasteb\.in/|ghostbin\.(?:co|com)`+
			`|\b0x0\.st\b|\btermbin\.com\b|\bix\.io\b|\bdpaste\.(?:com|org)\b|\bcontrolc\.com\b|\bjustpaste\.it\b`+
			`|\bfile\.io\b|\bgofile\.io\b|\btemp\.sh\b|\boshi\.at\b|\bbashupload\.com\b|\bcatbox\.moe\b|\buguu\.se\b`+
			`|\bkeep\.sh\b|\bx0\.at\b|\btransfer\.sh\b|\bfiletransfer\.io\b|\btmpfiles\.org\b`+
			// Out-of-band interaction / request catchers.
			`|webhook\.site|\.interact\.sh\b|\.oast\.(?:pro|live|fun|site|online|me)\b|\.burpcollaborator\.net`+
			`|\bdnslog\.cn\b|\.ceye\.io\b|\brequestbin\b|\.pipedream\.net\b|\.requestcatcher\.com\b|\.beeceptor\.com\b`+
			`|\bmockbin\.(?:io|org)\b`),

	// ── PowerShell and Windows script tradecraft ──
	v(classAMSIBypass, "amsi", `AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsiContext`),
	v(classDownloadExec, "", `(?:\biex\b|Invoke-Expression)[^\n]{0,200}(?:DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)|(?:DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)[^\n]{0,200}\|\s*(?:iex|Invoke-Expression)\b`),
	v(classDecodeExec, "", `(?:\biex\b|Invoke-Expression)[^\n]{0,400}(?:FromBase64String|GzipStream|DeflateStream|SecureStringToBSTR)|(?:FromBase64String|GzipStream|DeflateStream)[^\n]{0,400}\|\s*(?:iex|Invoke-Expression)\b`),
	v(classCredAccess, "", `MiniDumpWriteDump|LsaEnumerateLogonSessions|LsaRetrievePrivateData|SamIConnect|\bcpassword\b|SECURITY\\Policy\\Secrets|UseLogonCredential|CredEnumerate|VaultEnumerate|PasswordVault\b|CryptUnprotect(?:Data|Memory)|ProtectedData\]::Unprotect|Win32_ShadowCopy|lsass(?:\.exe)?\b`),
	v(classTokenTheft, "", `\b(?:ImpersonateLoggedOnUser|DuplicateTokenEx|DuplicateToken|SetThreadToken|CreateProcessWithToken[AW]?|CreateProcessWithLogon[AW]?)\b`),
	v(classKeylogger, "", `\b(?:GetAsyncKeyState|SetWindowsHookEx[AW]?|GetKeyboardState)\b`, `\b(?:GetForegroundWindow|CallNextHookEx|GetWindowText[AW]?)\b`),
	v(classCapture, "", `\b(?:CopyFromScreen|mciSendString|waveInOpen)\b`),
	v(classLateral, "", `Win32_Process\b[^\n]{0,120}\bCreate\b|Invoke-WmiMethod[^\n]{0,160}\bCreate\b|\bOpenSCManager[AW]?\b`),
	v(classDefenseEvasion, "", `Set-MpPreference\s+-Disable|Add-MpPreference\s+-Exclusion|\bwevtutil(?:\.exe)?\s+cl\b|\bClear-EventLog\b|\bRemove-EventLog\b|\bauditpol(?:\.exe)?\s+/clear`),
	v(classDefenseEvasion, "eventlog", `\bTerminateThread\b`, `\beventlog\b`),
	v(classPersistence, "", `CurrentVersion\\Run\b|\bRegister-ScheduledTask\b|\bschtasks(?:\.exe)?\s+/create|Lsa\\?[^\n]{0,40}Security Packages|\bCreateShortcut\b`),
	v(classTimestomp, "", `\.(?:LastWriteTime|CreationTime|LastAccessTime)\s*=[^=]|SetFileTime\b`),
	v(classObfuscation, "", `-join\s*\[char|\[char\]\s*\d+\s*\+\s*\[char\]|-bxor\b|\[char\[\]\]\s*\(|\$env:comspec\[`),
	v(classProxy, "", `Net\.Sockets\b`, `\.Bind\(|AcceptTcpClient|\.BeginAccept\b|\.Listen\(`),
	v(classDCOMExec, "", `\bExecuteShellCommand\b|\bShellBrowserWindow\b|MMC20\.Application`, `\bGetTypeFromProgID\b|\bGetTypeFromCLSID\b|\bCreateInstance\b|\.Document\.`),
	v(classSQLShell, "xp_cmdshell", `sp_configure\b[^\n]{0,40}xp_cmdshell|\bexec(?:ute)?\s+(?:master\.+)?xp_cmdshell\b`),
	v(classGPPSecrets, "sysvol", `SYSVOL`, `\bcpassword\b|DefaultPassword`),
	v(classNTLMCraft, "ntlm", `NTLMSSP|HMACMD5|NTLM_hash`),
	v(classHiddenExec, "", `-WindowStyle\s+Hidden|\s-w(?:in)?\s+hidden\b`),
}

func (w *walker) scanScript(text, origin string) {
	if len(text) > maxScriptBytes {
		text = text[:maxScriptBytes]
	}
	lower := strings.ToLower(text)
	for _, vec := range vectors {
		if vec.hint != "" && !strings.Contains(lower, vec.hint) {
			continue
		}
		evidence := ""
		matched := true
		for i, re := range vec.all {
			loc := re.FindStringIndex(text)
			if loc == nil {
				matched = false
				break
			}
			if i == 0 {
				evidence = trunc(text[loc[0]:loc[1]], 120)
			}
		}
		if matched {
			w.add(vec.class, catalog[vec.class], origin, evidence)
		}
	}
	if strings.Contains(lower, "$_") {
		if ev := phpTaint(text); ev != "" {
			w.add(classPHPTaintExec, catalog[classPHPTaintExec], origin, ev)
		}
	}
}

var (
	phpAssign  = regexp.MustCompile(`\$(\w+)\s*=\s*([^;\n]{0,400})`)
	phpSinkArg = rx(phpSink + `([^;\n]{0,300})`)
	phpVar     = regexp.MustCompile(`\$(\w+)`)
	phpRequest = rx(reqSuper)
)

// phpTaint follows request input through assignments to an exec sink, for the
// shape `$c = $_GET['x']; system($c);` that a same-expression check misses. The
// walk is textual, not a parser: it ignores scope and sanitisers, so a line that
// launders input through escapeshellarg still reports. That is the right way to
// be wrong here, because the sink running attacker-shaped input is the finding.
func phpTaint(text string) string {
	tainted := map[string]bool{}
	assigns := phpAssign.FindAllStringSubmatch(text, 4096)
	for pass := 0; pass < 3; pass++ {
		for _, a := range assigns {
			if tainted[a[1]] {
				continue
			}
			rhs := a[2]
			hit := phpRequest.MatchString(rhs)
			for _, m := range phpVar.FindAllStringSubmatch(rhs, -1) {
				hit = hit || tainted[m[1]]
			}
			if hit {
				tainted[a[1]] = true
			}
		}
	}
	if len(tainted) == 0 {
		return ""
	}
	for _, m := range phpSinkArg.FindAllStringSubmatch(text, 1024) {
		for _, va := range phpVar.FindAllStringSubmatch(m[1], -1) {
			if tainted[va[1]] {
				return trunc(m[0], 120)
			}
		}
	}
	return ""
}
