package tradecraft

// This file catches the specific evasion primitives the engine would
// otherwise miss. Each entry is drawn from the ArcticFox detection-bypass
// catalogue (docs/Detection-Bypasses.md): for every evasion technique the
// doc describes, a pattern below fires on the code that implements it.
//
// The design keeps the "describe what the code does, not what it's named"
// contract: naming a bypass is prose; carrying the API pairing is the
// finding. So ld.so.preload alone is nothing, but opening and writing it
// is a shim install; memfd_create alone is nothing, but calling it beside
// execveat / fexecve is an anonymous in-memory executable.

func init() {
	vectors = append(vectors, bypassVectors...)
}

const (
	memfdCreate = `\bmemfd_create\s*\(|syscall\s*\(\s*(?:SYS_memfd_create|319)\b|\bNR_memfd_create\b|\.memfd_create\(`
	memfdRun    = `\bfexecve\s*\(|\bexecveat\s*\(|AT_EMPTY_PATH|/proc/self/fd/\d|/proc/\$\$/fd/|\bProcess\s*::\s*fexecve\b`
)

// near matches a and b within a screenful of each other, in either order.
func near(a, b string) string {
	const gap = `[\s\S]{0,800}`
	return `(?:` + a + `)` + gap + `(?:` + b + `)|(?:` + b + `)` + gap + `(?:` + a + `)`
}

var bypassVectors = []vector{
	// ── Anonymous in-memory exec: memfd_create / shm_open paired with a
	// loader that runs the resulting fd. Either exec primitive alone is a
	// legitimate pattern used by Go's os.CreateTemp, Python shared memory,
	// or systemd notify sockets, so the pairing is what counts.
	// A loader makes both calls together. Over a whole file the pairing means
	// nothing: a changelog or API reference names both, far apart (measured:
	// nix's CHANGELOG), so the two must sit close in either order.
	v(classBypassMemFD, "memfd_create", near(memfdCreate, memfdRun)),
	v(classBypassMemFD, "shm_open", near(`\bshm_open\s*\(`, `\bfexecve\s*\(|/proc/self/fd/\d|execveat\b`)),

	// ── Kernel-level process-name camouflage: the prctl(PR_SET_NAME, ...)
	// call reaches into the kernel's /proc comm field. Benign on its own
	// (Go's runtime uses it), suspicious when paired with a socket or exec
	// in the same file.
	v(classBypassProcRename, "pr_set_name",
		`\bprctl\s*\(\s*(?:PR_SET_NAME|15)\b`,
		`\bsocket\s*\(\s*(?:AF_INET|PF_INET|AF_INET6|PF_INET6|AF_PACKET)|\bexecve\s*\(|\bconnect\s*\(|\bdup2\s*\(|\bchild_subreaper\b|\bsshd\b|\bkworker\b|\bsystemd-`),

	// ── Writing /etc/ld.so.preload or resolving through RTLD_NEXT: the
	// classic shared-library hook. Reading the file is integrity checking;
	// writing it is installing a shim.
	v(classBypassLDPreload, "ld.so.preload",
		`(?:open|openat|fopen)\s*\(\s*['"]/etc/ld\.so\.preload['"]|>\s*/etc/ld\.so\.preload\b|\becho\s+[^|&;\n]{0,160}\s*>>\s*/etc/ld\.so\.preload\b`),
	v(classBypassLDPreload, "rtld_next",
		`\bdlsym\s*\(\s*RTLD_NEXT\b|\bRTLD_NEXT\b.{0,80}\bdlsym\b`),
	v(classBypassLDPreload, "dt_runpath",
		`\bDT_RUNPATH\b.{0,120}(?:patchelf|binary_patch|ElfW\(Dyn\)|\.dynamic|elfedit)`),

	// ── PAM-stack backdoor: either adding pam_exec.so (optionally with
	// expose_authtok, which captures the user's cleartext password) to any
	// pam.d file, or replacing pam_unix.so wholesale.
	v(classBypassPAMBackdoor, "pam_exec",
		`(?:>>?|\btee\b|\bprintf\b|\bcat\s*<<)\s*(?:/etc/)?pam\.d/\S+\b[^\n]{0,200}\bpam_exec\.so\b|\bpam_exec\.so\b[^\n]{0,80}\bexpose_authtok\b`),
	v(classBypassPAMBackdoor, "pam_unix",
		`\bcp\s+\S+\s+/(?:usr/)?lib(?:64|/x86_64-linux-gnu)?/security/pam_unix\.so\b|\binstall\s+(?:-m\s+\d+\s+)?\S+\s+/(?:usr/)?lib(?:64|/x86_64-linux-gnu)?/security/pam_unix\.so\b`),

	// ── Systemd unit hijack: either editing an existing service with --full
	// (dangerous; replaces upstream content), dropping an override.conf under
	// a known service's .service.d/, or using systemd-run --user to persist
	// as a non-systemctl-listed user timer.
	v(classBypassSystemdHijack, "systemctl edit",
		`\bsystemctl\s+edit\s+--full\s+(?:sshd|systemd-logind|cron|rsyslog|dbus|NetworkManager|docker|containerd|snapd)\b`),
	v(classBypassSystemdHijack, ".service.d/",
		`/etc/systemd/system/(?:sshd|systemd-logind|cron|rsyslog|dbus|NetworkManager|docker|containerd|snapd)\.service\.d/[\w-]+\.conf\b`),
	v(classBypassSystemdHijack, "systemd-run --user",
		`\bsystemd-run\s+(?:[^\n]*\s)?--user\s+(?:[^\n]*\s)?--on-(?:unit-active-sec|calendar|boot-sec)\b`),

	// ── Self-delete artefacts: unlinking /proc/self/exe is uniquely the
	// "keep running, erase me from disk" pattern. unlink("<argv0>") paired
	// with a running daemon is weaker; "remove the (deleted) suffix forensic"
	// is explicitly what the bypass doc names.
	v(classBypassSelfDelete, "/proc/self/exe",
		`\bunlink(?:at)?\s*\(\s*(?:AT_FDCWD\s*,\s*)?['"]/proc/self/exe['"]|\bremove\s*\(\s*['"]/proc/self/exe['"]`),
	v(classBypassProcHide, "/proc/self/exe",
		`\bdd\s+if=/dev/zero\s+of=/proc/self/exe\b|\brename\s*\(\s*\w+,\s*['"]/tmp/\.[\w.-]+['"]\s*\)[^\n]{0,80}\bunlink\s*\(`),

	// ── GitHub dead-drop: reading a README (or a release asset) from the
	// Contents API or raw.githubusercontent, paired with cache-busting
	// query params — a regular viewer never adds `?nocache=` and `&t=`.
	v(classBypassGithubDeadDrop, "githubusercontent",
		`\braw\.githubusercontent\.com/[\w.-]+/[\w.-]+/[\w./-]+?\?(?:nocache|t|ts|_)=`),
	v(classBypassGithubDeadDrop, "api.github.com/repos",
		`api\.github\.com/repos/[\w.-]+/[\w.-]+/contents/[\w.-]+\.md\?(?:nocache|t|ts|ref|_)=`),

	// ── ICMP covert channel: a raw ICMP socket or BPF read, then marshalling
	// an echo payload. Legitimate `ping` uses the cap_net_raw bit but doesn't
	// decode/encode payloads at script level.
	v(classBypassICMPC2, "ipproto_icmp",
		`\bsocket\s*\(\s*(?:\w+\.)?(?:AF_INET|PF_INET|AF_INET6|PF_INET6)\s*,\s*(?:\w+\.)?SOCK_RAW\s*,\s*(?:\w+\.)?(?:IPPROTO_ICMP|IPPROTO_ICMPV6)\b`,
		`(?:struct\s+)?icmp(?:hdr|6_hdr)\b|\bicmp_echo\b|ICMP_ECHO\b|ICMP_ECHOREPLY\b|type\s*=\s*8\b`),
	v(classBypassICMPC2, "sock_raw",
		`\bSOCK_RAW\b.{0,100}(?:ICMP|htons\(\s*0x0800|AF_PACKET)|\bSO_BINDTODEVICE\b`,
		`\bbase64\.(?:b64decode|b64encode)|xor_?decode|_xor\b|chr\(\s*\w+\s*\^|\bpayload\[\s*\d+\s*\]`),

	// ── DNS covert channel: TXT/NULL query shaped to carry data, followed by
	// a decode step. Benign scripts read TXT records for SPF/DKIM but don't
	// decode the answer; a decode pipeline is what the C2 does.
	v(classBypassDNSC2, "dns.resolver",
		`\bdns\.resolver\.resolve\s*\(\s*\w+\s*,\s*['"](?:TXT|NULL|CNAME)['"]`,
		`\bbase64\.(?:b64decode|b32decode)|\.strings\b[^\n]{0,80}\bdecode|\bhex2bin\b|\bbinascii\.unhexlify\b`),
	v(classBypassDNSC2, "rdatatype",
		`qtype\s*=\s*(?:dns\.rdatatype\.TXT|dnstypes\.TXT|16\b)`,
		`\bbase64\.(?:b64decode|b32decode)|\bbinascii\.unhexlify\b`),
	v(classBypassDNSC2, "dig",
		`\bdig\s+(?:[+\-]\S+\s+){0,4}(?:TXT|NULL|CNAME)\s+\S+\b[^\n]{0,200}\|\s*[^\n|]*\b(?:base64\s+-d|base64\s+--decode|xxd\s+-r|openssl\s+(?:enc|base64)\s+-d|tr\s+-d\s+'"')`),

	// ── Open-redirect heartbeat: a hard-coded search-engine or trusted-site
	// redirector URL whose query carries a non-ASCII payload. Zero-width
	// characters in the URL are a strong hint — the stego pass detects them
	// in raw text, this one detects the *URL shape* code assembles.
	v(classBypassOpenRedirect, "google.com/url",
		`https?://(?:www\.)?google\.com/url\?[^"\n]{0,160}[\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}]`+
			`|https?://(?:www\.)?bing\.com/search\?[^"\n]{0,160}[\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}]`+
			`|https?://(?:www\.)?duckduckgo\.com/\?[^"\n]{0,160}[\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}]`),

	// ── Domain fronting: a static declaration where SNI and the HTTP Host
	// disagree. In Python's `requests`/`httpx` this is the ServerName / Host
	// header pair; in Go it's a custom tls.Config with ServerName set and a
	// different Host in the request.
	v(classBypassDomainFront, "servername",
		`(?:ServerName|tls\.ServerName|server_hostname)\s*[:=]\s*['"][^'"\n]+['"]`,
		`(?:['"]Host['"]\s*:\s*['"][^'"\n]+['"]|req\.Host\s*=\s*['"][^'"\n]+['"]|\bHost\s*=\s*['"][^'"\n]+['"])`),
}
