package linuxpkg

import (
	"regexp"
	"strings"
	"sync"

	"github.com/s-b-repo/cau/internal/intel"
	"github.com/s-b-repo/cau/internal/parallel"
	"github.com/s-b-repo/cau/internal/prefilter"
)

// ── ATT&CK technique ids ───────────────────────────────────────────────────────
//
// Every vector here is evidence that a package's install-time script — which the
// package manager runs as root — carries behaviour that a legitimate maintainer
// script almost never needs. The framing technique is the software supply-chain
// compromise (T1195.002): the trust a user places in "apt/dnf/pacman install"
// is what the payload rides in on.
const (
	techSupplyChain   = "T1195.002" // Supply Chain Compromise: Compromise Software Supply Chain
	techUnixShell     = "T1059.004" // Command and Scripting Interpreter: Unix Shell
	techIngressTool   = "T1105"     // Ingress Tool Transfer (curl/wget fetch)
	techDeobfuscate   = "T1140"     // Deobfuscate/Decode Files or Information
	techObfuscated    = "T1027"     // Obfuscated Files or Information
	techSystemd       = "T1543.002" // Create or Modify System Process: Systemd Service
	techCron          = "T1053.003" // Scheduled Task/Job: Cron
	techShellConfig   = "T1546.004" // Event Triggered Execution: Unix Shell Configuration Modification
	techSSHKeys       = "T1098.004" // Account Manipulation: SSH Authorized Keys
	techSudo          = "T1548.003" // Abuse Elevation Control Mechanism: Sudo and Sudo Caching
	techFilePerms     = "T1222.002" // File and Directory Permissions Modification: Linux
	techIndicatorRm   = "T1070"     // Indicator Removal (anti-forensics)
	techImpairDefense = "T1562.001" // Impair Defenses: Disable or Modify Tools
	techResourceHijak = "T1496"     // Resource Hijacking (cryptominer)
	techReverseShell  = "T1571"     // Non-Standard Port / reverse connection
)

// vector is one install-script threat pattern. A match raises its finding at
// most once per package (classes de-duplicate), so Result.Score is the sum of
// the distinct behaviours observed, not the number of lines that matched.
type vector struct {
	class     string
	score     int
	technique string
	detail    string
	re        *regexp.Regexp
}

// scriptVectors is the catalog of install-script behaviours, ordered strongest
// first. Weights are tuned against the sibling detectors (default threshold 8):
// a single "pipe a remote download straight into a shell" or a reverse-shell
// one-liner crosses the bar alone, because in a package maintainer script those
// are near-certain malice; the softer persistence/permission tells score low and
// must corroborate (with each other, or via the fusion lattice) to cross.
//
// The patterns are deliberately conservative. A legitimate postinst that runs
// ldconfig, update-alternatives, systemctl daemon-reload, update-desktop-database
// or adduser --system matches nothing here.
var scriptVectors = []vector{
	{
		class: "linuxpkg.script.curl-pipe-shell", score: 8, technique: techIngressTool,
		detail: "downloads a remote resource and pipes it straight into a shell interpreter",
		re:     regexp.MustCompile(`(?i)\b(?:curl|wget|fetch)\b[^|&;` + "`" + `\n]{0,400}?\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|da)?sh\b`),
	},
	{
		class: "linuxpkg.script.reverse-shell", score: 9, technique: techReverseShell,
		detail: "contains a reverse / bind shell one-liner (interpreter bound to a network socket)",
		re:     regexp.MustCompile(`(?i)(?:/dev/(?:tcp|udp)/|\b(?:nc|ncat|netcat)\b[^\n` + "`" + `]{0,80}?\s-e\b|\bsh\s+-i\b[^\n]{0,80}?(?:>&|<>)\s*/dev/tcp|mkfifo\b[^\n]{0,120}?\|\s*(?:/bin/)?(?:ba)?sh\b)`),
	},
	{
		class: "linuxpkg.script.decode-exec", score: 8, technique: techDeobfuscate,
		detail: "decodes an encoded blob (base64/xxd/openssl) and executes or evaluates the result",
		re:     regexp.MustCompile(`(?i)(?:\bbase64\s+(?:--decode|-d|-D)\b[^\n` + "`" + `]{0,120}?\|\s*(?:/bin/)?(?:ba)?sh\b|\bxxd\s+-r\b[^\n]{0,120}?\|\s*(?:ba)?sh\b|\beval\s+"?\$\((?:echo|printf)[^\n]{0,200}?base64)`),
	},
	{
		class: "linuxpkg.script.cryptominer", score: 8, technique: techResourceHijak,
		detail: "references a cryptocurrency miner (xmrig / stratum pool / donate-level)",
		re:     regexp.MustCompile(`(?i)(?:\bxmrig\b|stratum\+(?:tcp|ssl)://|--donate-level\b|\bminerd\b|\bcpuminer\b)`),
	},
	{
		class: "linuxpkg.script.ssh-authorized-keys", score: 8, technique: techSSHKeys,
		detail: "writes an SSH public key into an authorized_keys file (backdoor access)",
		re:     regexp.MustCompile(`(?i)(?:>>?\s*\S*\.ssh/authorized_keys|authorized_keys\b[^\n]{0,60}?(?:ssh-(?:rsa|ed25519|dss)|echo))`),
	},
	{
		class: "linuxpkg.script.sudoers", score: 6, technique: techSudo,
		detail: "edits sudoers / drops a NOPASSWD rule (persistent privilege escalation)",
		re:     regexp.MustCompile(`(?i)(?:>>?\s*/etc/sudoers|/etc/sudoers\.d/|\bNOPASSWD\s*:\s*ALL)`),
	},
	{
		class: "linuxpkg.script.download-exec", score: 8, technique: techIngressTool,
		detail: "downloads a file, makes it executable and runs it",
		re:     regexp.MustCompile(`(?i)\b(?:curl|wget|fetch)\b[^\n` + "`" + `]{0,300}?(?:-o|-O|>)[^\n]{0,120}?(?:/tmp/|/dev/shm/|/var/tmp/)[^\n]{0,400}?chmod\s+[+0-7x]*x`),
	},
	{
		class: "linuxpkg.script.disable-defenses", score: 5, technique: techImpairDefense,
		detail: "disables a host security control (firewall, AppArmor/SELinux, antivirus)",
		re:     regexp.MustCompile(`(?i)(?:setenforce\s+0|\bsystemctl\s+(?:stop|disable|mask)\s+(?:ufw|firewalld|apparmor|clamav|auditd)|\bufw\s+disable\b|aa-complain\b|iptables\s+-F\b)`),
	},
	{
		class: "linuxpkg.script.anti-forensics", score: 4, technique: techIndicatorRm,
		detail: "clears shell history or sets immutable/anti-forensic flags",
		re:     regexp.MustCompile(`(?i)(?:\bhistory\s+-c\b|unset\s+HISTFILE|\bHISTFILE=/dev/null|\bchattr\s+[+][^\n]{0,20}?i\b|shred\s+-u\b)`),
	},
	{
		class: "linuxpkg.script.setuid-payload", score: 4, technique: techFilePerms,
		detail: "sets a setuid/setgid bit on a file (privilege-escalation payload)",
		re:     regexp.MustCompile(`(?i)\bchmod\s+(?:[ug]?\+s|[0-7]?[4-7][0-7]{3})\b`),
	},
	{
		class: "linuxpkg.script.suspicious-url", score: 4, technique: techIngressTool,
		detail: "fetches from a paste/shortener host or a bare IP-literal URL",
		re:     regexp.MustCompile(`(?i)https?://(?:(?:pastebin|paste\.ee|ghostbin|hastebin|transfer\.sh|termbin|0x0\.st|bit\.ly|tinyurl|is\.gd)\b|(?:\d{1,3}\.){3}\d{1,3}(?:[:/]))`),
	},
	{
		class: "linuxpkg.script.obfuscated", score: 4, technique: techObfuscated,
		detail: "contains a long encoded blob or a heavily obfuscated eval chain",
		re:     regexp.MustCompile("(?:[A-Za-z0-9+/]{220,}={0,2}|(?i)eval\\s+\"?\\$\\([^\\n]{0,40}?(?:rev|tr\\s|sed\\s)[^\\n]{0,200}?\\))"),
	},
	{
		class: "linuxpkg.script.systemd-persistence", score: 3, technique: techSystemd,
		detail: "installs or enables a systemd unit from within the install script",
		re:     regexp.MustCompile(`(?i)(?:>\s*/etc/systemd/system/\S+\.service|cat\s*>[^\n]{0,80}?\.service\b|\bsystemctl\s+enable\b[^\n]{0,120}?\.(?:service|timer)\b)`),
	},
	{
		class: "linuxpkg.script.cron-persistence", score: 3, technique: techCron,
		detail: "installs a cron job or an @reboot task for persistence",
		re:     regexp.MustCompile(`(?i)(?:>>?\s*/etc/cron|/etc/cron\.d/|\bcrontab\s+-|@reboot\b)`),
	},
	{
		class: "linuxpkg.script.shellrc-persistence", score: 3, technique: techShellConfig,
		detail: "appends to a shell startup file or /etc/profile.d (persistence on login)",
		re:     regexp.MustCompile(`(?i)>>?\s*(?:\S*/\.(?:bashrc|bash_profile|profile|zshrc)|/etc/profile(?:\.d/\S+)?|/etc/bash\.bashrc)\b`),
	},
}

// scriptSource names where an extracted script came from, for evidence strings.
type scriptSource struct {
	name string // e.g. "postinst", "%post", ".INSTALL:post_install"
	body string
}

// matchIntel runs the abuse-intel feed over every extracted script body and
// returns a finding per distinct indicator hit. A known-bad IP/domain/URL in an
// install script that runs as root is a strong, high-weight signal. Feed hits
// de-duplicate across scripts by indicator value.
//
// MatchTextReportsTruncation examines a fixed number of URL/IP/domain
// candidates per body. When a script overflows that cap a listed indicator
// after the cut is not examined, so the truncation is reported here as its own
// low-weight finding rather than the package looking cleanly matched.
func matchIntel(feed *intel.Feed, scripts []scriptSource) []Finding {
	if feed == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []Finding
	truncReported := false
	for _, s := range scripts {
		hits, truncated := feed.MatchTextReportsTruncation(s.body)
		for _, h := range hits {
			if seen[h.Value] {
				continue
			}
			seen[h.Value] = true
			label := h.Label
			if label == "" {
				label = "listed in the abuse-intel feed"
			}
			out = append(out, Finding{
				Class:     "linuxpkg.intel." + string(h.Kind),
				Score:     8,
				Technique: techIngressTool,
				Detail:    "an install script references a known-bad " + string(h.Kind) + " from the abuse-intel feed (" + label + ")",
				Evidence:  s.name + ": " + h.Value,
			})
		}
		if truncated && !truncReported {
			truncReported = true
			out = append(out, Finding{
				Class:    "linuxpkg.intel.truncated",
				Score:    2,
				Detail:   "an install script had more URL/IP/domain candidates than the feed matcher scans, so a listed indicator after the cut may have been missed",
				Evidence: s.name + ": feed match truncated at its candidate cap",
			})
		}
	}
	return out
}

// ScanText runs the install-script threat vectors over an arbitrary piece of
// shell-like text — for example a running process's command line — and returns
// the findings, labelled with name. It lets callers outside this package (the
// live process scanner) reuse the same curl|bash / reverse-shell / dropper
// recognisers without duplicating them.
func ScanText(name, body string) []Finding {
	return scanScripts([]scriptSource{{name: name, body: body}})
}

// parallelFrom is the amount of text worth spreading across the CPUs. Below it a
// goroutine costs more than the regexes it would save: the persistence audit calls
// this once per line, and a whole binary is what makes it take seconds.
const parallelFrom = 64 << 10

// scanScripts runs every vector over every extracted script and returns one
// finding per distinct class (first match wins, ordered as scriptVectors). The
// evidence is a short, single-line, truncated excerpt of the matching text — it
// never carries the whole script.
//
// Each vector's result lands in its own slot and they are merged in table order,
// so a vector finishing early changes nothing about which one wins a class.
func scanScripts(scripts []scriptSource) []Finding {
	size := 0
	hits := make([]prefilter.Hits, len(scripts))
	for i, s := range scripts {
		size += len(s.body)
		hits[i] = scriptFilter().Scan(s.body)
		defer hits[i].Release()
	}
	slots := make([]*Finding, len(scriptVectors))
	if size >= parallelFrom {
		parallel.Share(len(scriptVectors), func(i int) { slots[i] = firstMatch(i, scripts, hits) })
	} else {
		for i := range scriptVectors {
			slots[i] = firstMatch(i, scripts, hits)
		}
	}

	seen := make(map[string]bool, len(scriptVectors))
	var out []Finding
	for _, f := range slots {
		if f != nil && !seen[f.Class] {
			seen[f.Class] = true
			out = append(out, *f)
		}
	}
	return out
}

// scriptFilter says which vectors can't match a script, so the regexes that would
// only prove it aren't run. The persistence audit calls this once per line.
var scriptFilter = sync.OnceValue(func() *prefilter.Set {
	exprs := make([]string, len(scriptVectors))
	for i, v := range scriptVectors {
		exprs[i] = v.re.String()
	}
	return prefilter.New(exprs)
})

// firstMatch returns vector i's finding in the first script it matches.
func firstMatch(i int, scripts []scriptSource, hits []prefilter.Hits) *Finding {
	v := scriptVectors[i]
	for j, s := range scripts {
		if !hits[j].May(i) {
			continue
		}
		if loc := v.re.FindStringIndex(s.body); loc != nil {
			return &Finding{
				Class:     v.class,
				Score:     v.score,
				Technique: v.technique,
				Detail:    v.detail,
				Evidence:  s.name + ": " + excerpt(s.body, loc[0], loc[1]),
			}
		}
	}
	return nil
}

// excerpt returns a one-line, length-capped slice of body around [start,end),
// with whitespace runs collapsed so a multi-line match stays readable in a
// report and never dumps payload bytes wholesale.
func excerpt(body string, start, end int) string {
	const max = 120
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	// Grow a little to the right for context, bounded by max.
	if end-start < max {
		end = start + max
		if end > len(body) {
			end = len(body)
		}
	}
	frag := body[start:end]
	frag = strings.Join(strings.Fields(frag), " ")
	if len(frag) > max {
		frag = frag[:max] + "…"
	}
	return frag
}
