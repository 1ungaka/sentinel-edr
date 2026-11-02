package linuxpkg

import (
	"bytes"
	"regexp"
	"strings"
)

// This file extends the detector to executable *configuration*: the files a
// desktop session, service manager or shell runs on login/boot without the user
// re-confirming anything. These are a favourite persistence and
// initial-foothold surface on Linux:
//
//   - XDG autostart / .desktop entries (~/.config/autostart, /etc/xdg/autostart,
//     and KDE's own service and applet .desktop files) — Exec= runs at login.
//   - systemd unit files (.service/.timer) — ExecStart= runs at boot / on a timer.
//   - shell startup files ("bash setup": .bashrc/.bash_profile/.profile/.zshrc,
//     /etc/profile.d, /etc/bash.bashrc) and KDE's autostart-scripts / env .sh —
//     sourced on every login shell.
//
// The same install-script vectors (vectors.go) apply to the command these
// configs launch; on top of them we add config-shaped tells: an autostart/unit
// whose Exec target lives in a world-writable or hidden location. Detection is
// content-based and conservative — a benign .bashrc or a normal .desktop launcher
// scores zero.

const (
	techXDGAutostart = "T1547.013" // Boot or Logon Autostart Execution: XDG Autostart Entries
)

// configVectors are the config-shaped tells, scored on top of the shared script
// vectors that also run over every extracted Exec/ExecStart command.
var configVectors = []vector{
	{
		class: "linuxpkg.config.autostart-world-writable-exec", score: 6, technique: techXDGAutostart,
		detail: "an autostart/unit launches a program from a world-writable path (/tmp, /dev/shm, /var/tmp)",
		re:     regexp.MustCompile(`(?im)^\s*(?:Exec|ExecStart)\s*=\s*\S*(?:/tmp/|/dev/shm/|/var/tmp/)`),
	},
	{
		class: "linuxpkg.config.autostart-hidden-exec", score: 5, technique: techXDGAutostart,
		detail: "an autostart/unit launches a hidden program (a dotfile or dot-directory target)",
		re:     regexp.MustCompile(`(?im)^\s*(?:Exec|ExecStart)\s*=\s*\S*/\.[A-Za-z0-9._-]+/`),
	},
	{
		class: "linuxpkg.config.autostart-inline-shell", score: 6, technique: techXDGAutostart,
		detail: "an autostart/unit Exec line is an inline shell one-liner (sh -c …) rather than a program",
		re:     regexp.MustCompile(`(?im)^\s*(?:Exec|ExecStart)\s*=\s*\S*(?:ba|z)?sh\s+-c\b`),
	},
}

// aptSourceVectors flag abuse in APT / nala repository sources (sources.list,
// sources.list.d/*.list and the deb822 *.sources format). An attacker who adds a
// repository — or weakens an existing one — gets code execution via the next
// `apt upgrade`, so these are supply-chain tells.
var aptSourceVectors = []vector{
	{
		class: "linuxpkg.apt.trusted-yes", score: 6, technique: techSupplyChain,
		detail: "an APT source sets [trusted=yes] / Trusted: yes, disabling package signature verification",
		re:     regexp.MustCompile(`(?i)(?:\[[^\]]*\btrusted=yes\b[^\]]*\]|^\s*Trusted:\s*yes)`),
	},
	{
		class: "linuxpkg.apt.ip-literal-repo", score: 5, technique: techSupplyChain,
		detail: "an APT source points at a bare IP-literal host rather than a named repository",
		re:     regexp.MustCompile(`(?im)^\s*(?:deb(?:-src)?\b.*|URIs:\s*)https?://(?:\d{1,3}\.){3}\d{1,3}\b`),
	},
	{
		class: "linuxpkg.apt.insecure-http", score: 2, technique: techSupplyChain,
		detail: "an APT source fetches packages over plain http:// (no transport integrity)",
		re:     regexp.MustCompile(`(?im)^\s*(?:deb(?:-src)?\s+(?:\[[^\]]*\]\s*)?|URIs:\s*)http://`),
	},
	{
		class: "linuxpkg.apt.pipe-in-signed-by", score: 6, technique: techSupplyChain,
		detail: "an APT source embeds a command substitution / pipe in a key or option field",
		re:     regexp.MustCompile(`(?im)^\s*(?:deb(?:-src)?\b|Signed-By:).*(?:\$\(|` + "`" + `|\|\s*(?:ba)?sh\b)`),
	},
}

func isAptSources(data []byte) bool {
	head := data[:min(len(data), maxManifestBytes)]
	return reDebLine.Match(head) || (bytes.Contains(head, []byte("Types:")) && bytes.Contains(head, []byte("URIs:")))
}

var reDebLine = regexp.MustCompile(`(?m)^\s*deb(?:-src)?\s+(?:\[[^\]]*\]\s*)?[a-z]+://`)

var (
	reDesktopEntry = regexp.MustCompile(`(?m)^\[(?:Desktop Entry|Desktop Action[^\]]*)\]`)
	reSystemdUnit  = regexp.MustCompile(`(?m)^\[(?:Unit|Service|Timer)\]`)
	reExecLine     = regexp.MustCompile(`(?im)^\s*(?:Exec|ExecStart|ExecStartPre|ExecStartPost|TryExec)\s*=\s*(.+)$`)
	reShellRCMark  = regexp.MustCompile(`(?m)^\s*(?:export\s+\w+=|alias\s+\w+=|PATH=|source\s+|\.\s+[~/]|eval\s+")`)
)

// isExecConfig reports whether data is an executable configuration file we scan.
// It is deliberately specific: a structured desktop/systemd unit, or a shell
// startup file that actually carries shell directives.
func isExecConfig(data []byte) bool {
	head := data[:min(len(data), maxManifestBytes)]
	if reDesktopEntry.Match(head) || reSystemdUnit.Match(head) {
		return true
	}
	if isAptSources(data) {
		return true
	}
	// Shell startup file without a shebang (those are handled as FormatScript):
	// require real shell-rc directives so arbitrary text is not misfiled.
	if !bytes.HasPrefix(data, []byte("#!")) && reShellRCMark.Match(head) {
		return true
	}
	return false
}

func parseConfig(data []byte) *container {
	c := &container{format: FormatConfig}
	text := string(data[:min(len(data), maxManifestBytes)])

	// APT / nala repository sources.
	if isAptSources(data) && !reDesktopEntry.MatchString(text) && !reSystemdUnit.MatchString(text) {
		seen := make(map[string]bool)
		for _, v := range aptSourceVectors {
			if loc := v.re.FindStringIndex(text); loc != nil && !seen[v.class] {
				seen[v.class] = true
				c.findings = append(c.findings, Finding{
					Class: v.class, Score: v.score, Technique: v.technique, Detail: v.detail,
					Evidence: excerpt(text, loc[0], loc[1]),
				})
			}
		}
		c.scriptNames = append(c.scriptNames, "apt-sources")
		return c
	}

	isUnit := reDesktopEntry.MatchString(text) || reSystemdUnit.MatchString(text)
	if isUnit {
		// Config-shaped tells over the raw unit text.
		seen := make(map[string]bool)
		for _, v := range configVectors {
			if loc := v.re.FindStringIndex(text); loc != nil && !seen[v.class] {
				seen[v.class] = true
				c.findings = append(c.findings, Finding{
					Class: v.class, Score: v.score, Technique: v.technique, Detail: v.detail,
					Evidence: excerpt(text, loc[0], loc[1]),
				})
			}
		}
		// Extract each Exec/ExecStart command so the shared script vectors see the
		// actual launched command line.
		for _, m := range reExecLine.FindAllStringSubmatch(text, 64) {
			cmd := strings.TrimSpace(m[1])
			cmd = strings.TrimPrefix(cmd, "/usr/bin/env ")
			c.scripts = append(c.scripts, scriptSource{name: "Exec", body: capStr(cmd)})
		}
		c.scriptNames = append(c.scriptNames, "unit")
		return c
	}

	// Shell startup file ("bash setup" / KDE autostart-scripts): scan the whole
	// body with the script vectors.
	c.scripts = append(c.scripts, scriptSource{name: "shell-rc", body: capStr(text)})
	c.scriptNames = append(c.scriptNames, "shell-rc")
	return c
}
