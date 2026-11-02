package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cau-edr/cau/internal/intel"
	"github.com/cau-edr/cau/internal/report"
	"github.com/cau-edr/cau/scanner/linuxpkg"
)

// cau installed audits the maintainer/install scripts of ALREADY-installed
// packages, in place, from the package managers' on-disk metadata. It is
// offline and read-only:
//
//   - dpkg (Debian/Ubuntu/Kali): /var/lib/dpkg/info/<pkg>.{preinst,postinst,
//     prerm,postrm,config}
//   - pacman (Arch): /var/lib/pacman/local/<pkg>/install
//
// Each script is run through the same install-script vectors cau scan uses, plus
// the abuse-intel feed, so a backdoored or trojanised package that is already
// on the system is caught without re-downloading anything. (RPM stores its
// scriptlets inside the rpmdb rather than as loose files; scanning those needs
// the rpm database reader and is noted as a gap here, not silently skipped.)

const (
	defaultDpkgInfo    = "/var/lib/dpkg/info"
	defaultPacmanLocal = "/var/lib/pacman/local"
)

var dpkgScriptSuffixes = []string{".preinst", ".postinst", ".prerm", ".postrm", ".config"}

func installedUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau installed [flags]

Audits the maintainer/install scripts of already-installed packages, in place,
from the package managers' on-disk metadata (offline, read-only). Flags any whose
scripts carry the same tradecraft cau scan looks for (curl|bash, reverse shells,
SSH-key backdoors, persistence) or that reference an abuse-intel indicator.

Covers dpkg (/var/lib/dpkg/info) and pacman (/var/lib/pacman/local). RPM keeps
its scriptlets in the rpmdb, not as files, so it is reported as a gap.

Flags:
  --format <fmt>      text or json (default text)
  --threshold <n>     per-package score to report (default 8)
  --feed <path>       abuse-intel feed file (default: search path)
  --dpkg-info <dir>   override /var/lib/dpkg/info (testing)
  --pacman-local <dir> override /var/lib/pacman/local (testing)

Exit codes: 0 nothing flagged, 1 one or more packages flagged, 3 failed, 4 usage.
`)
}

// installedPkg is one flagged installed package.
type installedPkg struct {
	Name     string             `json:"name"`
	Manager  string             `json:"manager"`
	Scripts  []string           `json:"scripts"`
	Score    int                `json:"score"`
	Findings []linuxpkg.Finding `json:"findings"`
}

type installedResult struct {
	Scanned   int            `json:"scanned"`
	Threshold int            `json:"threshold"`
	Flagged   []installedPkg `json:"flagged,omitempty"`
	Warnings  []string       `json:"warnings,omitempty"`
}

func cmdInstalled(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("installed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { installedUsage(stderr) }
	format := fs.String("format", "text", "output format: text or json")
	threshold := fs.Int("threshold", linuxpkg.Threshold, "per-package score to report")
	feedPath := fs.String("feed", "", "abuse-intel feed file")
	dpkgInfo := fs.String("dpkg-info", defaultDpkgInfo, "dpkg info directory")
	pacmanLocal := fs.String("pacman-local", defaultPacmanLocal, "pacman local database directory")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if *threshold < 1 {
		return fail(stderr, report.ExitUsage, "--threshold must be at least 1")
	}

	feed := loadFeedQuiet(*feedPath)
	res := &installedResult{Threshold: *threshold}

	auditDpkg(*dpkgInfo, *threshold, feed, res)
	auditPacman(*pacmanLocal, *threshold, feed, res)

	// RPM gap note when an rpmdb is present but we cannot read its scriptlets.
	for _, p := range []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"} {
		if _, err := os.Stat(p); err == nil {
			res.Warnings = append(res.Warnings, "an RPM database is present at "+p+" but RPM stores scriptlets in the rpmdb, not as files; `cau installed` does not read it (scan .rpm files directly with `cau scan`)")
			break
		}
	}

	sort.Slice(res.Flagged, func(i, j int) bool {
		if res.Flagged[i].Score != res.Flagged[j].Score {
			return res.Flagged[i].Score > res.Flagged[j].Score
		}
		return res.Flagged[i].Name < res.Flagged[j].Name
	})

	if *format == "json" {
		if err := writeJSON(stdout, res); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		fmt.Fprintf(stdout, "Packages scanned : %d\n", res.Scanned)
		fmt.Fprintf(stdout, "Threshold        : %d\n", res.Threshold)
		fmt.Fprintf(stdout, "Flagged          : %d\n", len(res.Flagged))
		for _, w := range res.Warnings {
			fmt.Fprintf(stdout, "  [note] %s\n", w)
		}
		for _, p := range res.Flagged {
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, " [!] %s (%s) score %d  scripts: %s\n", p.Name, p.Manager, p.Score, strings.Join(p.Scripts, ","))
			for _, fnd := range p.Findings {
				tag := ""
				if fnd.Technique != "" {
					tag = "  (" + fnd.Technique + ")"
				}
				fmt.Fprintf(stdout, "     [%s] %d%s\n", fnd.Class, fnd.Score, tag)
				detail := fnd.Detail
				if fnd.Evidence != "" {
					detail += ": " + fnd.Evidence
				}
				fmt.Fprintf(stdout, "       %s\n", truncStr(detail, 200))
			}
		}
		if len(res.Flagged) == 0 {
			fmt.Fprintln(stdout, "\n No installed package flagged.")
		} else {
			fmt.Fprintln(stdout, "\n *** FLAGGED INSTALLED PACKAGE(S) — INVESTIGATE ***")
		}
	}

	if len(res.Flagged) > 0 {
		return report.ExitThreat
	}
	return report.ExitOK
}

// scoreScripts runs the shared vector engine (and feed) over a set of named
// script bodies and returns the findings and total score.
func scoreScripts(scripts map[string]string, feed *intel.Feed) ([]linuxpkg.Finding, int, []string) {
	var findings []linuxpkg.Finding
	var names []string
	for name, body := range scripts {
		names = append(names, name)
		findings = append(findings, linuxpkg.ScanText(name, body)...)
		if feed != nil {
			for _, h := range feed.MatchText(body) {
				findings = append(findings, linuxpkg.Finding{
					Class: "linuxpkg.intel." + string(h.Kind), Score: 8,
					Detail:   "references a known-bad " + string(h.Kind) + " from the abuse-intel feed",
					Evidence: name + ": " + h.Value,
				})
			}
		}
	}
	sort.Strings(names)
	score := 0
	for _, f := range findings {
		score += f.Score
	}
	return findings, score, names
}

func auditDpkg(infoDir string, threshold int, feed *intel.Feed, res *installedResult) {
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return // not a dpkg system, or unreadable
	}
	// Group scripts by package name (the file stem before the script suffix).
	byPkg := map[string]map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		for _, suf := range dpkgScriptSuffixes {
			if strings.HasSuffix(name, suf) {
				pkg := strings.TrimSuffix(name, suf)
				body := readScript(filepath.Join(infoDir, name))
				if body == "" {
					continue
				}
				if byPkg[pkg] == nil {
					byPkg[pkg] = map[string]string{}
				}
				byPkg[pkg][strings.TrimPrefix(suf, ".")] = body
				break
			}
		}
	}
	for pkg, scripts := range byPkg {
		res.Scanned++
		findings, score, names := scoreScripts(scripts, feed)
		if score >= threshold {
			res.Flagged = append(res.Flagged, installedPkg{Name: pkg, Manager: "dpkg", Scripts: names, Score: score, Findings: findings})
		}
	}
}

func auditPacman(localDir string, threshold int, feed *intel.Feed, res *installedResult) {
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		installPath := filepath.Join(localDir, e.Name(), "install")
		body := readScript(installPath)
		if body == "" {
			continue
		}
		res.Scanned++
		findings, score, names := scoreScripts(map[string]string{".INSTALL": body}, feed)
		if score >= threshold {
			res.Flagged = append(res.Flagged, installedPkg{Name: e.Name(), Manager: "pacman", Scripts: names, Score: score, Findings: findings})
		}
	}
}

const maxInstalledScriptBytes = 1 << 20

func readScript(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, maxInstalledScriptBytes))
	return string(data)
}
