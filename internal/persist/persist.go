// Package persist audits a Linux host for the footholds attackers leave behind:
// the places that make code run again after a reboot or a login, and the
// accounts and privileges that let them back in. It is the at-rest complement
// to procscan: a process scan sees what is running now, this sees what will run
// next.
//
// It is READ-ONLY. It reports what it finds and never edits a file, because the
// entry it would remove may be the only evidence of the intrusion, and removing
// a line from PAM or sudoers by machine is a good way to lock an operator out.
//
// Every check is a function of file contents under Options.Root, so the whole
// audit is testable against a fixture tree. Symlinks are not followed: a root
// scan must not be steered by a user's ~/.bashrc into quoting /etc/shadow. Whatever
// loads an audited path does follow one, though, so a link is judged by where it
// points, from the link alone, and its target is never opened.
package persist

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/1ungaka/sentinel-edr/internal/parallel"
	"github.com/1ungaka/sentinel-edr/internal/safefs"
	"github.com/1ungaka/sentinel-edr/scanner/linuxpkg"
)

// DefaultThreshold is the per-finding score at which an entry is reported as a
// detection. Scores below it are observations, shown only on request.
const DefaultThreshold = 8

const (
	maxFileBytes = 1 << 20
	maxWalk      = 20000
)

// ATT&CK technique ids.
const (
	techPreload  = "T1574.006" // Dynamic Linker Hijacking
	techCron     = "T1053.003" // Scheduled Task: Cron
	techSystemd  = "T1543.002" // Create or Modify System Process: Systemd Service
	techShellCfg = "T1546.004" // Event Triggered Execution: Unix Shell Configuration
	techRCScript = "T1037.004" // Boot or Logon Initialization Scripts: RC Scripts
	techXDG      = "T1547.013" // Boot or Logon Autostart: XDG Autostart Entries
	techSSHKeys  = "T1098.004" // Account Manipulation: SSH Authorized Keys
	techLocalAcc = "T1136.001" // Create Account: Local Account
	techValidAcc = "T1078.003" // Valid Accounts: Local Accounts
	techSudo     = "T1548.003" // Abuse Elevation Control: Sudo and Sudo Caching
	techUdev     = "T1546"     // Event Triggered Execution
	techPAM      = "T1556.003" // Modify Authentication Process: PAM
	techSUID     = "T1548.001" // Abuse Elevation Control: Setuid and Setgid
	techFilePerm = "T1222.002" // File and Directory Permissions Modification: Linux
	techModules  = "T1547.006" // Boot or Logon Autostart: Kernel Modules
	techMOTD     = "T1037"     // Boot or Logon Initialization Scripts
	techBootInit = "T1037"     // the same technique, for a path of no one kind
)

// Finding is one suspicious entry.
type Finding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Path      string `json:"path"`
	Line      int    `json:"line,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// Result is the audit outcome. Findings are sorted, highest score first.
type Result struct {
	Root      string    `json:"root"`
	Checked   int       `json:"files_checked"`
	Threshold int       `json:"threshold"`
	Findings  []Finding `json:"findings,omitempty"`
	// Incomplete names the paths the audit could not read. A missing path is
	// not one: most audited paths exist only on hosts that use them, and their
	// absence is the documented skip. A path listed here was found but not
	// read, so it is unverified rather than clean.
	Incomplete []string `json:"incomplete,omitempty"`
}

// Flagged returns the findings at or above the threshold.
func (r *Result) Flagged() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Score >= r.Threshold {
			out = append(out, f)
		}
	}
	return out
}

// Options configure an audit.
type Options struct {
	// Root is the filesystem to audit; "" means "/". Pointing it at a mounted
	// image audits a suspect disk from a clean host.
	Root      string
	Threshold int
}

// audit is shared by every check, which all run at once. mu guards the three
// fields below it, and nothing else in a check touches shared state.
type audit struct {
	root string

	// maxWalk bounds the entries one walk reads. It is a field rather than a
	// constant so a test can lower it; the shipped value is the constant.
	maxWalk int

	mu         sync.Mutex
	checked    int
	out        []Finding
	links      map[string]bool // symlinks already judged
	unreadable map[string]bool // paths a check tried and failed to read
}

// noteUnreadable records a path a check could not read, so the result can report
// incomplete coverage instead of presenting an unread location as a clean one.
// Only a path that is merely absent is skipped: that is the documented skip for
// paths a host does not use, not a gap in the audit.
func (a *audit) noteUnreadable(rel string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.unreadable[rel] = true
}

// Scan runs every check.
func Scan(opts Options) *Result {
	a := &audit{root: opts.Root, maxWalk: maxWalk, links: map[string]bool{}, unreadable: map[string]bool{}}
	if a.root == "" {
		a.root = "/"
	}
	th := opts.Threshold
	if th <= 0 {
		th = DefaultThreshold
	}
	// The accounts come first because the checks of what they own read them.
	// After that no check depends on another, so each runs on its own.
	accounts := a.checkAccounts()
	parallel.Do(
		a.checkPreload,
		a.checkCron,
		func() { a.checkSystemd(accounts) },
		func() { a.checkShellConfig(accounts) },
		a.checkRCLocal,
		func() { a.checkAutostart(accounts) },
		func() { a.checkAuthorizedKeys(accounts) },
		a.checkSudoers,
		a.checkUdev,
		a.checkPAM,
		a.checkSUID,
		a.checkInitScripts,
		a.checkAptHooks,
		a.checkLinkerConfig,
		a.checkModuleConfig,
		a.checkSensitivePerms,
		a.checkCapabilities,
	)

	sort.SliceStable(a.out, func(i, j int) bool {
		if a.out[i].Score != a.out[j].Score {
			return a.out[i].Score > a.out[j].Score
		}
		if a.out[i].Path != a.out[j].Path {
			return a.out[i].Path < a.out[j].Path
		}
		if a.out[i].Line != a.out[j].Line {
			return a.out[i].Line < a.out[j].Line
		}
		// The checks finish in any order, so the report's order can't rest on it.
		if a.out[i].Class != a.out[j].Class {
			return a.out[i].Class < a.out[j].Class
		}
		return a.out[i].Evidence < a.out[j].Evidence
	})

	var incomplete []string
	for rel := range a.unreadable {
		incomplete = append(incomplete, rel)
	}
	sort.Strings(incomplete)
	return &Result{Root: a.root, Checked: a.checked, Threshold: th, Findings: a.out, Incomplete: incomplete}
}

// read returns a regular file's lines, or nil when it is missing, unreadable, or
// too large to be a configuration file. A symlink is judged by noteSymlink and
// not read. A path that exists but cannot be opened or scanned is recorded as
// unreadable: no result from it is a coverage gap, not a clean file.
func (a *audit) read(rel string) []string {
	p := filepath.Join(a.root, rel)
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		a.noteSymlink(rel)
		return nil
	}
	f, fi, err := safefs.OpenNoFollow(p)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			a.noteUnreadable(rel)
		}
		return nil
	}
	defer f.Close()
	if fi.Size() > maxFileBytes {
		return nil
	}
	// Everything read here runs at boot, at login or as root, so a file anyone
	// can write is the foothold itself, whatever it says today.
	if fi.Mode().Perm()&0o002 != 0 {
		a.add(Finding{Class: "persist.perms.world-writable-autostart", Score: 8, Technique: techFilePerm, Path: rel,
			Detail: "a file that runs automatically is writable by every user", Evidence: fi.Mode().String()})
	}
	a.mu.Lock()
	a.checked++
	a.mu.Unlock()
	var lines []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), maxFileBytes)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	// A read that stopped early leaves the rest of the file unseen, so the
	// lines returned are not the file.
	if err := s.Err(); err != nil {
		a.noteUnreadable(rel)
	}
	return lines
}

// list returns the regular files directly under a directory, relative to root.
// A symlink among them is judged by noteSymlink. A directory that is there but
// cannot be read is recorded as unreadable: its contents are unknown, not empty.
func (a *audit) list(rel string) []string {
	entries, err := os.ReadDir(filepath.Join(a.root, rel))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			a.noteUnreadable(rel)
		}
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, filepath.Join(rel, e.Name()))
		} else if e.Type()&fs.ModeSymlink != 0 {
			a.noteSymlink(filepath.Join(rel, e.Name()))
		}
	}
	return out
}

// criticalFiles are never symlinks on a stock system, so one is a finding wherever
// it points. The value is the technique it would serve.
var criticalFiles = map[string]string{
	"etc/ld.so.preload": techPreload,
	"etc/sudoers":       techSudo,
	"etc/passwd":        techLocalAcc,
	"etc/shadow":        techValidAcc,
	"etc/crontab":       techCron,
}

// systemTrees hold what packages install. Every link at an audited path on the
// development host (100, nearly all of them enabled systemd units) lands in one
// of these or on /dev/null, which is how systemd masks a unit.
var systemTrees = []string{"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/etc/"}

// noteSymlink judges a link at an audited path by its target's name. The target
// stays unread, which is what keeps a user's dotfile from getting /etc/shadow
// quoted into a root audit's report, and it also means the name is all there is:
// a link into a system tree is taken at face value.
func (a *audit) noteSymlink(rel string) {
	a.mu.Lock()
	judged := a.links[rel]
	a.links[rel] = true
	a.mu.Unlock()
	if judged {
		return
	}
	target, err := os.Readlink(filepath.Join(a.root, rel))
	if err != nil {
		return
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join("/", filepath.Dir(rel), target)
	}
	target = filepath.Clean(target)
	if target == "/dev/null" {
		return
	}
	evidence := "-> " + target
	tech, critical := criticalFiles[rel]
	switch {
	case writablePath.MatchString(target):
		a.add(Finding{Class: "persist.symlink.writable-target", Score: 9, Technique: techBootInit, Path: rel,
			Detail: "a path that runs automatically is a link into a world-writable or hidden location", Evidence: evidence})
	case critical:
		a.add(Finding{Class: "persist.symlink.critical-file", Score: 9, Technique: tech, Path: rel,
			Detail: "a file the system trusts completely is a symbolic link, so its contents were not audited", Evidence: evidence})
	case !inSystemTree(target):
		a.add(Finding{Class: "persist.symlink.unaudited", Score: 4, Technique: techBootInit, Path: rel,
			Detail: "a path that runs automatically is a link outside the system trees, and its target was not read", Evidence: evidence})
	}
}

func inSystemTree(target string) bool {
	for _, tree := range systemTrees {
		if strings.HasPrefix(target, tree) {
			return true
		}
	}
	return false
}

func (a *audit) add(f Finding) {
	f.Path = "/" + strings.TrimPrefix(f.Path, "/")
	f.Evidence = trunc(strings.TrimSpace(f.Evidence), 200)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.out = append(a.out, f)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// writablePath is a path anyone can write to, or a hidden directory inside a
// system tree. Persistence that runs from one of these has no business there.
var writablePath = regexp.MustCompile(`(?:^|[\s'"=:;(|&])(?:/tmp/|/var/tmp/|/dev/shm/|/run/shm/|/(?:usr|var|etc|lib|opt)(?:/[^/\s]+)*/\.[^/\s.][^/\s]*)`)

// execVectors are the recognisers that mean "this line does something hostile".
// The persistence vectors in the same table are skipped: every crontab matches
// the cron one by being a crontab.
var execVectors = map[string]bool{
	"linuxpkg.script.curl-pipe-shell": true,
	"linuxpkg.script.reverse-shell":   true,
	"linuxpkg.script.decode-exec":     true,
	"linuxpkg.script.cryptominer":     true,
	"linuxpkg.script.download-exec":   true,
}

func comment(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || strings.HasPrefix(t, "#")
}

// scanExec applies the shared hostile-command recognisers and the writable-path
// check to the lines selected by keep, under the given class family.
func (a *audit) scanExec(rel string, lines []string, family, tech string, keep func(string) bool) {
	a.scanLines(rel, lines, family, tech, keep, true)
}

// scanScript is scanExec for whole scripts, where the lines are not each a
// command: `DIR="/tmp/$1"` in an init script is data (measured: x11-common), so
// only the hostile-command recognisers apply.
func (a *audit) scanScript(rel string, lines []string, family, tech string) {
	a.scanLines(rel, lines, family, tech, nil, false)
}

func (a *audit) scanLines(rel string, lines []string, family, tech string, keep func(string) bool, writable bool) {
	for i, line := range lines {
		if comment(line) || (keep != nil && !keep(line)) {
			continue
		}
		hit := false
		for _, f := range linuxpkg.ScanText("persist", line) {
			if execVectors[f.Class] {
				a.add(Finding{Class: family + "." + strings.TrimPrefix(f.Class, "linuxpkg.script."), Score: 9, Technique: tech,
					Path: rel, Line: i + 1, Detail: f.Detail, Evidence: line})
				hit = true
			}
		}
		if !hit && writable && writablePath.MatchString(line) {
			a.add(Finding{Class: family + ".writable-path", Score: 8, Technique: tech, Path: rel, Line: i + 1,
				Detail: "an autostart entry runs from a world-writable or hidden location", Evidence: line})
		}
	}
}

type account struct {
	name, home string
	uid        int
}

// checkAccounts flags rogue root-equivalent accounts and returns the accounts
// with a real home, whose dotfiles the later checks read.
func (a *audit) checkAccounts() []account {
	var homes []account
	for i, line := range a.read("etc/passwd") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		if uid == 0 && f[0] != "root" {
			a.add(Finding{Class: "persist.account.uid0", Score: 9, Technique: techLocalAcc, Path: "etc/passwd", Line: i + 1,
				Detail: "an account other than root has UID 0", Evidence: f[0]})
		}
		if f[1] == "" {
			a.add(Finding{Class: "persist.account.empty-password", Score: 9, Technique: techValidAcc, Path: "etc/passwd", Line: i + 1,
				Detail: "an account has an empty password field: anyone can log in as it", Evidence: f[0]})
		}
		if (uid == 0 || uid >= 1000) && uid != 65534 && strings.HasPrefix(f[5], "/") && f[5] != "/" {
			homes = append(homes, account{name: f[0], home: strings.TrimPrefix(f[5], "/"), uid: uid})
		}
	}
	for i, line := range a.read("etc/shadow") {
		f := strings.Split(line, ":")
		if len(f) >= 2 && f[1] == "" {
			a.add(Finding{Class: "persist.account.empty-password", Score: 9, Technique: techValidAcc, Path: "etc/shadow", Line: i + 1,
				Detail: "an account has an empty password hash: anyone can log in as it", Evidence: f[0]})
		}
	}
	return homes
}

func (a *audit) checkPreload() {
	for i, line := range a.read("etc/ld.so.preload") {
		if comment(line) {
			continue
		}
		// The file is normally absent, and a library named here is mapped into
		// every dynamically linked process on the host.
		a.add(Finding{Class: "persist.ld-preload", Score: 9, Technique: techPreload, Path: "etc/ld.so.preload", Line: i + 1,
			Detail: "a library is force-loaded into every process (a classic userland rootkit hook)", Evidence: line})
	}
}

func (a *audit) checkCron() {
	files := []string{"etc/crontab", "etc/anacrontab"}
	for _, d := range []string{"etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly",
		"var/spool/cron", "var/spool/cron/crontabs"} {
		files = append(files, a.list(d)...)
	}
	for _, rel := range files {
		a.scanExec(rel, a.read(rel), "persist.cron", techCron, nil)
	}
}

func execLine(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "Exec")
}

func (a *audit) checkSystemd(accounts []account) {
	// Transient units (systemd-run) and drop-ins change what a unit runs without
	// touching a unit file a reviewer would look at.
	dirs := []string{"etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system", "etc/systemd/user", "run/systemd/transient", "run/systemd/system"}
	for _, u := range accounts {
		dirs = append(dirs, filepath.Join(u.home, ".config/systemd/user"))
	}
	for _, d := range dirs {
		for _, rel := range a.list(d) {
			if strings.HasSuffix(rel, ".service") || strings.HasSuffix(rel, ".timer") || strings.HasSuffix(rel, ".path") {
				a.scanExec(rel, a.read(rel), "persist.systemd", techSystemd, execLine)
			}
		}
		entries, err := os.ReadDir(filepath.Join(a.root, d))
		if err != nil {
			// The drop-in directories below it stay unseen, so this is the same
			// coverage gap a.list reports.
			if !errors.Is(err, fs.ErrNotExist) {
				a.noteUnreadable(d)
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() && strings.HasSuffix(e.Name(), ".d") {
				for _, rel := range a.list(filepath.Join(d, e.Name())) {
					a.scanExec(rel, a.read(rel), "persist.systemd", techSystemd, execLine)
				}
			}
		}
	}
}

var sudoAlias = regexp.MustCompile(`^\s*alias\s+(?:sudo|su|ssh|passwd)=`)
var preloadExport = regexp.MustCompile(`^\s*(?:export\s+)?LD_(?:PRELOAD|AUDIT)=`)

func (a *audit) checkShellConfig(accounts []account) {
	files := []string{"etc/profile", "etc/bash.bashrc", "etc/zsh/zshrc", "etc/zsh/zprofile", "etc/environment"}
	files = append(files, a.list("etc/profile.d")...)
	for _, u := range accounts {
		for _, n := range []string{".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".ssh/rc", ".config/fish/config.fish"} {
			files = append(files, filepath.Join(u.home, n))
		}
	}
	for _, rel := range files {
		lines := a.read(rel)
		a.scanExec(rel, lines, "persist.shellrc", techShellCfg, nil)
		for i, line := range lines {
			if sudoAlias.MatchString(line) {
				a.add(Finding{Class: "persist.shellrc.credential-alias", Score: 8, Technique: techShellCfg, Path: rel, Line: i + 1,
					Detail: "a shell alias shadows a credential-handling command", Evidence: line})
			}
			if preloadExport.MatchString(line) {
				a.add(Finding{Class: "persist.shellrc.preload", Score: 9, Technique: techPreload, Path: rel, Line: i + 1,
					Detail: "a startup file forces a library into everything the shell runs", Evidence: line})
			}
		}
	}
}

func (a *audit) checkRCLocal() {
	for _, rel := range []string{"etc/rc.local", "etc/rc.d/rc.local"} {
		a.scanExec(rel, a.read(rel), "persist.rc-local", techRCScript, nil)
	}
}

func (a *audit) checkAutostart(accounts []account) {
	dirs := []string{"etc/xdg/autostart"}
	for _, u := range accounts {
		dirs = append(dirs, filepath.Join(u.home, ".config/autostart"))
	}
	for _, d := range dirs {
		for _, rel := range a.list(d) {
			a.scanExec(rel, a.read(rel), "persist.autostart", techXDG, func(l string) bool {
				return strings.HasPrefix(strings.TrimSpace(l), "Exec=")
			})
		}
	}
}

var forcedCommand = regexp.MustCompile(`(?:^|,)\s*command="((?:[^"\\]|\\.)*)"`)

func (a *audit) checkAuthorizedKeys(accounts []account) {
	for _, u := range accounts {
		for _, n := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			rel := filepath.Join(u.home, n)
			for i, line := range a.read(rel) {
				if comment(line) {
					continue
				}
				if m := forcedCommand.FindStringSubmatch(line); m != nil {
					a.scanExec(rel, []string{m[1]}, "persist.ssh-key", techSSHKeys, nil)
				}
				if u.uid == 0 {
					// Worth seeing, not an alert: admins do this. Only a key is
					// quoted, never a private path.
					a.add(Finding{Class: "persist.ssh-key.root-login", Score: 3, Technique: techSSHKeys, Path: rel, Line: i + 1,
						Detail: "a key grants direct root login; check it is one you issued", Evidence: keyComment(line)})
				}
			}
		}
	}
}

func keyComment(line string) string {
	f := strings.Fields(line)
	if len(f) < 3 {
		return ""
	}
	return strings.Join(f[2:], " ")
}

var sudoEveryone = regexp.MustCompile(`^\s*ALL\s+ALL\s*=.*NOPASSWD:\s*ALL`)
var sudoNoPass = regexp.MustCompile(`^\s*[^#\s%]\S*\s+\S+\s*=.*NOPASSWD:\s*ALL`)
var sudoEnvKeep = regexp.MustCompile(`^\s*Defaults\b.*env_keep\s*\+?=.*\b(?:LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|PYTHONPATH|PERL5LIB)\b`)

func (a *audit) checkSudoers() {
	files := append([]string{"etc/sudoers"}, a.list("etc/sudoers.d")...)
	for _, rel := range files {
		for i, line := range a.read(rel) {
			switch {
			case sudoEveryone.MatchString(line):
				a.add(Finding{Class: "persist.sudoers.everyone-nopasswd", Score: 9, Technique: techSudo, Path: rel, Line: i + 1,
					Detail: "every user can run anything as root without a password", Evidence: line})
			case sudoEnvKeep.MatchString(line):
				a.add(Finding{Class: "persist.sudoers.env-keep-loader", Score: 9, Technique: techSudo, Path: rel, Line: i + 1,
					Detail: "sudo keeps a loader variable, so any allowed command runs an attacker's library as root", Evidence: line})
			case sudoNoPass.MatchString(line):
				a.add(Finding{Class: "persist.sudoers.user-nopasswd", Score: 4, Technique: techSudo, Path: rel, Line: i + 1,
					Detail: "a single user has passwordless root; check it is expected", Evidence: line})
			}
		}
	}
}

func (a *audit) checkUdev() {
	for _, rel := range a.list("etc/udev/rules.d") {
		a.scanExec(rel, a.read(rel), "persist.udev", techUdev, func(l string) bool {
			return strings.Contains(l, "RUN")
		})
	}
}

var pamPermitBackdoor = regexp.MustCompile(`^\s*auth\s+sufficient\s+(?:\S*/)?pam_permit\.so`)
var pamExec = regexp.MustCompile(`pam_exec\.so`)

func (a *audit) checkPAM() {
	for _, rel := range a.list("etc/pam.d") {
		lines := a.read(rel)
		for i, line := range lines {
			if pamPermitBackdoor.MatchString(line) {
				a.add(Finding{Class: "persist.pam.permit-backdoor", Score: 9, Technique: techPAM, Path: rel, Line: i + 1,
					Detail: "'auth sufficient pam_permit.so' accepts any password", Evidence: line})
			}
		}
		a.scanExec(rel, lines, "persist.pam", techPAM, pamExec.MatchString)
	}
}

// checkInitScripts reads the scripts run as root at boot and at login.
func (a *audit) checkInitScripts() {
	for _, d := range []string{"etc/update-motd.d", "etc/init.d", "etc/network/if-up.d", "etc/network/if-pre-up.d"} {
		for _, rel := range a.list(d) {
			a.scanScript(rel, a.read(rel), "persist.init-script", techMOTD)
		}
	}
}

var aptHook = regexp.MustCompile(`(?i)^\s*(?:APT::Update::(?:Pre|Post)-Invoke|DPkg::(?:Pre|Post)-Invoke)`)

// checkAptHooks reads package-manager hooks, which run as root on every update.
func (a *audit) checkAptHooks() {
	for _, rel := range a.list("etc/apt/apt.conf.d") {
		a.scanExec(rel, a.read(rel), "persist.apt-hook", techShellCfg, aptHook.MatchString)
	}
}

// checkLinkerConfig reads the library search path. A directory anyone can write
// to here hijacks every dynamically linked root process.
func (a *audit) checkLinkerConfig() {
	files := append([]string{"etc/ld.so.conf"}, a.list("etc/ld.so.conf.d")...)
	for _, rel := range files {
		for i, line := range a.read(rel) {
			if !comment(line) && writablePath.MatchString(" "+strings.TrimSpace(line)+"/") {
				a.add(Finding{Class: "persist.ld-conf.writable-path", Score: 9, Technique: techPreload, Path: rel, Line: i + 1,
					Detail: "the system library path includes a world-writable or hidden directory", Evidence: line})
			}
		}
	}
}

// checkModuleConfig reads modprobe's `install` directive, which runs a command
// in place of loading a module, and the list of modules loaded at boot.
func (a *audit) checkModuleConfig() {
	for _, rel := range a.list("etc/modprobe.d") {
		a.scanExec(rel, a.read(rel), "persist.modprobe", techModules, func(l string) bool {
			return strings.HasPrefix(strings.TrimSpace(l), "install ")
		})
	}
}

// checkSensitivePerms flags the account files being writable by everyone, which
// turns any local user into root without an exploit.
func (a *audit) checkSensitivePerms() {
	for _, rel := range []string{"etc/passwd", "etc/shadow", "etc/sudoers", "etc/group"} {
		fi, err := os.Lstat(filepath.Join(a.root, rel))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if fi.Mode().Perm()&0o002 != 0 {
			a.add(Finding{Class: "persist.perms.world-writable-account-file", Score: 9, Technique: techFilePerm, Path: rel,
				Detail: "an account database is writable by every user", Evidence: fi.Mode().String()})
		}
		if rel == "etc/shadow" && fi.Mode().Perm()&0o004 != 0 {
			a.add(Finding{Class: "persist.perms.world-readable-shadow", Score: 8, Technique: techFilePerm, Path: rel,
				Detail: "password hashes are readable by every user", Evidence: fi.Mode().String()})
		}
	}
}

// interpreterDirs and interpreterNames bound the capability check to what can
// turn a capability straight into a root shell.
var (
	interpreterDirs  = []string{"usr/bin", "usr/local/bin", "bin"}
	interpreterNames = regexp.MustCompile(`^(?:python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|lua[0-9.]*|gdb|vim|vim\.basic|tar|bash|dash|sh|zsh|awk|gawk|find)$`)
)

// checkCapabilities flags dangerous file capabilities on interpreters and other
// programs that run arbitrary code: `cap_setuid+ep` on python is a root shell
// any user can have, with no set-uid bit for a scanner to see.
func (a *audit) checkCapabilities() {
	seen := map[string]bool{}
	for _, d := range interpreterDirs {
		entries, err := os.ReadDir(filepath.Join(a.root, d))
		if err != nil {
			// An interpreter directory that is there but unreadable hides its
			// programs from the check.
			if !errors.Is(err, fs.ErrNotExist) {
				a.noteUnreadable(d)
			}
			continue
		}
		for _, e := range entries {
			if !interpreterNames.MatchString(e.Name()) {
				continue
			}
			rel := filepath.Join(d, e.Name())
			p := filepath.Join(a.root, rel)
			// usr-merge makes /bin and /usr/bin one directory.
			resolved, err := filepath.EvalSymlinks(p)
			if err != nil || seen[resolved] {
				continue
			}
			seen[resolved] = true
			if caps := dangerousCaps(fileCaps(resolved)); caps != "" {
				a.add(Finding{Class: "persist.caps.dangerous-on-interpreter", Score: 9, Technique: techSUID, Path: rel,
					Detail: "a program that runs arbitrary code holds a capability equivalent to root", Evidence: caps})
			}
		}
	}
}

// Capability bits, from linux/capability.h.
var dangerousBits = []struct {
	bit  uint
	name string
}{
	{1, "cap_dac_override"}, {2, "cap_dac_read_search"}, {3, "cap_fowner"}, {6, "cap_setgid"}, {7, "cap_setuid"},
	{16, "cap_sys_module"}, {19, "cap_sys_ptrace"}, {21, "cap_sys_admin"},
}

// dangerousCaps decodes a security.capability xattr (struct vfs_cap_data) and
// names the permitted capabilities that amount to root.
func dangerousCaps(raw []byte) string {
	if len(raw) < 12 {
		return ""
	}
	permitted := uint64(binary.LittleEndian.Uint32(raw[4:]))
	if len(raw) >= 16 {
		permitted |= uint64(binary.LittleEndian.Uint32(raw[12:])) << 32
	}
	var names []string
	for _, c := range dangerousBits {
		if permitted&(1<<c.bit) != 0 {
			names = append(names, c.name)
		}
	}
	return strings.Join(names, ",")
}

// checkSUID finds set-uid programs in directories anyone can write to. A root
// shell copy dropped in /tmp is the fastest way back in, and nothing legitimate
// installs there.
func (a *audit) checkSUID() {
	walked := 0
	for _, d := range []string{"tmp", "var/tmp", "dev/shm"} {
		base := filepath.Join(a.root, d)
		walkedRoot := safefs.WalkRoot(base)
		// The walk stops at maxWalk entries, and everything under it is then
		// uninspected. A set-uid binary in that remainder would not be
		// reported, so the tree is recorded as incomplete rather than left
		// looking clean.
		capped := false
		err := filepath.WalkDir(walkedRoot, func(p string, e fs.DirEntry, err error) error { // audit:ok the root is safefs.WalkRoot, which resolves a symlinked root
			if err != nil {
				// A root that is not there is the documented skip, so one
				// default list works across hosts. Any other error leaves a
				// subtree nothing looked at, which is a coverage gap.
				if p != walkedRoot || !errors.Is(err, fs.ErrNotExist) {
					if rel, relErr := filepath.Rel(a.root, p); relErr == nil {
						a.noteUnreadable(rel)
					}
				}
				return nil
			}
			if walked++; walked > a.maxWalk {
				capped = true
				return filepath.SkipAll
			}
			if !e.Type().IsRegular() {
				return nil
			}
			fi, err := e.Info()
			if err != nil || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) == 0 {
				return nil
			}
			rel, _ := filepath.Rel(a.root, p)
			a.add(Finding{Class: "persist.suid.writable-dir", Score: 9, Technique: techSUID, Path: rel,
				Detail: "a set-uid or set-gid program sits in a world-writable directory", Evidence: fi.Mode().String()})
			return nil
		})
		if err != nil || capped {
			// Two ways the tree was not fully inspected: the walk itself
			// stopped early, or the entry limit cut it. Either way the rest of
			// the tree was never looked at, and a set-uid binary in it would
			// not be reported — so the tree is named as incomplete coverage
			// rather than left looking clean.
			if rel, relErr := filepath.Rel(a.root, walkedRoot); relErr == nil {
				a.noteUnreadable(rel)
			}
		}
	}
}
