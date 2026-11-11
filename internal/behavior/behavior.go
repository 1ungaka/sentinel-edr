// Package behavior is the sensor-side rule set for the host techniques: the
// things a process does to the *host* rather than to a file.
//
// The file detectors answer "is this file malicious". These answer "is
// something on this host arranging for the next file to be missed": an
// auditor library injected into every process, a fanotify listener that
// ignores the events it was given, a systemd generator that adds a unit at
// boot, a BPF program attached to the audit hooks.
//
// The benign anchor is provenance. A distribution package that ships an
// auditor, a fanotify watcher or a systemd generator is ordinary software, and
// the package database says so; the same thing dropped on the host by hand is
// not. Every inventory check here reconciles against it, and an inventory
// whose benign anchor cannot be read says so rather than calling everything
// suspicious.
package behavior

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/s-b-repo/cau/internal/provenance"
	"github.com/s-b-repo/cau/internal/safefs"
)

// The novel-technique ids this package reports. They are the plan's
// detection-first catalogue entries, not MITRE techniques: the behaviour is
// real and the mapping is not, and the ids say so.
const (
	// NovelAuditLibrary is the LD_AUDIT / LD_PRELOAD inventory (NOVEL-007).
	NovelAuditLibrary = "NOVEL-007"
	// NovelFanotify is the fanotify listener inventory (NOVEL-008).
	NovelFanotify = "NOVEL-008"
	// NovelGenerator is the systemd generator inventory (NOVEL-009).
	NovelGenerator = "NOVEL-009"
	// NovelBPFProgram is the in-kernel BPF program inventory (NOVEL-010).
	NovelBPFProgram = "NOVEL-010"
)

// Classes are the finding classes this package emits.
const (
	// ClassAuditLibrary is an auditor library loaded into processes that no
	// package owns.
	ClassAuditLibrary = "behavior.audit-library"
	// ClassFanotify is a fanotify listener that is not package-owned.
	ClassFanotify = "behavior.fanotify-listener"
	// ClassFanotifyMask is a fanotify listener that ignores events.
	ClassFanotifyMask = "behavior.fanotify-ignored-mask"
	// ClassGenerator is a systemd generator unit that no package owns.
	ClassGenerator = "behavior.systemd-generator"
	// ClassBPFProgram is a pinned BPF program that no package owns.
	ClassBPFProgram = "behavior.bpf-program"
)

// Finding is one observation about the host's behaviour.
type Finding struct {
	// Class is the stable identifier of the observation.
	Class string `json:"class"`
	// Score is how much the observation is worth. The inventory classes are
	// state, not proof: they score below the threshold on their own, because
	// a host administrator may legitimately install any of them.
	Score int `json:"score"`
	// Novel is the plan's technique id.
	Novel string `json:"novel,omitempty"`
	// Technique is the ATT&CK technique, when the behaviour maps to one.
	Technique string `json:"technique,omitempty"`
	// Detail says what was found.
	Detail string `json:"detail"`
	// Evidence names the thing found (a path, a process), never its content.
	Evidence string `json:"evidence,omitempty"`
	// Owner is the package that owns the thing, when one does.
	Owner string `json:"owner,omitempty"`
}

// Result is the outcome of the checks.
type Result struct {
	// Findings are the observations, strongest first.
	Findings []Finding `json:"findings,omitempty"`
	// Checked is how many processes and inventories were read.
	Checked int `json:"checked"`
	// Provenance says whether the benign anchor was available ("dpkg",
	// "pacman", or "" when there is no package database). Without it every
	// inventory check reports what it found and says the anchor was missing.
	Provenance string `json:"provenance,omitempty"`
	// Notes say what could not be read.
	Notes []string `json:"notes,omitempty"`
}

// generatorDirs are the directories a systemd generator is installed in.
//
// /usr/lib/systemd/system-generators is left out: it is owned by the systemd
// package, so everything in it is accounted for. The other two are where a
// generator that no package owns would be put, and where systemd reads it
// from at every boot.
var generatorDirs = []string{
	"etc/systemd/system-generators",
	"usr/local/lib/systemd/system-generators",
}

// noAnchor records, once, that the package database could not answer the
// question the inventories ask it, so a path that no package owns could not be
// told apart from a path the database never saw.
//
// The note matters more than the silence it replaces: without it the host
// looks clean because the checks had nothing to say, rather than because
// nothing was found.
func (r *Result) noAnchor() {
	const note = "the package database could not say whether a path is owned, so the inventories below have no benign anchor"
	for _, n := range r.Notes {
		if n == note {
			return
		}
	}
	r.Notes = append(r.Notes, note)
}

// Options configure the checks.
type Options struct {
	// ProcRoot overrides "/proc".
	ProcRoot string
	// Root overrides "/" for the other surfaces (the systemd generator
	// directory, the bpffs root).
	Root string
	// Resolver is the provenance resolver. When nil, one is built over Root.
	Resolver *provenance.Resolver
	// MaxProcesses caps how many processes are read.
	MaxProcesses int
}

// Defaults for the options.
const (
	defaultMaxProcesses = 4096
	// maxEnvironBytes bounds one process's environment block.
	maxEnvironBytes = 64 << 10
)

// Check runs the host-behaviour checks.
//
// The checks are read-only: they look at what the host is doing, and they
// never change it.
func Check(opts Options) *Result {
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.MaxProcesses <= 0 {
		opts.MaxProcesses = defaultMaxProcesses
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = provenance.New(opts.Root)
	}

	r := &Result{}
	r.Provenance = resolver.Manager()
	if r.Provenance == "" {
		r.Notes = append(r.Notes, "no package database was found: the inventories below have no benign anchor, so they report nothing")
	}

	procs := readProcesses(opts.ProcRoot, opts.MaxProcesses, r)
	r.Checked = len(procs)

	// ── the auditor-library inventory (NOVEL-007) ──
	for _, p := range procs {
		for _, env := range p.environment {
			name, value, ok := strings.Cut(env, "=")
			if !ok {
				continue
			}
			switch name {
			case "LD_AUDIT", "LD_PRELOAD":
			default:
				continue
			}
			for _, so := range strings.Split(value, ":") {
				so = strings.TrimSpace(so)
				if so == "" {
					continue
				}
				owner, known := ownerOf(resolver, so)
				if owner != "" {
					// A package that ships the auditor is ordinary
					// software; the package database is the anchor.
					continue
				}
				if !known {
					r.noAnchor()
					continue
				}
				r.Findings = append(r.Findings, Finding{
					Class:     ClassAuditLibrary,
					Score:     4,
					Novel:     NovelAuditLibrary,
					Technique: "T1574.006",
					Detail:    name + " loads a library no package owns: " + so,
					Evidence:  p.exe,
				})
			}
		}
	}

	// ── the fanotify inventory (NOVEL-008) ──
	for _, p := range procs {
		for _, fan := range p.fanotify {
			owner, known := ownerOf(resolver, p.exe)
			if owner != "" {
				continue
			}
			if !known {
				r.noAnchor()
				continue
			}
			r.Findings = append(r.Findings, Finding{
				Class:    ClassFanotify,
				Score:    4,
				Novel:    NovelFanotify,
				Detail:   "a fanotify listener no package owns is watching the filesystem",
				Evidence: p.exe,
			})
			if mask := suppressedEvents(fan.ignored); mask != "" {
				r.Findings = append(r.Findings, Finding{
					Class:    ClassFanotifyMask,
					Score:    6,
					Novel:    NovelFanotify,
					Detail:   "the fanotify listener suppresses events it was asked not to miss (" + mask + ")",
					Evidence: p.exe,
				})
			}
		}
	}

	// ── the systemd generator inventory (NOVEL-009) ──
	//
	// A generator is *installed* in one of the directories below. The
	// runtime directory (/run/systemd/generator) holds what systemd's own
	// generators produced at boot — every systemd host has entries there,
	// none of them is an installation, and the package database lists none
	// of them, so looking there reports the host's own systemd as an
	// unowned generator on every run.
	for _, dir := range generatorDirs {
		full := filepath.Join(opts.Root, dir)
		units, err := listDir(full)
		if err != nil {
			r.Notes = append(r.Notes, "the systemd generator directory "+full+" could not be read: "+err.Error())
			continue
		}
		for _, unit := range units {
			if strings.HasSuffix(unit, ".wants") || strings.HasSuffix(unit, ".requires") {
				continue
			}
			path := filepath.Join(full, unit)
			owner, known := ownerOf(resolver, path)
			if owner != "" {
				continue
			}
			if !known {
				r.noAnchor()
				continue
			}
			r.Findings = append(r.Findings, Finding{
				Class:    ClassGenerator,
				Score:    5,
				Novel:    NovelGenerator,
				Detail:   "a systemd generator unit no package owns is installed and adds itself at every boot",
				Evidence: path,
			})
		}
	}

	// ── the pinned BPF program inventory (NOVEL-010) ──
	programs, err := listDir(filepath.Join(opts.Root, "sys/fs/bpf"))
	if err != nil {
		r.Notes = append(r.Notes, "the bpffs root could not be read: "+err.Error())
	}
	for _, obj := range programs {
		path := filepath.Join(opts.Root, "sys/fs/bpf", obj)
		owner, known := ownerOf(resolver, path)
		if owner != "" {
			continue
		}
		if !known {
			r.noAnchor()
			continue
		}
		r.Findings = append(r.Findings, Finding{
			Class:    ClassBPFProgram,
			Score:    5,
			Novel:    NovelBPFProgram,
			Detail:   "a pinned BPF object no package owns is loaded into the kernel",
			Evidence: path,
		})
	}

	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.Evidence < b.Evidence
	})
	return r
}

// procInfo is the little the checks need from one process.
type procInfo struct {
	pid int
	exe string
	// environment is the process's environment block, NUL-separated.
	environment []string
	// fanotify is what the process's fanotify file descriptors say.
	fanotify []fanotifyInfo
}

// fanotifyInfo is one fanotify file descriptor's masks.
type fanotifyInfo struct {
	// ignored is the union of the events the listener's marks asked not to
	// be told about.
	ignored uint64
	// marks is how many marks the group has.
	marks int
}

// readProcesses reads the process table for the checks.
func readProcesses(procRoot string, max int, r *Result) []procInfo {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		r.Notes = append(r.Notes, "the process table could not be read: "+err.Error())
		return nil
	}
	var out []procInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil { // audit:ok the process table holds entries that are not PIDs; they are not processes
			continue
		}
		if len(out) >= max {
			r.Notes = append(r.Notes, fmt.Sprintf("more than %d processes; the rest were not read", max))
			break
		}
		out = append(out, readProcess(procRoot, pid))
	}
	return out
}

// readProcess reads one process's environment and fanotify descriptors.
//
// The environment belongs to the process that set it: it is read with the
// process's own permissions, so an unreadable one is unreadable rather than
// empty.
func readProcess(procRoot string, pid int) procInfo {
	p := procInfo{pid: pid}
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	if link, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		// The kernel appends " (deleted)" to the link when the binary has
		// been unlinked. The package database lists the path without it,
		// so the suffix is trimmed before the lookup: a package-owned
		// binary that was replaced is still package-owned.
		p.exe = strings.TrimSuffix(link, " (deleted)")
	}
	if data, err := safefs.ReadFile(filepath.Join(base, "environ"), maxEnvironBytes); err == nil {
		for _, env := range strings.Split(string(data), "\x00") {
			if env != "" {
				p.environment = append(p.environment, env)
			}
		}
	}
	p.fanotify = readFanotify(base)
	return p
}

// readFanotify reads the fanotify file descriptors of one process.
//
// The kernel describes a fanotify file descriptor in its fdinfo: the mark,
// the mask and the events it asked not to be told about.
func readFanotify(base string) []fanotifyInfo {
	fds, err := os.ReadDir(filepath.Join(base, "fd"))
	if err != nil { // audit:ok the process is gone or its descriptor table is unreadable: either way there is no listener to report
		return nil
	}
	var out []fanotifyInfo
	for _, fd := range fds {
		data, err := safefs.ReadFile(filepath.Join(base, "fdinfo", fd.Name()), 8<<10)
		if err != nil { // audit:ok one descriptor that cannot be read is one descriptor with no fanotify line in it
			continue
		}
		info := fanotifyInfo{}
		for _, line := range strings.Split(string(data), "\n") {
			mask, ok := parseFanotifyLine(line)
			if !ok {
				continue
			}
			info.ignored |= mask
			info.marks++
		}
		if info.marks > 0 {
			out = append(out, info)
		}
	}
	return out
}

// parseFanotifyLine reads one line of a fanotify fdinfo and returns the events
// the listener asked not to be told about, and whether the line was a fanotify
// line at all.
//
// The kernel has written this line in two shapes. Since Linux 4.19 it is
//
//	fanotify sdev:%x mflags:%x mask:%x ignored_mask:%x
//
// one line per mark, and the older shape was
//
//	fanotify: group=%x mask=%x mark=%x ignored=%x
//
// The engine parsed only the older one, so on every current kernel the
// fanotify inventory saw nothing at all: the check never fired, and the host
// it was written for was reported as having no listener.
func parseFanotifyLine(line string) (uint64, bool) {
	if !strings.HasPrefix(line, "fanotify") {
		return 0, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "fanotify"))
	rest = strings.TrimPrefix(rest, ":")
	// The kernel writes the masks space separated; some kernels comma them,
	// so both are split.
	fields := strings.FieldsFunc(rest, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	})
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			// The current shape separates the key and the value with a
			// colon: "ignored_mask:4000".
			key, value, ok = strings.Cut(field, ":")
			if !ok {
				continue
			}
		}
		switch key {
		case "ignored", "ign", "ignored_mask":
			n, err := strconv.ParseUint(value, 16, 64)
			if err != nil { // audit:ok a field that is not a hex mask is not the one being read, and the line says which one is
				continue
			}
			return n, true
		}
	}
	return 0, false
}

// fanotifyEvents names the event classes in a suppress mask, from
// include/uapi/linux/fanotify.h. A mark's ignore mask says which events the
// listener will not be told about.
var fanotifyEvents = []struct {
	bit  uint64
	name string
}{
	{0x00000001, "FAN_ACCESS"},
	{0x00000002, "FAN_MODIFY"},
	{0x00000004, "FAN_ATTRIB"},
	{0x00000008, "FAN_CLOSE_WRITE"},
	{0x00000010, "FAN_CLOSE_NOWRITE"},
	{0x00000020, "FAN_OPEN"},
	{0x00000040, "FAN_MOVED_FROM"},
	{0x00000080, "FAN_MOVED_TO"},
	{0x00000100, "FAN_CREATE"},
	{0x00000200, "FAN_DELETE"},
	{0x00000400, "FAN_DELETE_SELF"},
	{0x00000800, "FAN_MOVE_SELF"},
	{0x00004000, "FAN_Q_OVERFLOW"},
	{0x00010000, "FAN_OPEN_EXEC"},
	{0x00020000, "FAN_ACCESS_PERM"},
	{0x00040000, "FAN_OPEN_EXEC_PERM"},
	{0x00080000, "FAN_OPEN_PERM"},
	{0x00100000, "FAN_OPEN_BY_HANDLE_PERM"},
	{0x01000000, "FAN_ONDIR"},
	{0x02000000, "FAN_EVENT_ONCHILD"},
}

// fanotifySecurityEvents are the suppressions worth reporting.
//
// A mark's ignore mask is empty for an ordinary watcher, and a listener that
// does not want directory events is ordinary software. What is worth reporting
// is a listener that will not hear about the loss of its own queue: it can
// miss events without knowing it missed them.
var fanotifySecurityEvents = []uint64{0x00004000} // FAN_Q_OVERFLOW

// suppressedEvents names the event classes a listener asked not to be told
// about that matter, or returns "" when it suppressed none that matter.
func suppressedEvents(mask uint64) string {
	if mask == 0 {
		return ""
	}
	var names []string
	for _, e := range fanotifyEvents {
		if mask&e.bit == 0 {
			continue
		}
		for _, sec := range fanotifySecurityEvents {
			if e.bit == sec {
				names = append(names, e.name)
			}
		}
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ",")
}

// ownerOf asks the package database who owns a path.
//
// The second answer says whether the first is worth anything. A package
// database that was not read (none was found, the one found could not be read,
// or the index was truncated at its cap) and a package manager this resolver
// does not read (rpm) cannot say that no package owns a path. Treating that
// silence as "nobody owns it" reports every library, every fanotify listener,
// every generator unit and every pinned BPF object on the host as unowned —
// which is the whole host flagged, on every distribution whose package
// database this resolver does not read.
func ownerOf(r *provenance.Resolver, path string) (owner string, known bool) {
	if r == nil {
		return "", false
	}
	p := r.Lookup(path, provenance.Digests{})
	switch p.State {
	case provenance.Unowned:
		return "", true // the database was read, and no package lists this path
	case provenance.Unknown, provenance.Unsupported:
		return "", false
	}
	return p.Package, true
}

// listDir lists the names in a directory, sorted.
//
// A directory that is *absent* yields nothing and no error: the surfaces here
// (a systemd generator directory, a bpffs root) are absent on most hosts, and
// an absent surface has nothing to report. A directory that exists and cannot
// be read is a different thing — a permission problem — and it is returned as
// an error so the layer can say so.
func listDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}
