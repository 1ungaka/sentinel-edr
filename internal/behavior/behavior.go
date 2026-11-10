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
		r.Notes = append(r.Notes, "no package database was found: the inventories below are reported without a benign anchor")
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
				owner := ownerOf(resolver, so)
				if owner != "" {
					// A package that ships the auditor is ordinary
					// software; the package database is the anchor.
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
			owner := ownerOf(resolver, p.exe)
			if owner != "" {
				continue
			}
			r.Findings = append(r.Findings, Finding{
				Class:    ClassFanotify,
				Score:    4,
				Novel:    NovelFanotify,
				Detail:   "a fanotify listener no package owns is watching the filesystem",
				Evidence: p.exe,
			})
			if fan.ignored != "" && fan.ignored != "0" {
				r.Findings = append(r.Findings, Finding{
					Class:    ClassFanotifyMask,
					Score:    6,
					Novel:    NovelFanotify,
					Detail:   "the fanotify listener ignores events (" + fan.ignored + ")",
					Evidence: p.exe,
				})
			}
		}
	}

	// ── the systemd generator inventory (NOVEL-009) ──
	generators, err := listDir(filepath.Join(opts.Root, "run/systemd/generator"))
	if err != nil {
		r.Notes = append(r.Notes, "the systemd generator directory could not be read: "+err.Error())
	}
	for _, unit := range generators {
		if strings.HasSuffix(unit, ".wants") || strings.HasSuffix(unit, ".requires") {
			continue
		}
		path := filepath.Join(opts.Root, "run/systemd/generator", unit)
		owner := ownerOf(resolver, path)
		if owner != "" {
			continue
		}
		r.Findings = append(r.Findings, Finding{
			Class:    ClassGenerator,
			Score:    5,
			Novel:    NovelGenerator,
			Detail:   "a systemd generator unit no package owns adds itself at every boot",
			Evidence: path,
		})
	}

	// ── the pinned BPF program inventory (NOVEL-010) ──
	programs, err := listDir(filepath.Join(opts.Root, "sys/fs/bpf"))
	if err != nil {
		r.Notes = append(r.Notes, "the bpffs root could not be read: "+err.Error())
	}
	for _, obj := range programs {
		path := filepath.Join(opts.Root, "sys/fs/bpf", obj)
		owner := ownerOf(resolver, path)
		if owner != "" {
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
	// ignored is the mask of events the listener asked not to be told about.
	ignored string
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
		p.exe = link
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
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "fanotify:") {
				continue
			}
			info := fanotifyInfo{}
			// The kernel writes the masks as "group=1 mask=1f mark=1f
			// ignored=8", space separated; some kernels comma them, so
			// both are split.
			fields := strings.FieldsFunc(strings.TrimPrefix(line, "fanotify:"), func(r rune) bool {
				return r == ' ' || r == ',' || r == '\t'
			})
			for _, field := range fields {
				key, value, ok := strings.Cut(field, "=")
				if !ok {
					continue
				}
				switch key {
				case "ignored", "ign":
					info.ignored = value
				}
			}
			out = append(out, info)
		}
	}
	return out
}

// ownerOf asks the package database who owns a path. An empty answer means no
// package owns it, which is the interesting case.
func ownerOf(r *provenance.Resolver, path string) string {
	if r == nil {
		return ""
	}
	p := r.Lookup(path, provenance.Digests{})
	if p.Package == "" {
		return ""
	}
	return p.Package
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
