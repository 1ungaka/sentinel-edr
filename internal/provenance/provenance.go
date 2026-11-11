// Package provenance answers one question per scanned file: does the host's
// package manager own it, and does its content still match what the package
// shipped?
//
// It is a read-only resolver over the package databases present on the host.
// dpkg (/var/lib/dpkg: status, info/*.list, info/*.md5sums, diversions) and
// pacman (/var/lib/pacman/local/*/{desc,files,mtree}) are loose files and are
// read directly. rpm keeps its file manifest in a Berkeley DB / SQLite rpmdb,
// not in loose files, and the engine never shells out, so a host that only has
// an rpmdb gets State Unsupported.
//
// The index is built once, lazily, on the first lookup, in memory, keyed by the
// cleaned absolute path with the merged-/usr spellings collapsed (/bin/ls and
// /usr/bin/ls are the same file on a merged host and resolve to the same
// entry). Every database file is read through internal/safefs (bounded,
// non-blocking, never a FIFO, never a symlink out of the database directory),
// lines are length-capped, a corrupt file is skipped with a note, and the
// whole index is capped at MaxPaths entries and MaxIndexBytes.
//
// Verification never re-reads the scanned file: the caller hands in the
// digests the engine already computed (MD5/SHA-1/SHA-256) and the resolver
// compares the one the package database recorded. A conffile (dpkg Conffiles,
// pacman %BACKUP%) is expected to differ from what shipped and is reported as
// OwnedConffile, never as modified.
//
// # What provenance does and does not say
//
// Provenance says a file is what the package shipped, per the host's own
// package database. It says nothing about whether the package itself is
// trustworthy: a malicious package is "intact". And the database is a file
// tree that root can write, so an attacker with root can make it agree with
// any file (rewrite the md5sums, add a conffile stanza, divert the path).
// Treat an "intact" answer as "the database and the file agree", not as a
// signature check; the packages' own signed manifests live in the archive,
// not on the host.
package provenance

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/1ungaka/sentinel-edr/internal/safefs"
)

// Bounds. A Kali install has about 4,300 packages and 650,000 database paths;
// the caps are an order of magnitude above a large desktop install and exist
// so that a hostile or runaway database cannot exhaust memory.
const (
	// MaxPaths caps the number of indexed paths across every package.
	MaxPaths = 2_000_000
	// MaxIndexBytes caps the estimated in-memory size of the index (the path
	// bytes plus a fixed per-entry and per-directory overhead).
	MaxIndexBytes = 64 << 20
	// MaxLineBytes caps one database line; a longer line is skipped.
	MaxLineBytes = 4096
	// MaxDBFileBytes caps one database file (a .list, .md5sums, status, an
	// mtree after decompression). Larger files are skipped with a note.
	MaxDBFileBytes = 64 << 20
	// MaxDBFiles caps the number of entries read from one database directory.
	MaxDBFiles = 1 << 17
	// MaxNotes caps the notes kept about skipped or corrupt database files.
	MaxNotes = 64

	// entryOverhead and dirOverhead are the per-entry and per-directory
	// constants of the MaxIndexBytes estimate (map slot, value, string header).
	entryOverhead = 64
	dirOverhead   = 64
	// sniffBytes is how much of a modified file is read to tell an executable
	// from data for the modified-system-binary observation.
	sniffBytes = 64
)

// Managers.
const (
	ManagerDpkg   = "dpkg"
	ManagerPacman = "pacman"
	ManagerRPM    = "rpm"
)

// State is the resolver's answer for one path.
type State string

const (
	// OwnedIntact: a package owns the path and the scanned digest matches the
	// digest the package database recorded.
	OwnedIntact State = "owned-intact"
	// OwnedModified: a package owns the path, the database recorded a digest,
	// and the scanned digest differs. The file is not a conffile.
	OwnedModified State = "owned-modified"
	// OwnedConffile: a package owns the path as a configuration file, which the
	// administrator is expected to edit; it is never reported as modified.
	OwnedConffile State = "owned-conffile"
	// OwnedUnverifiable: a package owns the path but recorded no digest for it
	// (a symlink, a directory, a package without md5sums), or the scan
	// produced no digest of the recorded algorithm.
	OwnedUnverifiable State = "owned-unverifiable"
	// Unowned: a package database was loaded completely and no package lists
	// the path.
	Unowned State = "unowned"
	// Unsupported: the host's package manager keeps its manifest in a form
	// this resolver does not read (rpm).
	Unsupported State = "unsupported"
	// Unknown: no package database was found, the one found could not be read,
	// or the index was truncated at its cap so an absence proves nothing.
	Unknown State = "unknown"
)

// Owned reports whether the state names an owning package.
func (s State) Owned() bool {
	switch s {
	case OwnedIntact, OwnedModified, OwnedConffile, OwnedUnverifiable:
		return true
	}
	return false
}

// Provenance is the answer for one scanned file.
type Provenance struct {
	// Manager is "dpkg", "pacman" or "rpm" (unsupported), empty when no
	// database was found.
	Manager string `json:"manager,omitempty"`
	// Package and Version name the owning package; empty unless State.Owned().
	Package string `json:"package,omitempty"`
	Version string `json:"version,omitempty"`
	State   State  `json:"state"`
	// ShippedDigest is the lower-case hex digest the package database recorded
	// for the path, with DigestAlgo its algorithm ("md5" or "sha256"). Set for
	// every owned path that has one, including conffiles.
	ShippedDigest string `json:"shipped_digest,omitempty"`
	DigestAlgo    string `json:"digest_algo,omitempty"`
	// Finding is the modified-system-binary observation, set only when State
	// is OwnedModified and the file is an executable or library. It is an
	// observation outside the verdict: see Finding.
	Finding *Finding `json:"finding,omitempty"`
}

// Summary is the one-line form for a human: "dpkg coreutils 9.4-3 (intact)".
func (p Provenance) Summary() string {
	switch {
	case p.State.Owned():
		s := p.Manager + " " + p.Package
		if p.Version != "" {
			s += " " + p.Version
		}
		return s + " (" + shortState(p.State) + ")"
	case p.Manager != "":
		return p.Manager + " (" + string(p.State) + ")"
	default:
		return string(p.State)
	}
}

func shortState(s State) string {
	switch s {
	case OwnedIntact:
		return "intact"
	case OwnedModified:
		return "MODIFIED"
	case OwnedConffile:
		return "conffile"
	case OwnedUnverifiable:
		return "unverifiable"
	}
	return string(s)
}

// Finding classes and the technique they carry.
const (
	// ClassModifiedSystemBinary: a package-owned executable or library whose
	// content no longer matches the package's recorded digest and that is not
	// a conffile. The classic shape of a trojaned system binary.
	ClassModifiedSystemBinary = "provenance.modified-system-binary"
	// TechniqueModifiedSystemBinary is ATT&CK T1554, Compromise Host Software
	// Binary.
	TechniqueModifiedSystemBinary = "T1554"
)

// Finding is the modified-system-binary observation. It is deliberately not
// scored: it is reported beside the verdict, not folded into it, because the
// engine's fusion lattice is assembled inside the scanner and no weight for
// this source has been measured.
type Finding struct {
	Class     string `json:"class"`
	Technique string `json:"technique"`
	// Kind is "elf" or "script" (an interpreter line).
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Digests are the digests the engine computed for the scanned file, as
// lower-case or upper-case hex; empty when not computed.
type Digests struct {
	MD5, SHA1, SHA256 string
}

// fileKey identifies one indexed path: the id of its (canonical) directory
// and its base name. Keying on the directory id rather than the full path
// stores each directory string once; keying on the pair rather than nesting
// a map per directory avoids a Go map's fixed cost for every small directory
// (a /usr/share/doc tree has tens of thousands with one or two files each).
type fileKey struct {
	dir  uint32
	base string
}

// fileEntry is one indexed path. The digest lives in the resolver's digest
// arena: md5 (16 bytes) for dpkg, sha256 (32) or md5 (16) for pacman; dlen is
// 0 when none was recorded.
type fileEntry struct {
	pkg      uint32
	dig      uint32
	dlen     uint8
	conffile bool
}

type pkgInfo struct {
	name, version string
}

type limits struct {
	paths      int
	indexBytes int64
	fileBytes  int64
}

// Resolver is the lazily loaded index over the host's package database. It is
// safe for concurrent lookups once built; the build itself runs once.
type Resolver struct {
	root string
	lim  limits

	once sync.Once

	manager   string
	dirIDs    map[string]uint32
	files     map[fileKey]fileEntry
	digests   []byte
	pkgs      []pkgInfo
	pkgIndex  map[string]uint32
	aliases   []alias
	divert    map[string]diversion
	notes     []string
	noteCount int
	entries   int
	bytes     int64
	truncated bool
	loaded    bool
	scratch   []byte
	lastDir   string
	lastDirID uint32
}

type alias struct{ from, to string }

type diversion struct{ to, pkg string }

// New returns a resolver over the package databases under root ("/" for the
// running host; a test tree otherwise). Nothing is read until the first
// Lookup, Load or Manager call.
func New(root string) *Resolver {
	if root == "" {
		root = string(filepath.Separator)
	}
	return &Resolver{
		root: filepath.Clean(root),
		lim:  limits{paths: MaxPaths, indexBytes: MaxIndexBytes, fileBytes: MaxDBFileBytes},
	}
}

// Load builds the index now instead of on the first lookup. It is idempotent.
func (r *Resolver) Load() { r.once.Do(r.load) }

// Manager reports which package database was found: "dpkg", "pacman", "rpm"
// (present but unsupported) or "" (none).
func (r *Resolver) Manager() string {
	r.Load()
	return r.manager
}

// Notes lists the database files that were skipped or truncated, bounded.
func (r *Resolver) Notes() []string {
	r.Load()
	out := append([]string(nil), r.notes...)
	if r.noteCount > len(r.notes) {
		out = append(out, fmt.Sprintf("%d further note(s) not shown", r.noteCount-len(r.notes)))
	}
	return out
}

// Stats reports the size of the index: packages, paths and whether the path
// or byte cap truncated it.
func (r *Resolver) Stats() (packages, paths int, truncated bool) {
	r.Load()
	return len(r.pkgs), r.entries, r.truncated
}

// Summary is one status line for the operator.
func (r *Resolver) Summary() string {
	r.Load()
	switch r.manager {
	case "":
		return "no package database found under " + r.root
	case ManagerRPM:
		return "rpm database found under " + r.root + " (unsupported: rpm keeps its file manifest in the rpmdb, not loose files)"
	}
	s := fmt.Sprintf("%s: %d package(s), %d path(s) indexed", r.manager, len(r.pkgs), r.entries)
	if r.truncated {
		s += " (index truncated at its cap: unlisted paths are reported unknown, not unowned)"
	}
	if r.noteCount > 0 {
		s += fmt.Sprintf(", %d note(s)", r.noteCount)
	}
	return s
}

// Lookup resolves one scanned path against the index. path is the path the
// engine scanned (relative paths are made absolute); d are the digests it
// computed. The file is read only in one case: an owned, modified, non-conffile
// path is sniffed (its first 64 bytes) to tell an executable from data for the
// modified-system-binary observation.
func (r *Resolver) Lookup(path string, d Digests) Provenance {
	r.Load()
	switch r.manager {
	case "":
		return Provenance{State: Unknown}
	case ManagerRPM:
		return Provenance{Manager: ManagerRPM, State: Unsupported}
	}
	if !r.loaded {
		return Provenance{Manager: r.manager, State: Unknown}
	}
	key, ok := r.keyFor(path)
	if !ok {
		return Provenance{Manager: r.manager, State: Unknown}
	}
	dir, base := splitKey(key)
	e, found := r.lookupEntry(dir, base)
	if !found {
		if r.truncated {
			return Provenance{Manager: r.manager, State: Unknown}
		}
		return Provenance{Manager: r.manager, State: Unowned}
	}
	p := Provenance{Manager: r.manager}
	if int(e.pkg) < len(r.pkgs) { // audit:ok e.pkg is a uint32 and int is 64-bit here: the conversion cannot go negative
		p.Package, p.Version = r.pkgs[e.pkg].name, r.pkgs[e.pkg].version
	}
	var scanned string
	switch e.dlen {
	case 16:
		p.DigestAlgo, scanned = "md5", d.MD5
	case 32:
		p.DigestAlgo, scanned = "sha256", d.SHA256
	}
	if e.dlen > 0 && int(e.dig)+int(e.dlen) <= len(r.digests) { // audit:ok uint32 and uint8 into a 64-bit int: never negative, and the sum is checked against the arena length
		p.ShippedDigest = hex.EncodeToString(r.digests[e.dig : e.dig+uint32(e.dlen)])
	}
	switch {
	case e.conffile:
		p.State = OwnedConffile
	case e.dlen == 0 || scanned == "":
		p.State = OwnedUnverifiable
	case strings.EqualFold(strings.TrimSpace(scanned), p.ShippedDigest):
		p.State = OwnedIntact
	default:
		p.State = OwnedModified
		if kind := sniffExecutable(path); kind != "" {
			p.Finding = &Finding{
				Class:     ClassModifiedSystemBinary,
				Technique: TechniqueModifiedSystemBinary,
				Kind:      kind,
				Detail: fmt.Sprintf("%s owned by %s %s no longer matches the package's recorded %s (shipped %s); not a conffile",
					kindLabel(kind), p.Manager, p.Package, p.DigestAlgo, p.ShippedDigest),
			}
		}
	}
	return p
}

func kindLabel(kind string) string {
	if kind == "script" {
		return "script with an interpreter line"
	}
	return "ELF executable or library"
}

// sniffExecutable reads the first bytes of path through safefs and reports
// "elf", "script" or "" (data, unreadable, not a regular file).
func sniffExecutable(path string) string {
	f, _, err := safefs.Open(path)
	if err != nil { // audit:ok "" is this function's "not classifiable": the caller then records the modified state without the executable observation, never a success
		return ""
	}
	defer f.Close()
	buf := make([]byte, sniffBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return ""
	}
	buf = buf[:n]
	switch {
	case bytes.HasPrefix(buf, []byte("\x7fELF")):
		return "elf"
	case bytes.HasPrefix(buf, []byte("#!")):
		return "script"
	}
	return ""
}

// keyFor turns a scanned path into an index key: absolute, cleaned, with the
// root prefix stripped and the merged-/usr spellings collapsed.
func (r *Resolver) keyFor(path string) (string, bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	abs = filepath.ToSlash(filepath.Clean(abs))
	if r.root != "/" && r.root != "" {
		root := filepath.ToSlash(r.root)
		switch {
		case abs == root:
			return "", false
		case strings.HasPrefix(abs, root+"/"):
			abs = abs[len(root):]
		}
	}
	if !strings.HasPrefix(abs, "/") {
		return "", false
	}
	return r.canon(abs), true
}

// canon collapses a merged-/usr spelling: with /bin -> usr/bin on the host,
// "/bin/ls" becomes "/usr/bin/ls". Only the directory prefix is rewritten.
func (r *Resolver) canon(p string) string {
	for _, a := range r.aliases {
		if p == a.from {
			return a.to
		}
		if strings.HasPrefix(p, a.from+"/") {
			return a.to + p[len(a.from):]
		}
	}
	return p
}

func splitKey(key string) (dir, base string) {
	i := strings.LastIndexByte(key, '/')
	if i < 0 {
		return "/", key
	}
	if i == 0 {
		return "/", key[1:]
	}
	return key[:i], key[i+1:]
}

// lookupEntry finds one indexed path by its canonical directory and base.
func (r *Resolver) lookupEntry(dir, base string) (fileEntry, bool) {
	id, ok := r.dirIDs[dir]
	if !ok {
		return fileEntry{}, false
	}
	e, ok := r.files[fileKey{dir: id, base: base}]
	return e, ok
}

// ── loading ──────────────────────────────────────────────────────────────────

func (r *Resolver) load() {
	r.dirIDs = map[string]uint32{}
	r.files = map[fileKey]fileEntry{}
	r.pkgIndex = map[string]uint32{}
	r.divert = map[string]diversion{}
	r.loadAliases()

	dpkgDir := filepath.Join(r.root, "var", "lib", "dpkg")
	pacmanDir := filepath.Join(r.root, "var", "lib", "pacman", "local")
	switch {
	case isDir(filepath.Join(dpkgDir, "info")):
		r.manager = ManagerDpkg
		r.loaded = r.loadDpkg(dpkgDir)
	case isDir(pacmanDir):
		r.manager = ManagerPacman
		r.loaded = r.loadPacman(pacmanDir)
	case isDir(filepath.Join(r.root, "var", "lib", "rpm")), isDir(filepath.Join(r.root, "usr", "lib", "sysimage", "rpm")):
		r.manager = ManagerRPM
	}
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// loadAliases records the merged-/usr directory symlinks (/bin -> usr/bin,
// /lib64 -> usr/lib64, ...) present under the root, so both spellings of a
// path land on one key. A target outside the root is ignored.
func (r *Resolver) loadAliases() {
	for _, name := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		p := filepath.Join(r.root, name)
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, err := os.Readlink(p)
		if err != nil || target == "" {
			continue
		}
		target = filepath.ToSlash(target)
		if !strings.HasPrefix(target, "/") {
			target = "/" + target
		}
		target = filepath.ToSlash(filepath.Clean(target))
		if target == "/"+name || target == "/" || strings.HasPrefix(target, "/..") {
			continue
		}
		r.aliases = append(r.aliases, alias{from: "/" + name, to: target})
	}
	// Longest prefix first so /lib64 is not rewritten by /lib's rule.
	sort.Slice(r.aliases, func(i, j int) bool { return len(r.aliases[i].from) > len(r.aliases[j].from) })
}

func (r *Resolver) note(format string, a ...interface{}) {
	r.noteCount++
	if len(r.notes) < MaxNotes {
		r.notes = append(r.notes, fmt.Sprintf(format, a...))
	}
}

// pkgID interns a package name and returns its index. The version is set
// when first known.
func (r *Resolver) pkgID(name, version string) uint32 {
	if id, ok := r.pkgIndex[name]; ok {
		if version != "" && r.pkgs[id].version == "" {
			r.pkgs[id].version = version
		}
		return id
	}
	id := uint32(len(r.pkgs))
	r.pkgs = append(r.pkgs, pkgInfo{name: name, version: version})
	r.pkgIndex[name] = id
	return id
}

// insert adds or updates one path, given as database bytes with or without
// the leading slash. A caller passing a digest sets it; a caller passing
// conffile marks it; neither clears what another record set. It reports false
// once the index is at its cap.
//
// It is the hot loop of the load (a million lines on a desktop install), so
// it works on byte slices and allocates only for a new directory or a new
// path: an already-clean path is split in place, and the merged-/usr rewrite
// and filepath.Clean run only when a line needs them.
func (r *Resolver) insert(p []byte, pkg uint32, digest []byte, conffile bool) bool {
	if r.truncated {
		return false
	}
	// Absolute, cleaned, canonical, in the scratch buffer (no allocation on
	// the common path).
	r.scratch = r.scratch[:0]
	if len(p) == 0 || p[0] != '/' {
		r.scratch = append(r.scratch, '/')
	}
	r.scratch = append(r.scratch, p...)
	if !isCleanAbs(r.scratch) {
		r.scratch = append(r.scratch[:0], cleanAbs(string(r.scratch))...)
	}
	r.canonBytes()
	key := r.scratch
	if len(r.divert) > 0 {
		if dv, ok := r.divert[string(key)]; ok && dv.pkg != r.pkgs[pkg].name {
			// Another package diverted this path: the file this package
			// shipped now lives at the diversion target.
			r.scratch = append(r.scratch[:0], r.canon(dv.to)...)
			key = r.scratch
		}
	}
	i := bytes.LastIndexByte(key, '/')
	var dir, base []byte
	switch {
	case i <= 0:
		dir, base = key[:1], key[i+1:]
	default:
		dir, base = key[:i], key[i+1:]
	}
	if len(base) == 0 {
		return true // the root itself
	}
	// Database files list a directory's files together, so the directory of
	// the previous line is the usual answer: one byte compare instead of a
	// map lookup.
	var id uint32
	if r.lastDir != "" && string(dir) == r.lastDir {
		id = r.lastDirID
	} else {
		var ok bool
		id, ok = r.dirIDs[string(dir)]
		if !ok {
			if r.entries >= r.lim.paths || r.bytes+int64(len(dir))+dirOverhead > r.lim.indexBytes {
				r.truncated = true
				return false
			}
			id = uint32(len(r.dirIDs))
			r.dirIDs[string(dir)] = id
			r.bytes += int64(len(dir)) + dirOverhead
		}
		r.lastDir, r.lastDirID = string(dir), id
	}
	fk := fileKey{dir: id, base: string(base)}
	e, exists := r.files[fk]
	if !exists {
		if r.entries >= r.lim.paths || r.bytes+int64(len(base))+entryOverhead > r.lim.indexBytes {
			r.truncated = true
			return false
		}
		r.entries++
		r.bytes += int64(len(base)) + entryOverhead
	}
	// A conffile record (from status / %BACKUP%) pins the owner; a .list or
	// md5sums line for the same path from the same package keeps it.
	if !e.conffile || e.pkg == pkg {
		e.pkg = pkg
	}
	if conffile {
		e.conffile = true
	}
	if n := len(digest); n == 16 || n == 32 {
		if int(e.dlen) == n && int(e.dig)+n <= len(r.digests) {
			copy(r.digests[e.dig:], digest) // same algorithm: overwrite in place
		} else {
			e.dig = uint32(len(r.digests))
			r.digests = append(r.digests, digest...)
			r.bytes += int64(n)
		}
		e.dlen = uint8(n)
	}
	r.files[fk] = e
	return true
}

// canonBytes applies the merged-/usr aliases to the path in r.scratch.
func (r *Resolver) canonBytes() {
	for _, a := range r.aliases {
		p := r.scratch
		if len(p) < len(a.from) || string(p[:len(a.from)]) != a.from {
			continue
		}
		if len(p) == len(a.from) || p[len(a.from)] == '/' {
			rest := append([]byte(nil), p[len(a.from):]...)
			r.scratch = append(append(r.scratch[:0], a.to...), rest...)
			return
		}
	}
}

// isCleanAbs reports whether p is an absolute path filepath.Clean would
// return unchanged: no empty, "." or ".." segment and no trailing slash.
func isCleanAbs(p []byte) bool {
	if len(p) == 0 || p[0] != '/' {
		return false
	}
	if len(p) == 1 {
		return true
	}
	if p[len(p)-1] == '/' || bytes.Contains(p, []byte("//")) { // audit:ok len(p) == 0 and len(p) == 1 returned above
		return false
	}
	// Only a "/." can start a "." or ".." segment; most paths have none.
	for rest := p; ; {
		i := bytes.Index(rest, []byte("/."))
		if i < 0 {
			return true
		}
		seg := rest[i+2:]
		if len(seg) == 0 || seg[0] == '/' {
			return false // "/." segment
		}
		if seg[0] == '.' && (len(seg) == 1 || seg[1] == '/') {
			return false // "/.." segment
		}
		rest = seg
	}
}

// readDB reads one database file through safefs: never a symlink in the final
// component, never a FIFO or device, never more than the file cap.
func (r *Resolver) readDB(path string) ([]byte, bool) {
	data, _, err := safefs.ReadFileNoFollow(path, r.lim.fileBytes)
	if err != nil {
		r.note("skipped %s: %v", filepath.Base(path), err)
		return nil, false
	}
	return data, true
}

// forEachLine calls fn for every line of data, without the line ending. A
// line longer than MaxLineBytes is skipped and counted; fn returns false to
// stop. The number of skipped lines is returned.
func forEachLine(data []byte, fn func(line []byte) bool) (skipped int) {
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		var line []byte
		if i < 0 {
			line, data = data, nil
		} else {
			line, data = data[:i], data[i+1:]
		}
		if len(line) > MaxLineBytes {
			skipped++
			continue
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if !fn(line) {
			return skipped
		}
	}
	return skipped
}

// listDir lists a database directory, bounded, skipping symlinked entries
// (never follow a link out of the database directory). Names are returned
// sorted so loading is deterministic.
func (r *Resolver) listDir(dir string) ([]os.DirEntry, bool) {
	f, err := os.Open(dir)
	if err != nil {
		r.note("cannot open %s: %v", dir, err)
		return nil, false
	}
	defer f.Close()
	var out []os.DirEntry
	for len(out) < MaxDBFiles {
		batch, err := f.ReadDir(1024)
		for _, d := range batch {
			if d.Type()&os.ModeSymlink != 0 {
				r.note("skipped %s: symbolic link in the database directory", d.Name())
				continue
			}
			out = append(out, d)
		}
		if err != nil {
			break
		}
	}
	if len(out) >= MaxDBFiles {
		r.note("%s: more than %d entries; the rest were not read", dir, MaxDBFiles)
		r.truncated = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, true
}

// validHex reports whether s is a lower-case or upper-case hex digest of n
// bytes and returns the decoded bytes.
func validHex(s []byte, n int) ([]byte, bool) {
	if len(s) != 2*n {
		return nil, false
	}
	out := make([]byte, n) // audit:ok n is the digest length the caller names (16 or 32) and len(s) == 2*n was checked
	if _, err := hex.Decode(out, s); err != nil {
		return nil, false
	}
	return out, true
}
