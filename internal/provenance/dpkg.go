package provenance

import (
	"bytes"
	"path/filepath"
	"strings"
)

// loadDpkg indexes a dpkg database directory (/var/lib/dpkg):
//
//   - status: one stanza per package; Package, Version, Architecture, and the
//     Conffiles field, whose continuation lines are " /path md5 [flag]".
//     Conffiles are indexed first so their owner and digest are pinned.
//   - diversions: triples of lines (from, to, package). A package other than
//     the diverter that ships `from` has its file at `to`.
//   - info/<pkg>.list: one absolute path per line, directories included
//     ("/." first). A line followed by a line that extends it with "/" is a
//     directory and is not indexed.
//   - info/<pkg>.md5sums: "<md5>  <path>" with the path relative to "/".
//
// The <pkg> stem may carry a ":<arch>" suffix (multi-arch); the version is
// looked up by the stem and then by the bare name.
//
// It reports whether anything usable was read.
func (r *Resolver) loadDpkg(dir string) bool {
	versions := map[string]string{}
	if data, ok := r.readDB(filepath.Join(dir, "status")); ok {
		r.parseDpkgStatus(data, versions)
	}
	if data, ok := r.readDB(filepath.Join(dir, "diversions")); ok {
		r.parseDpkgDiversions(data)
	}
	infoDir := filepath.Join(dir, "info")
	entries, ok := r.listDir(infoDir)
	if !ok {
		return false
	}
	seenList := false
	for _, d := range entries {
		if r.truncated {
			break
		}
		name := d.Name()
		var stem string
		switch {
		case strings.HasSuffix(name, ".list"):
			stem = strings.TrimSuffix(name, ".list")
		case strings.HasSuffix(name, ".md5sums"):
			stem = strings.TrimSuffix(name, ".md5sums")
		default:
			continue
		}
		if stem == "" {
			continue
		}
		if !d.Type().IsRegular() {
			r.note("skipped %s: not a regular file (%s)", name, d.Type())
			continue
		}
		data, ok := r.readDB(filepath.Join(infoDir, name))
		if !ok {
			continue
		}
		version := versions[stem]
		if version == "" {
			if bare, _, found := strings.Cut(stem, ":"); found {
				version = versions[bare]
			}
		}
		pkg := r.pkgID(stem, version)
		if strings.HasSuffix(name, ".list") {
			seenList = true
			r.parseDpkgList(name, data, pkg)
		} else {
			r.parseDpkgMD5Sums(name, data, pkg)
		}
	}
	return seenList || len(versions) > 0
}

// parseDpkgStatus reads Package/Version/Architecture and Conffiles stanzas.
func (r *Resolver) parseDpkgStatus(data []byte, versions map[string]string) {
	var pkg, version, arch string
	var conffiles [][]byte
	inConffiles := false
	flush := func() {
		if pkg == "" {
			return
		}
		versions[pkg] = version
		if arch != "" {
			versions[pkg+":"+arch] = version
		}
		if len(conffiles) > 0 {
			// Conffiles are recorded under the bare package name (what the
			// stanza says), even when the .list stem carries ":<arch>".
			id := r.pkgID(pkg, version)
			for _, cf := range conffiles {
				fields := bytes.Fields(cf)
				if len(fields) < 1 || len(fields[0]) == 0 || fields[0][0] != '/' {
					continue
				}
				var digest []byte
				if len(fields) >= 2 {
					if d, ok := validHex(fields[1], 16); ok {
						digest = d
					}
				}
				if !r.insert(fields[0], id, digest, true) {
					return
				}
			}
		}
		pkg, version, arch, conffiles = "", "", "", nil
	}
	skipped := forEachLine(data, func(line []byte) bool {
		switch {
		case len(line) == 0:
			flush()
			inConffiles = false
			return !r.truncated
		case line[0] == ' ' || line[0] == '\t':
			if inConffiles {
				conffiles = append(conffiles, line)
			}
			return true
		}
		inConffiles = false
		key, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			return true
		}
		value = bytes.TrimSpace(value)
		switch string(key) {
		case "Package":
			pkg = string(value)
		case "Version":
			version = string(value)
		case "Architecture":
			arch = string(value)
		case "Conffiles":
			inConffiles = true
		}
		return true
	})
	flush()
	if skipped > 0 {
		r.note("status: %d over-long line(s) skipped", skipped)
	}
}

// parseDpkgDiversions reads the diversions file: lines in triples.
func (r *Resolver) parseDpkgDiversions(data []byte) {
	var triple [3]string
	n := 0
	bad := 0
	forEachLine(data, func(line []byte) bool {
		triple[n%3] = string(line)
		n++
		if n%3 == 0 {
			from, to, pkg := triple[0], triple[1], triple[2]
			if strings.HasPrefix(from, "/") && strings.HasPrefix(to, "/") && pkg != "" {
				r.divert[r.canon(cleanAbs(from))] = diversion{to: cleanAbs(to), pkg: pkg}
			} else {
				bad++
			}
		}
		return len(r.divert) < MaxDBFiles
	})
	if bad > 0 || n%3 != 0 {
		r.note("diversions: %d malformed record(s) ignored", bad+boolInt(n%3 != 0))
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseDpkgList indexes a .list file. Directories are detected by the next
// line extending the current one; the trailing entry of a file is never a
// directory with contents, so it is indexed (a harmless extra entry for an
// empty directory).
func (r *Resolver) parseDpkgList(name string, data []byte, pkg uint32) {
	var prev []byte
	havePrev := false
	bad := 0
	emit := func(line []byte) bool {
		if len(line) == 0 || line[0] != '/' {
			bad++
			return true
		}
		if bytes.Equal(line, []byte("/.")) {
			return true
		}
		return r.insert(line, pkg, nil, false)
	}
	skipped := forEachLine(data, func(line []byte) bool {
		if havePrev {
			isDir := len(line) > len(prev) && bytes.HasPrefix(line, prev) && line[len(prev)] == '/'
			if !isDir && !emit(prev) {
				return false
			}
		}
		prev = append(prev[:0], line...)
		havePrev = true
		return true
	})
	if havePrev && !r.truncated {
		emit(prev)
	}
	if skipped > 0 || bad > 0 {
		r.note("%s: %d over-long and %d malformed line(s) skipped", name, skipped, bad)
	}
}

// parseDpkgMD5Sums indexes a .md5sums file: "<32 hex>  <path>".
func (r *Resolver) parseDpkgMD5Sums(name string, data []byte, pkg uint32) {
	bad := 0
	skipped := forEachLine(data, func(line []byte) bool {
		if len(line) < 35 {
			bad++
			return true
		}
		digest, ok := validHex(line[:32], 16)
		if !ok || line[32] != ' ' {
			bad++
			return true
		}
		p := bytes.TrimLeft(line[33:], " *")
		if len(p) == 0 {
			bad++
			return true
		}
		return r.insert(p, pkg, digest, false)
	})
	if skipped > 0 || bad > 0 {
		r.note("%s: %d over-long and %d malformed line(s) skipped", name, skipped, bad)
	}
}

// cleanAbs cleans a database path as an absolute slash path: ".." segments
// collapse against "/", so a path cannot name anything outside the root.
func cleanAbs(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return filepath.ToSlash(filepath.Clean(p))
}
