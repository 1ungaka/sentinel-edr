package provenance

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// loadPacman indexes a pacman local database (/var/lib/pacman/local): one
// directory per installed package holding
//
//   - desc: "%NAME%\n<name>\n\n%VERSION%\n<version>\n\n..." sections;
//   - files: "%FILES%" (paths relative to "/", directories end in "/") and
//     "%BACKUP%" (conffile equivalent: "<path>\t<md5>");
//   - mtree: a gzip-compressed mtree(5) manifest with md5digest and
//     sha256digest per file. sha256 is what is indexed.
//
// A symlinked package directory is skipped. It reports whether anything
// usable was read.
func (r *Resolver) loadPacman(dir string) bool {
	entries, ok := r.listDir(dir)
	if !ok {
		return false
	}
	seen := false
	for _, d := range entries {
		if r.truncated {
			break
		}
		if !d.IsDir() {
			continue
		}
		pkgDir := filepath.Join(dir, d.Name())
		name, version := r.parsePacmanDesc(pkgDir)
		if name == "" {
			name = d.Name()
		}
		pkg := r.pkgID(name, version)
		if data, ok := r.readOptionalDB(filepath.Join(pkgDir, "files")); ok {
			seen = true
			r.parsePacmanFiles(d.Name(), data, pkg)
		}
		if data, ok := r.readMtree(filepath.Join(pkgDir, "mtree")); ok {
			seen = true
			r.parseMtree(d.Name(), data, pkg)
		}
	}
	return seen
}

// readOptionalDB is readDB without a note for a file that is simply absent.
func (r *Resolver) readOptionalDB(path string) ([]byte, bool) {
	if _, err := os.Lstat(path); err != nil {
		return nil, false
	}
	return r.readDB(path)
}

// parsePacmanDesc reads %NAME% and %VERSION% from desc.
func (r *Resolver) parsePacmanDesc(pkgDir string) (name, version string) {
	data, ok := r.readOptionalDB(filepath.Join(pkgDir, "desc"))
	if !ok {
		return "", ""
	}
	section := ""
	forEachLine(data, func(line []byte) bool {
		s := string(bytes.TrimSpace(line))
		switch {
		case s == "":
			section = ""
		case strings.HasPrefix(s, "%") && strings.HasSuffix(s, "%"):
			section = s
		case section == "%NAME%" && name == "":
			name = s
		case section == "%VERSION%" && version == "":
			version = s
		}
		return name == "" || version == ""
	})
	return name, version
}

// parsePacmanFiles indexes the %FILES% paths (no digest) and the %BACKUP%
// paths (conffiles, with their shipped md5).
func (r *Resolver) parsePacmanFiles(name string, data []byte, pkg uint32) {
	section := ""
	bad := 0
	skipped := forEachLine(data, func(line []byte) bool {
		if len(line) == 0 {
			return true
		}
		if line[0] == '%' {
			section = string(line)
			return true
		}
		switch section {
		case "%FILES%":
			if line[len(line)-1] == '/' { // audit:ok an empty line returned at the top of this callback
				return true // directory
			}
			return r.insert(line, pkg, nil, false)
		case "%BACKUP%":
			p, sum, _ := bytes.Cut(line, []byte("\t"))
			if len(p) == 0 {
				bad++
				return true
			}
			var digest []byte
			if d, ok := validHex(bytes.TrimSpace(sum), 16); ok {
				digest = d
			}
			return r.insert(p, pkg, digest, true)
		}
		return true
	})
	if skipped > 0 || bad > 0 {
		r.note("%s/files: %d over-long and %d malformed line(s) skipped", name, skipped, bad)
	}
}

// readMtree reads and decompresses a gzip mtree, bounded by the file cap on
// both the compressed and the decompressed size. A plain-text mtree (no gzip
// magic) is accepted as is.
func (r *Resolver) readMtree(path string) ([]byte, bool) {
	raw, ok := r.readOptionalDB(path)
	if !ok {
		return nil, false
	}
	if !bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) {
		return raw, true
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		r.note("skipped %s: %v", filepath.Base(filepath.Dir(path))+"/mtree", err)
		return nil, false
	}
	defer zr.Close()
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(zr, r.lim.fileBytes+1))
	if err != nil {
		r.note("skipped %s: %v", filepath.Base(filepath.Dir(path))+"/mtree", err)
		return nil, false
	}
	if n > r.lim.fileBytes {
		r.note("skipped %s: decompresses past the %d byte cap", filepath.Base(filepath.Dir(path))+"/mtree", r.lim.fileBytes)
		return nil, false
	}
	return buf.Bytes(), true
}

// parseMtree indexes the file entries of an mtree(5) manifest. "/set" lines
// carry defaults (type=...), "/unset" clears them, and an entry line is
// "./path key=value ...". Only type=file entries with a digest are indexed;
// paths use the octal escapes of vis(3) for whitespace and backslashes.
func (r *Resolver) parseMtree(name string, data []byte, pkg uint32) {
	setType := ""
	bad := 0
	skipped := forEachLine(data, func(line []byte) bool {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			return true
		}
		fields := bytes.Fields(line)
		if len(fields) == 0 {
			return true
		}
		head := string(fields[0])
		switch head {
		case "/set":
			for _, kv := range fields[1:] {
				if k, v, ok := bytes.Cut(kv, []byte("=")); ok && string(k) == "type" {
					setType = string(v)
				}
			}
			return true
		case "/unset":
			for _, kv := range fields[1:] {
				if string(kv) == "type" {
					setType = ""
				}
			}
			return true
		}
		if !strings.HasPrefix(head, "./") || strings.HasPrefix(head, "./.") {
			if !strings.HasPrefix(head, "./.") {
				bad++
			}
			return true
		}
		typ := setType
		var sha256, md5 []byte
		for _, kv := range fields[1:] {
			k, v, ok := bytes.Cut(kv, []byte("="))
			if !ok {
				continue
			}
			switch string(k) {
			case "type":
				typ = string(v)
			case "sha256digest":
				if d, ok := validHex(v, 32); ok {
					sha256 = d
				}
			case "md5digest":
				if d, ok := validHex(v, 16); ok {
					md5 = d
				}
			}
		}
		if typ != "file" {
			return true
		}
		p, ok := unvis(head[1:])
		if !ok {
			bad++
			return true
		}
		digest := sha256
		if digest == nil {
			digest = md5
		}
		return r.insert([]byte(p), pkg, digest, false)
	})
	if skipped > 0 || bad > 0 {
		r.note("%s/mtree: %d over-long and %d malformed line(s) skipped", name, skipped, bad)
	}
}

// unvis decodes the "\ooo" octal escapes an mtree path carries. Any other
// backslash sequence is malformed.
func unvis(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			sb.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", false
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", false
		}
		sb.WriteByte(byte(v))
		i += 3
	}
	return sb.String(), true
}
