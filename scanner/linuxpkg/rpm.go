package linuxpkg

import (
	"bytes"
	"encoding/binary"
)

// RPM stores its install scriptlets as plain, uncompressed strings in the
// package *header* (not in the compressed cpio payload), so the pure-Go scanner
// can read every %pre/%post/%preun/%postun/%pretrans/%posttrans script directly
// — no external rpm2cpio, no decompression. Reference: the RPM header is a
// self-describing (tag,type,offset,count) index over a byte store, documented in
// the RPM file-format spec and rpm's lib/header.c.

const rpmLeadLen = 96

var rpmHeaderMagic = []byte{0x8e, 0xad, 0xe8}

// RPM header tags for the install scriptlets and their interpreters.
const (
	rpmtagName          = 1000
	rpmtagPrein         = 1023
	rpmtagPostin        = 1024
	rpmtagPreun         = 1025
	rpmtagPostun        = 1026
	rpmtagPreinProg     = 1085
	rpmtagPostinProg    = 1086
	rpmtagPreunProg     = 1087
	rpmtagPostunProg    = 1088
	rpmtagPretrans      = 1151
	rpmtagPosttrans     = 1152
	rpmtagPretransProg  = 1153
	rpmtagPosttransProg = 1154
)

// scriptletTags maps a scriptlet tag to the human label used in evidence.
var scriptletTags = map[uint32]string{
	rpmtagPrein:     "%pre",
	rpmtagPostin:    "%post",
	rpmtagPreun:     "%preun",
	rpmtagPostun:    "%postun",
	rpmtagPretrans:  "%pretrans",
	rpmtagPosttrans: "%posttrans",
}

// progTags maps an interpreter-program tag to the scriptlet it belongs to, so an
// unusual interpreter (e.g. a scriptlet declared to run under python/perl rather
// than /bin/sh) can be surfaced.
var progTags = map[uint32]string{
	rpmtagPreinProg:     "%pre",
	rpmtagPostinProg:    "%post",
	rpmtagPreunProg:     "%preun",
	rpmtagPostunProg:    "%postun",
	rpmtagPretransProg:  "%pretrans",
	rpmtagPosttransProg: "%posttrans",
}

const (
	rpmTypeString      = 6
	rpmTypeStringArray = 8
	rpmTypeI18NString  = 9
)

type rpmEntry struct {
	tag, typ, offset, count uint32
}

func parseRPM(data []byte) *container {
	c := &container{format: FormatRPM}
	if len(data) < rpmLeadLen+16 || !bytes.Equal(data[:4], magicRPM) {
		c.warning = "not an RPM lead"
		return c
	}

	off := rpmLeadLen
	// Signature header: parse only to learn its size so we can skip it, then
	// 8-byte-align to reach the main header.
	_, _, next, ok := readRPMHeader(data, off)
	if !ok {
		c.warning = "malformed RPM signature header"
		return c
	}
	off = align8(next)

	entries, store, _, ok := readRPMHeader(data, off)
	if !ok {
		c.warning = "malformed RPM main header"
		return c
	}

	for _, e := range entries {
		switch {
		case e.tag == rpmtagName:
			if s := rpmString(store, e); s != "" {
				c.name = s
			}
		case scriptletTags[e.tag] != "":
			label := scriptletTags[e.tag]
			if body := rpmString(store, e); body != "" {
				c.scripts = append(c.scripts, scriptSource{name: label, body: capStr(body)})
				c.scriptNames = append(c.scriptNames, label)
			}
		case progTags[e.tag] != "":
			if interp := rpmString(store, e); interp != "" && unusualInterp(interp) {
				c.findings = append(c.findings, Finding{
					Class: "linuxpkg.rpm.scriptlet-interpreter", Score: 3, Technique: techUnixShell,
					Detail:   "a scriptlet is declared to run under a non-shell interpreter",
					Evidence: progTags[e.tag] + " -> " + interp,
				})
			}
		}
	}
	return c
}

// readRPMHeader parses one RPM header structure beginning at off and returns its
// index entries, its data store, and the offset just past the store. It is fully
// bounds-checked and cap-guarded so a hostile header cannot over-read or force a
// huge allocation.
func readRPMHeader(data []byte, off int) (entries []rpmEntry, store []byte, end int, ok bool) {
	if off < 0 || off+16 > len(data) {
		return nil, nil, 0, false
	}
	if !bytes.Equal(data[off:off+3], rpmHeaderMagic) {
		return nil, nil, 0, false
	}
	nindex := binary.BigEndian.Uint32(data[off+8 : off+12])
	hsize := binary.BigEndian.Uint32(data[off+12 : off+16])
	if nindex > maxRPMIndexEntries || hsize > maxRPMHeaderStore {
		return nil, nil, 0, false
	}
	idxStart := off + 16
	storeStart := idxStart + int(nindex)*16
	storeEnd := storeStart + int(hsize)
	if storeStart < idxStart || storeEnd < storeStart || storeEnd > len(data) {
		return nil, nil, 0, false
	}
	entries = make([]rpmEntry, 0, nindex)
	for i := 0; i < int(nindex); i++ {
		b := data[idxStart+i*16 : idxStart+i*16+16]
		entries = append(entries, rpmEntry{
			tag:    binary.BigEndian.Uint32(b[0:4]),
			typ:    binary.BigEndian.Uint32(b[4:8]),
			offset: binary.BigEndian.Uint32(b[8:12]),
			count:  binary.BigEndian.Uint32(b[12:16]),
		})
	}
	return entries, data[storeStart:storeEnd], storeEnd, true
}

// rpmString reads the (first) string value of a STRING / I18NSTRING /
// STRING_ARRAY entry from the store. Returns "" on any out-of-range or wrong
// type.
func rpmString(store []byte, e rpmEntry) string {
	if e.typ != rpmTypeString && e.typ != rpmTypeI18NString && e.typ != rpmTypeStringArray {
		return ""
	}
	if uint64(e.offset) >= uint64(len(store)) {
		return ""
	}
	seg := store[e.offset:]
	z := bytes.IndexByte(seg, 0x00)
	if z < 0 {
		z = len(seg)
	}
	return string(seg[:z])
}

func align8(n int) int {
	if r := n % 8; r != 0 {
		return n + (8 - r)
	}
	return n
}

// unusualInterp reports whether an interpreter path is something other than the
// ordinary POSIX shell a scriptlet normally runs under.
func unusualInterp(prog string) bool {
	switch prog {
	case "", "/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "<lua>":
		return false
	}
	return true
}
