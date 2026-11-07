package peeler

import (
	"bytes"
	"compress/flate"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
	"sync"
)

// The registry has two kinds of layer, and they need different evidence.
//
// A base decoder over the wrong alphabet produces random bytes, so "the output
// is a known format or clean text" (plausible) tells a right guess from a wrong
// one. A substitution cipher is different: rotating text gives more text, every
// time, on every file. Taken at face value each rotation would be one more
// layer, every layer adds to the depth score, and an ordinary README would read
// as a deep obfuscation chain. A substitution therefore has to reveal something
// that was not visible before (reveals), which plain rotated text never does.

const (
	// peekWindow bounds what a trial looks at. Thirty ciphers run per node, so
	// the cost of a trial has to be independent of the size of the file.
	peekWindow = 4096
	// maxPeekDepth is how many encodings a trial looks through. rot13 over
	// base64 over base64 over gzip still reads as a reveal; past that, a chain
	// is exposed one layer at a time as the walk descends.
	maxPeekDepth = 3
	// minPlainFraction is the printable share at which output counts as text.
	minPlainFraction = 0.95
)

func window(b []byte) []byte {
	if len(b) > peekWindow {
		return b[:peekWindow]
	}
	return b
}

// printableFraction is the share of b that is printable ASCII or whitespace.
func printableFraction(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t' {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

// plausible is the bar for a base decoder's output. An archive counts beside the
// formats reveals knows: its four-byte magic does not come out of a wrong guess.
func plausible(b []byte) bool {
	return len(b) > 0 && (printableFraction(window(b)) >= minPlainFraction || reveals(b) || zipLayer{}.Detect(b))
}

// reveals is the bar for a substitution: b is, or decodes to, something known.
func reveals(b []byte) bool {
	w := window(b)
	if revealsAt(w, 0, true) {
		return true
	}
	// A reversed encoding keeps its alphabet, so it survives into the next
	// cipher trial only if the trial can see through it.
	return isToken(textBody(w)) && peekEncoded(reversed(w), 1, true, isCut(w))
}

// isCut reports a window that is the head of something longer, so an encoding
// in it may stop in the middle of a group.
func isCut(w []byte) bool { return len(w) >= peekWindow }

// revealsPayload is the bar for lifting a blob out of a file: under however many
// encodings, there is a format or a script. Text alone is not enough here. A file
// of test vectors or SSH keys is full of runs that decode to text, and each would
// open a branch.
func revealsPayload(b []byte) bool { return revealsAt(window(b), 0, false) }

// isToken reports one unbroken run of visible characters, which is what an
// encoding is. Everything else leaves the expensive path on its first space.
func isToken(s []byte) bool {
	for _, c := range s {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	return len(s) > 0
}

func revealsAt(w []byte, depth int, textCounts bool) bool {
	return revealsCut(w, depth, textCounts, isCut(w))
}

// revealsCut is revealsAt for a blob decoded out of a window: it is cut short if
// the window was, whatever its own length.
func revealsCut(w []byte, depth int, textCounts, cut bool) bool {
	if knownFormat(w) || scriptLike(w) {
		return true
	}
	return depth < maxPeekDepth && peekEncoded(w, depth, textCounts, cut)
}

// peekEncoded reports a window that decodes, under some base, to a known format
// or to clean text. Text is enough here where it is not for a cipher: a wrong
// guess at a base gives noise, so text coming out means the guess was right, and
// the next layer down in a long chain is usually one more encoding.
func peekEncoded(w []byte, depth int, textCounts, cut bool) bool {
	s := bytes.TrimRight(textBody(w), "=")
	if len(s) < minLayerLen || !isToken(s) {
		return false
	}
	found := func(out []byte) bool {
		return len(out) >= minLayerLen/2 &&
			((textCounts && printableFraction(out) >= minPlainFraction) || revealsCut(out, depth+1, textCounts, cut))
	}
	buf := make([]byte, len(s))
	if base64Shaped(s) {
		chunk := s[:len(s)-len(s)%4]
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if n, err := enc.Decode(buf, chunk); err == nil && found(buf[:n]) {
				return true
			}
		}
	}
	if len(s)%2 == 0 {
		if n, err := hex.Decode(buf, s); err == nil && found(buf[:n]) {
			return true
		}
	}
	chunk := s[:len(s)-len(s)%8]
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	if n, err := enc.Decode(buf, chunk); err == nil && found(buf[:n]) {
		return true
	}
	for _, l := range peekBases() {
		if !l.detect(s) {
			continue
		}
		out, ok := l.decode(s)
		// A window that stops inside a group does not decode as it stands. The
		// base64 and base32 trials above drop the partial group; the grouped
		// bases here (five digits for base85, three for base45) need the same.
		for drop := 1; !ok && cut && drop < maxGroup && drop < len(s); drop++ {
			out, ok = l.decode(s[:len(s)-drop])
		}
		if ok && found(out) {
			return true
		}
	}
	return false
}

// maxGroup is the longest digit group of any base here (base85's five).
const maxGroup = 5

// peekBases is the baseLayers a trial can look through. It is built on first use
// because the layers themselves call back into reveals.
var peekBases = sync.OnceValue(func() (out []baseLayer) {
	for _, u := range baseLayers() {
		if l, ok := u.(baseLayer); ok {
			out = append(out, l)
		}
	}
	return out
})

func base64Shaped(s []byte) bool {
	for _, c := range s {
		if !base64Byte(c) {
			return false
		}
	}
	return true
}

func base64Byte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '-' || c == '_'
}

// knownFormat reports a format this package can act on, checked strictly enough
// that thirty trial transforms of random bytes do not produce one by chance.
func knownFormat(b []byte) bool {
	switch {
	case len(b) >= 5 && b[0] == 0x7f && string(b[1:4]) == "ELF":
		return b[4] == 1 || b[4] == 2
	case validPE(b):
		return true
	case len(b) >= 3 && b[0] == 0x1f && b[1] == 0x8b && b[2] == 0x08:
		return true
	case len(b) >= 10 && string(b[:3]) == "BZh" && b[3] >= '1' && b[3] <= '9' && string(b[4:10]) == "1AY&SY":
		return true
	case realShebang(b):
		return true
	case zlibLayer{}.Detect(b) && len(b) > 2:
		return inflatesToText(b[2:])
	}
	return false
}

// realShebang wants an interpreter path, because a rotation leaves punctuation
// alone: rot13 of "#!/bin/sh" still starts "#!/", as "#!/ova/fu".
func realShebang(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte("#!"))
	if len(b) == 0 {
		return false
	}
	b = bytes.TrimLeft(b[:min(len(b), 8)], " ")
	for _, dir := range []string{"/bin/", "/usr/", "/sbin/", "/opt/"} {
		if bytes.HasPrefix(b, []byte(dir)) {
			return true
		}
	}
	return false
}

func validPE(b []byte) bool {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	off := int64(b[0x3c]) | int64(b[0x3d])<<8 | int64(b[0x3e])<<16 | int64(b[0x3f])<<24
	return off+4 <= int64(len(b)) && string(b[off:off+4]) == "PE\x00\x00"
}

// inflatesToText reports raw DEFLATE that yields text or a known format. It has
// no header, so a guess has to prove itself on the output.
func inflatesToText(b []byte) bool {
	fr := flate.NewReader(bytes.NewReader(b))
	defer fr.Close()
	buf := make([]byte, 512)
	n, err := io.ReadFull(fr, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return false
	}
	out := buf[:n]
	return n >= minLayerLen*2 && (printableFraction(out) >= minPlainFraction || knownFormat(out))
}

// scriptKeywords are execution primitives. A strong one is enough with any other
// hit; two weak ones are needed, because a short token such as "exec(" turns up
// by chance when thirty rotations run over minified code.
var scriptKeywords = []struct {
	word   string
	strong bool
}{
	{"invoke-expression", true}, {"frombase64string", true}, {"downloadstring", true},
	{"invoke-webrequest", true}, {"net.webclient", true}, {"wscript.shell", true},
	{"shell.application", true}, {"set-executionpolicy", true}, {"-encodedcommand", true},
	{"base64_decode(", true}, {"gzinflate(", true}, {"createobject(", true}, {"/dev/tcp/", true},
	{"powershell", false}, {"/bin/bash", false}, {"/bin/sh", false}, {"cmd.exe", false},
	{"curl ", false}, {"wget ", false}, {"<?php", false}, {"eval(", false}, {"exec(", false},
	{"system(", false}, {"import socket", false}, {"subprocess.", false}, {"chmod +x", false},
}

// scriptLike reports text that executes something. It carries payloads with no
// shebang to carry them: a PowerShell stager, a PHP webshell body.
func scriptLike(w []byte) bool {
	if printableFraction(w) < 0.85 {
		return false
	}
	lower := bytes.ToLower(w)
	score := 0
	for _, k := range scriptKeywords {
		if bytes.Contains(lower, []byte(k.word)) {
			if k.strong {
				score += 2
			} else {
				score++
			}
			if score >= 2 {
				return true
			}
		}
	}
	return false
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}
