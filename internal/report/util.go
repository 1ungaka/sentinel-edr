package report

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SARIF result levels (SARIF 2.1.0 §3.27.10). Kept as strings because that is
// what the document carries and what WithSARIFLevels accepts.
const (
	LevelError   = "error"
	LevelWarning = "warning"
	LevelNote    = "note"
	LevelNone    = "none"
)

// osFileSize is the default StatFunc.
func osFileSize(p string) (int64, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// truncateString bounds s to maxRunes runes (after making it valid UTF-8) and
// appends TruncationMarker when it had to cut. maxRunes <= 0 means unlimited.
// The marker is appended on top of the limit, so the result may be slightly
// longer than maxRunes; callers that need a hard byte cap use truncateBytes.
func truncateString(s string, maxRunes int) (string, bool) {
	s = validUTF8(s)
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s, false
	}
	n := 0
	for i := range s {
		if n == maxRunes {
			return s[:i] + TruncationMarker, true
		}
		n++
	}
	return s, false
}

// truncateBytes bounds b to max bytes. max <= 0 means unlimited. The returned
// slice aliases b; callers must not modify it.
func truncateBytes(b []byte, max int) ([]byte, bool) {
	if max <= 0 || len(b) <= max {
		return b, false
	}
	return b[:max], true
}

// hexString renders bytes as lowercase hex.
func hexString(b []byte) string { return hex.EncodeToString(b) }

// preview renders a matched blob the way a human expects to read it: printable
// ASCII as-is, everything else as '.', cut at maxBytes. It never contains
// control characters, so it is safe to put on a terminal or in a log line.
func preview(b []byte, maxBytes int) string {
	cut, _ := truncateBytes(b, maxBytes)
	var sb strings.Builder
	sb.Grow(len(cut))
	for _, c := range cut {
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// TermSafe renders untrusted text for a terminal or a line-oriented log, showing
// control characters as visible escapes. A file name, process title or package
// field is whatever the attacker wants, and written raw it can erase its own
// report line, print a forged verdict after it, conceal the rest of the output,
// or set the clipboard. Newlines would forge a whole line. Bidi controls reorder
// what the analyst reads, so "evil\u202etxt.exe" displays as something else.
//
// The structured formats do not need this: their encoders escape already, and
// their consumers need the exact bytes.
func TermSafe(s string) string {
	if utf8.ValidString(s) && strings.IndexFunc(s, unsafeRune) < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1: // some terminals act on a bare 0x9b as CSI
			fmt.Fprintf(&sb, `\x%02x`, s[i])
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x100 && unsafeRune(r):
			fmt.Fprintf(&sb, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			sb.WriteRune(r)
		}
		i += n
	}
	return sb.String()
}

// unsafeRune reports a rune that changes how the surrounding text is displayed.
func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || unicode.In(r, unicode.Zl, unicode.Zp)
}

// boundedMessage is truncateString with the configured free-text cap.
func (c config) boundedMessage(s string) string {
	out, _ := truncateString(s, c.maxMessageRunes)
	return out
}

// boundedHash bounds a hash-shaped string. Hashes are also lower-cased so the
// document is canonical regardless of how the signature file spelled them.
func (c config) boundedHash(s string) string {
	out, _ := truncateString(strings.ToLower(s), c.maxHashChars)
	return out
}

var reSlug = regexp.MustCompile(`[^a-z0-9]+`)

// slug turns free text into a stable, URL- and id-safe token
// ("WannaCry Ransomware" -> "wannacry-ransomware").
func slug(s string) string {
	out := reSlug.ReplaceAllString(strings.ToLower(validUTF8(s)), "-")
	out = strings.Trim(out, "-")
	if out == "" {
		return "unnamed"
	}
	return out
}

// ── URIs ────────────────────────────────────────────────────────────────────

// toSlash normalises both POSIX and Windows separators to '/'. It is applied
// to every path that enters a URI so a report produced on Windows and one
// produced on Linux describe the same file the same way.
func toSlash(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

var reWindowsDrive = regexp.MustCompile(`^[A-Za-z]:/`)

// isAbsSlashPath reports whether a slash-normalised path is absolute on
// either platform ("/x", "C:/x", "//server/share").
func isAbsSlashPath(p string) bool {
	return strings.HasPrefix(p, "/") || reWindowsDrive.MatchString(p)
}

// relativeURI renders a file path for a SARIF artifactLocation.
//
// When root is set and the path lives underneath it, the result is a relative,
// forward-slash URI ("src/a.exe") and relative is true; the caller pairs it
// with uriBaseId "%SRCROOT%". Otherwise an absolute "file:" URI is returned
// when the path is absolute, or the cleaned relative path verbatim when it is
// not (there is no filesystem access here, so no attempt is made to resolve
// it against the working directory). Every segment is percent-encoded.
func relativeURI(root, p string) (uri string, relative bool) {
	sp := path.Clean(toSlash(strings.TrimSpace(p)))
	if sp == "." || sp == "" {
		return "", false
	}

	if root != "" {
		sr := path.Clean(toSlash(root))
		if rel, ok := relSlash(sr, sp); ok {
			return escapeSegments(rel), true
		}
	}

	if isAbsSlashPath(sp) {
		return fileURI(sp), false
	}
	return escapeSegments(sp), false
}

// relSlash returns p relative to root when p is root or lives under it. Both
// inputs are clean slash paths. The comparison is case-sensitive: SARIF
// consumers compare URIs byte-wise.
func relSlash(root, p string) (string, bool) {
	if root == "." || root == "" {
		// Everything relative is "under" the current directory, but an
		// absolute path is not.
		if isAbsSlashPath(p) || p == ".." || strings.HasPrefix(p, "../") {
			return "", false
		}
		return p, true
	}
	if p == root {
		return ".", true
	}
	prefix := root
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	if strings.HasPrefix(p, prefix) {
		return p[len(prefix):], true
	}
	return "", false
}

// fileURI renders an absolute slash path as a "file:" URI. Windows drive paths
// become file:///C:/...; POSIX paths become file:///abs/path.
func fileURI(p string) string {
	if reWindowsDrive.MatchString(p) {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	return u.String()
}

// escapeSegments percent-encodes each segment of a relative slash path without
// touching the separators.
func escapeSegments(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

// rootURI renders the configured root as the base URI for %SRCROOT%, with the
// trailing slash SARIF requires on a base. Empty when no root is set or the
// root is not absolute.
func rootURI(root string) string {
	if root == "" {
		return ""
	}
	sr := path.Clean(toSlash(root))
	if !isAbsSlashPath(sr) {
		return ""
	}
	return strings.TrimSuffix(fileURI(sr), "/") + "/"
}
