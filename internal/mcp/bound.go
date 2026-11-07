package mcp

import (
	"strings"
	"unicode/utf8"

	"github.com/s-b-repo/cau/internal/report"
)

// Bounding helpers for file-derived text. Every string an analysis tool lifts
// out of a sample (a firmware module name, a DMI serial, a boot-entry
// description, an ESP path) is whatever the sample's author wanted it to be.
// The JSON encoder keeps the channel intact, but the agent on the other end
// renders the text, so control and bidi characters are shown as visible
// escapes (report.TermSafe) and the length is capped so one hostile field
// cannot blow out the agent's context. A cut is marked, never silent.

// maxFieldRunes caps one file-derived string. Long enough for any legitimate
// path, name or variable value; short enough that fifty of them stay small.
const maxFieldRunes = 256

// truncationMarker is appended when a string was cut.
const truncationMarker = "...[truncated]"

// boundStr renders an untrusted string for an agent: valid UTF-8, visible
// escapes for control characters, at most maxFieldRunes runes.
func boundStr(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	if utf8.RuneCountInString(s) > maxFieldRunes {
		n := 0
		for i := range s {
			if n == maxFieldRunes {
				s = s[:i] + truncationMarker
				break
			}
			n++
		}
	}
	return report.TermSafe(s)
}

// boundStrs bounds a list of untrusted strings: each element through boundStr,
// and at most maxListItems of them. It returns the kept slice and how many
// were omitted.
func boundStrs(in []string) (out []string, omitted int) {
	for i, s := range in {
		if i >= maxListItems {
			return out, len(in) - maxListItems
		}
		out = append(out, boundStr(s))
	}
	return out, 0
}
