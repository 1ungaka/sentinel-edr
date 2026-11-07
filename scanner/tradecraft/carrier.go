package tradecraft

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Decoding bounds. A hostile file must not turn this pass into a decompression
// bomb or a quadratic scan, so every layer draws on one budget.
const (
	maxDepth        = 4
	maxBlobs        = 64
	maxDecodedTotal = 16 << 20
	maxInflated     = 8 << 20
	minCarrierBytes = 32 // fewer bytes than this cannot hold a working stub
	maxEscapeGap    = 48 // quote, newline and "buf += b" between \x runs
)

var (
	hexListRe = regexp.MustCompile(`(?i)(?:0x[0-9a-f]{1,2}\s*,\s*){32,}0x[0-9a-f]{1,2}`)
	vbHexRe   = regexp.MustCompile(`(?i)(?:&h[0-9a-f]{1,2}\s*,\s*(?:_\s*\r?\n\s*)?){32,}&h[0-9a-f]{1,2}`)
	decListRe = regexp.MustCompile(`(?:\b\d{1,3}\s*,\s*(?:_\s*\r?\n\s*)?){32,}\d{1,3}\b`)
	base64Re  = regexp.MustCompile(`[A-Za-z0-9+/]{128,}={0,2}`)
)

type blob struct {
	kind string
	data []byte
}

// carriers extracts the byte arrays and encoded payloads a text file carries.
func carriers(text string, w *walker) []blob {
	var out []blob
	take := func(kind string, b []byte) {
		if len(b) < minCarrierBytes || len(out) >= maxBlobs || w.budget < len(b) {
			return
		}
		w.budget -= len(b)
		out = append(out, blob{kind, b})
	}
	if mayHoldHexList(text) {
		for _, m := range hexListRe.FindAllString(text, maxBlobs) {
			take("hex-list", parseNumbers(m, w.budget))
		}
	}
	if mayHoldVBHexList(text) {
		for _, m := range vbHexRe.FindAllString(text, maxBlobs) {
			take("hex-list", parseNumbers(m, w.budget))
		}
	}
	if mayHoldDecimalList(text) {
		for _, m := range decListRe.FindAllString(text, maxBlobs) {
			take("decimal-list", parseNumbers(m, w.budget))
		}
	}
	for _, run := range escapeRuns(text) {
		take("hex-escape", run)
	}
	if mayHoldBase64(text) {
		for _, m := range base64Re.FindAllString(text, maxBlobs) {
			raw, err := base64.StdEncoding.DecodeString(padBase64(m))
			if err != nil {
				continue
			}
			kind, b := unwrap("base64", raw, w)
			take(kind, b)
		}
	}
	return out
}

// These run over the whole file, unlike the vectors, so one large text would spend
// most of its scan in them. Each regex needs something rare, and each check here is
// a necessary condition for it: false proves the regex has nothing to find.

// minListTokens is the 32 repetitions of the list expressions, plus the final token.
const minListTokens = 33

func mayHoldHexList(text string) bool {
	return strings.Count(text, "0x")+strings.Count(text, "0X") >= minListTokens
}

func mayHoldVBHexList(text string) bool {
	return strings.Count(text, "&h")+strings.Count(text, "&H") >= minListTokens
}

// mayHoldDecimalList counts commas that follow a digit, which each repetition of
// decListRe has one of.
func mayHoldDecimalList(text string) bool {
	found := 0
	for i := 0; i < len(text); i++ {
		if text[i] != ',' {
			continue
		}
		j := i - 1
		for j >= 0 && (text[j] == ' ' || (text[j] >= '\t' && text[j] <= '\r' && text[j] != '\v')) {
			j--
		}
		if j >= 0 && text[j] >= '0' && text[j] <= '9' {
			if found++; found >= minListTokens-1 {
				return true
			}
		}
	}
	return false
}

const minBase64Run = 128

func mayHoldBase64(text string) bool {
	run := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
			if run++; run >= minBase64Run {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func padBase64(s string) string {
	if n := len(s) % 4; n != 0 {
		return s + strings.Repeat("=", 4-n)
	}
	return s
}

// parseNumbers turns a matched list into bytes, or nil when any element does
// not fit one: a table of larger integers is not a byte array.
// parseNumbers decodes a list into bytes, or nil if it holds a number that isn't a
// byte or would decode past limit, which take would refuse anyway. A list can be
// tens of millions of tokens, so they are walked rather than collected.
func parseNumbers(list string, limit int) []byte {
	var out []byte
	ok := eachNumber(list, func(t string) bool {
		var v uint64
		var err error
		if len(t) > 2 && (t[0] == '&' || t[1] == 'x' || t[1] == 'X') {
			v, err = strconv.ParseUint(t[2:], 16, 16)
		} else {
			v, err = strconv.ParseUint(t, 10, 16)
		}
		if err != nil || v > 255 || len(out) >= limit {
			return false
		}
		out = append(out, byte(v))
		return true
	})
	if !ok {
		return nil
	}
	return out
}

// eachNumber calls fn with each number in s, until it returns false, and reports
// whether it got to the end. A number is 0x or &h and hex digits, or decimal digits,
// exactly as (?i)0x[0-9a-f]+|&h[0-9a-f]+|\d+ finds them, which is what the test holds
// it to. It is written out because collecting that expression's matches over a
// large list held a string header per token.
func eachNumber(s string, fn func(string) bool) bool {
	isHex := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
	}
	for i := 0; i < len(s); {
		c := s[i]
		// A prefix counts only with a hex digit after it, or the alternation falls
		// through: "0xg" is the number 0.
		if i+2 < len(s) && (c == '0' && (s[i+1] == 'x' || s[i+1] == 'X') || c == '&' && (s[i+1] == 'h' || s[i+1] == 'H')) && isHex(s[i+2]) {
			j := i + 3
			for j < len(s) && isHex(s[j]) {
				j++
			}
			if !fn(s[i:j]) {
				return false
			}
			i = j
			continue
		}
		if c >= '0' && c <= '9' {
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if !fn(s[i:j]) {
				return false
			}
			i = j
			continue
		}
		i++
	}
	return true
}

// escapeRuns collects "\xNN" sequences. They are walked rather than matched so
// a payload split over several concatenated string literals stays one array.
func escapeRuns(text string) [][]byte {
	var runs [][]byte
	var cur []byte
	last := -1
	flush := func() {
		if len(cur) >= minCarrierBytes && len(runs) < maxBlobs {
			runs = append(runs, cur)
		}
		cur = nil
	}
	for i := 0; ; {
		j := strings.Index(text[i:], `\x`)
		if j < 0 || i+j+4 > len(text) {
			break
		}
		at := i + j
		v, err := strconv.ParseUint(text[at+2:at+4], 16, 8)
		if err != nil {
			i = at + 2
			continue
		}
		if last >= 0 && at-last > maxEscapeGap {
			flush()
		}
		cur = append(cur, byte(v))
		last = at + 4
		i = at + 4
	}
	flush()
	return runs
}

// unwrap peels the compression and text encodings a decoded blob commonly has
// on, and names the chain for the report.
func unwrap(kind string, raw []byte, w *walker) (string, []byte) {
	for i := 0; i < 3; i++ {
		switch {
		case len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b:
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				return kind, raw
			}
			out, err := inflate(zr)
			_ = zr.Close()
			if err != nil && len(out) == 0 {
				return kind, raw
			}
			kind, raw = kind+">gzip", out
		case len(raw) > 2 && raw[0] == 0x78 && (uint(raw[0])<<8|uint(raw[1]))%31 == 0:
			zr, err := zlib.NewReader(bytes.NewReader(raw))
			if err != nil {
				return kind, raw
			}
			out, err := inflate(zr)
			_ = zr.Close()
			if err != nil && len(out) == 0 {
				return kind, raw
			}
			kind, raw = kind+">zlib", out
		case utf16Shaped(raw):
			return kind + ">utf16", []byte(decodeUTF16(raw, true))
		default:
			return kind, raw
		}
	}
	return kind, raw
}

func inflate(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxInflated))
}

// utf16Shaped reports UTF-16LE ASCII: every second byte NUL at the start.
func utf16Shaped(b []byte) bool {
	if len(b) < 16 {
		return false
	}
	for i := 1; i < 16; i += 2 {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
