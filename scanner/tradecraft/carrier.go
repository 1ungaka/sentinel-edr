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
	numberRe  = regexp.MustCompile(`(?i)0x[0-9a-f]+|&h[0-9a-f]+|\d+`)
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
	for _, m := range hexListRe.FindAllString(text, maxBlobs) {
		take("hex-list", parseNumbers(m))
	}
	for _, m := range vbHexRe.FindAllString(text, maxBlobs) {
		take("hex-list", parseNumbers(m))
	}
	for _, m := range decListRe.FindAllString(text, maxBlobs) {
		take("decimal-list", parseNumbers(m))
	}
	for _, run := range escapeRuns(text) {
		take("hex-escape", run)
	}
	for _, m := range base64Re.FindAllString(text, maxBlobs) {
		raw, err := base64.StdEncoding.DecodeString(padBase64(m))
		if err != nil {
			continue
		}
		kind, b := unwrap("base64", raw, w)
		take(kind, b)
	}
	return out
}

func padBase64(s string) string {
	if n := len(s) % 4; n != 0 {
		return s + strings.Repeat("=", 4-n)
	}
	return s
}

// parseNumbers turns a matched list into bytes, or nil when any element does
// not fit one: a table of larger integers is not a byte array.
func parseNumbers(list string) []byte {
	toks := numberRe.FindAllString(list, -1)
	out := make([]byte, 0, len(toks))
	for _, t := range toks {
		var v uint64
		var err error
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "0x"):
			v, err = strconv.ParseUint(lower[2:], 16, 16)
		case strings.HasPrefix(lower, "&h"):
			v, err = strconv.ParseUint(lower[2:], 16, 16)
		default:
			v, err = strconv.ParseUint(t, 10, 16)
		}
		if err != nil || v > 255 {
			return nil
		}
		out = append(out, byte(v))
	}
	return out
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
