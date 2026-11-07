package encchain

import "bytes"

// run is an encoded region. chars is the whole run with interior whitespace
// removed (the MIME-dewrapped form). starts holds additional decode attempts,
// one per interior line boundary, so a plain-text preamble joined to the blob
// by a newline ("here is the payload\n<base64>") does not shift the decode
// alignment and hide the executable. Each attempt is already whitespace-free.
type run struct {
	offset int
	kind   string
	chars  []byte
	starts [][]byte
}

// attempts returns the decode candidates for this run, whole form first.
func (r run) attempts() [][]byte {
	out := make([][]byte, 0, 1+len(r.starts))
	out = append(out, r.chars)
	out = append(out, r.starts...)
	return out
}

const maxLineStarts = 8 // cap the per-run line-boundary retries

func isBase64(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '-' || c == '_' || c == '='
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Interior whitespace that may wrap an encoded blob. Space is deliberately
// excluded: base64/hex never use it, while prose does, so allowing it would
// merge space-separated words into a run.
func isWrap(c byte) bool { return c == '\r' || c == '\n' || c == '\t' }

// collectRuns scans data for maximal runs of alphabet characters (per member)
// with interior line-wrapping whitespace allowed, and returns those whose
// alphabet-character count is at least minRun, each with its per-line decode
// attempts.
func collectRuns(data []byte, minRun int, kind string, member func(byte) bool) []run {
	var runs []run
	// Reused, because nearly every run is a word far below minRun, and a file of text
	// has millions of them.
	var scratch []byte
	var lineStarts []int // index into chars where each interior line begins
	i, n := 0, len(data)
	for i < n {
		if !member(data[i]) {
			i++
			continue
		}
		start := i
		chars := scratch[:0]
		lineStarts = lineStarts[:0]
		atLineStart := false
		for i < n {
			c := data[i]
			switch {
			case member(c):
				if atLineStart {
					lineStarts = append(lineStarts, len(chars))
					atLineStart = false
				}
				chars = append(chars, c)
				i++
			case c == '\n':
				atLineStart = true
				i++
			case isWrap(c):
				i++
			default:
				goto done
			}
		}
	done:
		scratch = chars[:0]
		if len(chars) < minRun {
			continue
		}
		chars = bytes.Clone(chars) // r keeps it, and scratch is about to be reused
		r := run{offset: start, kind: kind, chars: chars}
		for _, ls := range lineStarts {
			if len(r.starts) >= maxLineStarts {
				break
			}
			if len(chars)-ls >= minRun {
				r.starts = append(r.starts, chars[ls:])
			}
		}
		runs = append(runs, r)
	}
	return runs
}

func base64Runs(data []byte, minRun int) []run {
	return collectRuns(data, minRun, "base64", isBase64)
}

// hexRuns requires twice the character floor: hex is two characters per byte,
// and a long pure-hex run is far rarer in benign text than a base64 one.
func hexRuns(data []byte, minRun int) []run {
	return collectRuns(data, 2*minRun, "hex", isHex)
}

// firstEncodedRun returns the first base64 or hex run of at least minRun
// characters in data, for peeling a decoded layer that is itself encoded.
func firstEncodedRun(data []byte, minRun int) *run {
	if b := base64Runs(data, minRun); len(b) > 0 {
		return &b[0]
	}
	if h := hexRuns(data, minRun); len(h) > 0 {
		return &h[0]
	}
	return nil
}

// executableHeader reports whether dec begins with a valid PE or ELF header.
// The checks are strict so chance collisions do not fire: PE requires the MZ
// magic AND a "PE\0\0" signature at the e_lfanew offset; ELF requires the
// 4-byte magic plus a valid class, data encoding and version.
func executableHeader(dec []byte) (class, detail string, ok bool) {
	if len(dec) >= 64 && dec[0] == 'M' && dec[1] == 'Z' {
		e := int(dec[0x3C]) | int(dec[0x3D])<<8 | int(dec[0x3E])<<16 | int(dec[0x3F])<<24
		if e >= 0 && e+4 <= len(dec) && dec[e] == 'P' && dec[e+1] == 'E' && dec[e+2] == 0 && dec[e+3] == 0 {
			return "encchain.pe", "decodes to a PE image (MZ with a PE header at 0x" + itoa(e) + ")", true
		}
	}
	if len(dec) >= 20 && dec[0] == 0x7f && dec[1] == 'E' && dec[2] == 'L' && dec[3] == 'F' &&
		(dec[4] == 1 || dec[4] == 2) && (dec[5] == 1 || dec[5] == 2) && dec[6] == 1 {
		return "encchain.elf", "decodes to an ELF image", true
	}
	return "", "", false
}
