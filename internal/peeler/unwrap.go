package peeler

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// An Unwrapper removes one obfuscation layer. It only ever *decodes* — it never
// executes, emulates, or runs sample content; the whole package is a detection
// pre-pass, so the publication rule holds (what to catch, not how to build it).
//
// Detect is a cheap, allocation-light guard: it decides whether a blob even
// looks like this layer, so the expensive Unwrap runs only on plausible input.
// Unwrap decodes with its output bounded by limit (the remaining global output
// budget) so a single stream can never overrun the wall; it returns
// ErrNotThisLayer when the blob turns out not to be this layer after all.
type Unwrapper interface {
	Name() string
	Detect(blob []byte) bool
	Unwrap(blob []byte, limit int64) ([]byte, error)
}

// ErrNotThisLayer is returned by Unwrap when a blob that passed the cheap
// Detect does not actually decode as this layer. It is an ordinary negative,
// not a failure — the node simply has no child along this transform.
var ErrNotThisLayer = errors.New("peeler: blob is not this layer")

// minLayerLen is the shortest blob worth trying to unwrap. Below it, a "decode"
// is noise: a few base64 characters decode to nothing meaningful and only feed
// the tree junk. It also stops the walk from chasing trivial tails.
const minLayerLen = 16

// DefaultUnwrappers is the built-in registry, ordered most-structural first so
// the estimator's frontier ranking has a sensible default. All are stdlib-only.
func DefaultUnwrappers() []Unwrapper {
	layers := []Unwrapper{
		gzipLayer{},
		zlibLayer{},
		bzip2Layer{},
		flateLayer{},
		base64Layer{},
		base32Layer{},
		hexLayer{},
	}
	return append(append(layers, baseLayers()...), cipherLayer{}, carveLayer{})
}

// ── bounded decode helpers ─────────────────────────────────────────────────

// readBounded copies at most limit+1 bytes from r. If the stream produces more
// than limit bytes it returns errBombCap, so a decompressor pointed at a bomb
// is stopped at the wall instead of filling memory.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errBombCap
	}
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, errBombCap
	}
	return out, nil
}

var errBombCap = errors.New("peeler: decoded stream exceeds the output budget")

// ── compression layers ─────────────────────────────────────────────────────

type gzipLayer struct{}

func (gzipLayer) Name() string { return "gzip" }
func (gzipLayer) Detect(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x1f && b[1] == 0x8b && b[2] == 0x08
}
func (gzipLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, ErrNotThisLayer
	}
	defer zr.Close()
	out, err := readBounded(zr, limit)
	if err != nil {
		if errors.Is(err, errBombCap) {
			return nil, err
		}
		return nil, ErrNotThisLayer
	}
	return out, nil
}

type zlibLayer struct{}

func (zlibLayer) Name() string { return "zlib" }
func (zlibLayer) Detect(b []byte) bool {
	// zlib: CMF/FLG where CMF low nibble is 8 (deflate) and (CMF<<8|FLG)%31==0.
	if len(b) < 2 || b[0]&0x0f != 0x08 {
		return false
	}
	return (uint16(b[0])<<8|uint16(b[1]))%31 == 0
}
func (zlibLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, ErrNotThisLayer
	}
	defer zr.Close()
	out, err := readBounded(zr, limit)
	if err != nil {
		if errors.Is(err, errBombCap) {
			return nil, err
		}
		return nil, ErrNotThisLayer
	}
	return out, nil
}

type bzip2Layer struct{}

func (bzip2Layer) Name() string { return "bzip2" }
func (bzip2Layer) Detect(b []byte) bool {
	return len(b) >= 4 && b[0] == 'B' && b[1] == 'Z' && b[2] == 'h' && b[3] >= '1' && b[3] <= '9'
}
func (bzip2Layer) Unwrap(b []byte, limit int64) ([]byte, error) {
	out, err := readBounded(bzip2.NewReader(bytes.NewReader(b)), limit)
	if err != nil {
		if errors.Is(err, errBombCap) {
			return nil, err
		}
		return nil, ErrNotThisLayer
	}
	if len(out) == 0 {
		return nil, ErrNotThisLayer
	}
	return out, nil
}

// flateLayer handles raw DEFLATE (no gzip/zlib wrapper). It has no magic, so it
// is tried last and only when the blob is otherwise unrecognized; a bad guess
// returns ErrNotThisLayer cheaply.
type flateLayer struct{}

func (flateLayer) Name() string { return "flate" }
func (flateLayer) Detect(b []byte) bool {
	// Raw deflate has no header; require a minimum length and let Unwrap judge.
	return len(b) >= minLayerLen
}
func (flateLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	fr := flate.NewReader(bytes.NewReader(b))
	defer fr.Close()
	out, err := readBounded(fr, limit)
	if err != nil {
		if errors.Is(err, errBombCap) {
			return nil, err
		}
		return nil, ErrNotThisLayer
	}
	// Raw deflate of random bytes often yields a few bytes before erroring;
	// require real progress so this layer does not manufacture junk children.
	if len(out) < minLayerLen {
		return nil, ErrNotThisLayer
	}
	return out, nil
}

// ── encoding layers ─────────────────────────────────────────────────────────

type base64Layer struct{}

func (base64Layer) Name() string { return "base64" }
func (base64Layer) Detect(b []byte) bool {
	b = textBody(b)
	if len(b) < minLayerLen {
		return false
	}
	// Require the blob to be (almost) entirely the base64 alphabet. A strict
	// gate keeps the tree from treating ordinary text as an encoded layer.
	pad := 0
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '-' || c == '_':
		case c == '=' && i >= len(b)-2:
			pad++
		default:
			return false
		}
	}
	return true
}
func (base64Layer) Unwrap(b []byte, limit int64) ([]byte, error) {
	s := string(textBody(b))
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil && len(out) >= minLayerLen {
			if int64(len(out)) > limit {
				return nil, errBombCap
			}
			return out, nil
		}
	}
	return nil, ErrNotThisLayer
}

type base32Layer struct{}

func (base32Layer) Name() string { return "base32" }
func (base32Layer) Detect(b []byte) bool {
	b = textBody(b)
	if len(b) < minLayerLen {
		return false
	}
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= '2' && c <= '7':
		case c == '=' && i >= len(b)-6:
		default:
			return false
		}
	}
	return true
}
func (base32Layer) Unwrap(b []byte, limit int64) ([]byte, error) {
	s := string(textBody(b))
	for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.StdEncoding.WithPadding(base32.NoPadding)} {
		if out, err := enc.DecodeString(s); err == nil && len(out) >= minLayerLen {
			if int64(len(out)) > limit {
				return nil, errBombCap
			}
			return out, nil
		}
	}
	return nil, ErrNotThisLayer
}

type hexLayer struct{}

func (hexLayer) Name() string { return "hex" }
func (hexLayer) Detect(b []byte) bool {
	b = textBody(b)
	if len(b) < minLayerLen || len(b)%2 != 0 {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
func (hexLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	s := textBody(b)
	if int64(len(s)/2) > limit {
		return nil, errBombCap
	}
	out, err := hex.DecodeString(string(s))
	if err != nil || len(out) < minLayerLen {
		return nil, ErrNotThisLayer
	}
	return out, nil
}
