package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndFormatRoundTrip(t *testing.T) {
	sums := map[string]string{
		"cau-linux-amd64": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"hashes.txt":      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	data := Format(sums)
	c, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for name, want := range sums {
		got, ok := c.Digest(name)
		if !ok || got != want {
			t.Errorf("%s: got %q ok=%v, want %q", name, got, ok, want)
		}
	}
}

func TestParseToleratesBinaryMarkerAndComments(t *testing.T) {
	data := []byte("# a comment\n" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa *cau\n" +
		"\n")
	c, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := c.Digest("cau"); !ok {
		t.Error("binary-marker name not parsed")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := Format(map[string]string{"cau": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"})
	sig := Sign(data, priv)
	if err := VerifySignature(data, sig, pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Tampered manifest → bad signature.
	if err := VerifySignature(append(data, ' '), sig, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered manifest verified: %v", err)
	}
	// Wrong key → bad signature.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifySignature(data, sig, other); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key accepted: %v", err)
	}
}

func TestVerifyFile(t *testing.T) {
	lower := strings.Repeat("d", 64)
	c, err := Parse(Format(map[string]string{"cau": lower}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := c.VerifyFile("cau", strings.ToUpper(lower)); err != nil {
		t.Errorf("case-insensitive match failed: %v", err)
	}
	if err := c.VerifyFile("cau", strings.Repeat("0", 64)); !errors.Is(err, ErrMismatch) {
		t.Errorf("mismatch not detected: %v", err)
	}
	if err := c.VerifyFile("missing", "x"); !errors.Is(err, ErrNotListed) {
		t.Errorf("unlisted not detected: %v", err)
	}
}

func TestDigestFileAndSelf(t *testing.T) {
	work := t.TempDir()
	p := filepath.Join(work, "f.bin")
	os.WriteFile(p, []byte("content"), 0o644)
	d, err := DigestFile(p)
	if err != nil || len(d) != 64 {
		t.Fatalf("DigestFile: %v len=%d", err, len(d))
	}
	// SelfDigest must return a 64-hex digest and a non-empty name for the test
	// binary.
	sd, name, err := SelfDigest()
	if err != nil || len(sd) != 64 || name == "" {
		t.Fatalf("SelfDigest: %v digest=%q name=%q", err, sd, name)
	}
}

func TestParseRejectsNonDigest(t *testing.T) {
	if _, err := Parse([]byte("nothex  cau\n")); err == nil {
		t.Error("accepted a non-digest line")
	}
}

func TestParseKeys(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParsePublicKey([]byte(hexOf(pub))); err != nil {
		t.Errorf("pub: %v", err)
	}
	if _, err := ParsePrivateKey([]byte(hexOf(priv.Seed()))); err != nil {
		t.Errorf("priv seed: %v", err)
	}
	if _, err := ParsePrivateKey([]byte(hexOf(priv))); err != nil {
		t.Errorf("priv full: %v", err)
	}
	if _, err := ParsePublicKey([]byte("xy")); err == nil {
		t.Error("accepted bad pub")
	}
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	o := make([]byte, len(b)*2)
	for i, c := range b {
		o[i*2] = h[c>>4]
		o[i*2+1] = h[c&0x0f]
	}
	return string(o)
}
