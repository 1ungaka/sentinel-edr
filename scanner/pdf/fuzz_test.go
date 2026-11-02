package pdf

import (
	"strings"
	"testing"
)

// FuzzAnalyze drives the lexical PDF scanner with mutated input. The scanner
// reads untrusted bytes: attacker-controlled object headers, stream keywords,
// deeply nested dictionaries, and #xx name escapes. The invariant is that
// Analyze never panics, always returns a non-nil result, runs in bounded time,
// and keeps Result.Score equal to the sum of its finding weights. Seeds cover an
// empty buffer, a valid synthetic PDF, a header-only buffer, deeply nested
// dictionaries, a flood of object tokens, pathological # escape sequences, and a
// malicious auto-run-JS document.
func FuzzAnalyze(f *testing.F) {
	valid := buildPDF("1.7",
		"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>",
		"<< /Type /Pages /Kids [] /Count 0 >>",
		"<< /S /JavaScript /JS (app.alert\\(1\\);) >>",
	)

	seeds := [][]byte{
		{},
		[]byte("not a pdf"),
		valid,
		[]byte("%PDF-1.7"), // header only
		[]byte("%PDF-1.7\n" + strings.Repeat("<<", 20000) + strings.Repeat(">>", 20000)), // deep nesting
		[]byte("%PDF-1.4\n" + strings.Repeat("1 0 obj<<>>endobj ", 10000)),               // obj flood
		[]byte("%PDF-1.7\n" + strings.Repeat("/J#61#62#63#", 5000) + "/OpenActi#6Fn"),    // # escape storm
		[]byte("%PDF-1.5\n" + strings.Repeat("stream\nxx\nendstream\n", 5000)),           // stream flood
		[]byte("%PDF-1.7\n/J#"), // truncated hex escape at EOF
		buildPDF("1.6", "<< /S /Launch /Launch << /F (x) >> >>"),
		buildPDF("1.7", "<< /Type /EmbeddedFile >>"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		if !IsPDF(data) {
			if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
				t.Fatalf("non-PDF buffer produced analysis: %+v", r)
			}
			return
		}
		sum := 0
		for _, fnd := range r.Findings {
			sum += fnd.Score
		}
		if sum != r.Score {
			t.Fatalf("score %d does not match finding sum %d: %+v", r.Score, sum, r.Findings)
		}
		if r.Parsed == nil {
			t.Fatalf("PDF buffer produced a nil Parsed: %+v", r)
		}
	})
}
