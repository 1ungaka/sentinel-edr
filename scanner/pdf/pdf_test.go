package pdf

import (
	"bytes"
	"fmt"
	"testing"
)

// ── synthetic PDF builder ───────────────────────────────────────────────────────
//
// buildPDF assembles structurally plausible PDF bytes from a list of object
// bodies. It constructs ONLY document bytes for the detector to read; it never
// writes, weaponises or executes anything, and nothing it emits is a real
// payload. Each object is wrapped as "N 0 obj ... endobj" so the lexical object
// counter sees it, and a minimal trailer closes the file. The cross-reference
// offsets are not accurate — the detector is lexical and does not rely on them.

func buildPDF(version string, objs ...string) []byte {
	if version == "" {
		version = "1.7"
	}
	var b bytes.Buffer
	b.WriteString("%PDF-" + version + "\n")
	b.WriteString("%\xE2\xE3\xCF\xD3\n") // binary-marker comment, as real PDFs carry
	for i, o := range objs {
		fmt.Fprintf(&b, "%d 0 obj\n", i+1)
		b.WriteString(o)
		b.WriteString("\nendobj\n")
	}
	b.WriteString("trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF")
	return b.Bytes()
}

func findClass(fs []Finding, class string) (Finding, bool) {
	for _, f := range fs {
		if f.Class == class {
			return f, true
		}
	}
	return Finding{}, false
}

// ── IsPDF ──────────────────────────────────────────────────────────────────────

func TestIsPDF(t *testing.T) {
	if !IsPDF(buildPDF("1.7", "<< /Type /Catalog >>")) {
		t.Fatal("valid synthetic PDF not recognised")
	}
	// Leading bytes before the header are allowed by the spec.
	lead := append([]byte("\x00\x01junk before header "), buildPDF("1.4", "<< >>")...)
	if !IsPDF(lead) {
		t.Fatal("PDF with leading bytes before %PDF- not recognised")
	}
	if IsPDF([]byte("this is plainly not a pdf document")) {
		t.Fatal("non-PDF buffer accepted")
	}
	if IsPDF(nil) {
		t.Fatal("nil accepted as a PDF")
	}
	// A header pushed past the 1024-byte window must not be found.
	far := append(bytes.Repeat([]byte{' '}, 2000), []byte("%PDF-1.7")...)
	if IsPDF(far) {
		t.Fatal("header beyond the 1024-byte window accepted")
	}
}

// ── Analyze table ──────────────────────────────────────────────────────────────

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name         string
		data         []byte
		wantDetected bool
		wantClasses  map[string]string // class -> required technique
		absentClass  []string
		check        func(t *testing.T, r *Result)
	}{
		{
			name: "benign one-page PDF with a URI link",
			data: buildPDF("1.7",
				"<< /Type /Catalog /Pages 2 0 R >>",
				"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
				"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [5 0 R] >>",
				"<< /Length 42 >>\nstream\nBT /F1 24 Tf 72 720 Td (Hello) Tj ET\nendstream",
				"<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://example.com/) >> >>",
			),
			wantDetected: false,
			wantClasses:  map[string]string{"pdf.uri": techMalLink},
			absentClass:  []string{"pdf.javascript", "pdf.action.openaction", "pdf.action.launch"},
			check: func(t *testing.T, r *Result) {
				if r.Score >= DefaultThreshold {
					t.Fatalf("benign PDF scored %d (>= threshold %d)", r.Score, DefaultThreshold)
				}
				if r.Parsed == nil || r.Parsed.Version != "1.7" {
					t.Fatalf("version not summarised: %+v", r.Parsed)
				}
				if r.Parsed.Objects != 5 {
					t.Fatalf("object count = %d, want 5", r.Parsed.Objects)
				}
				if r.Parsed.Streams != 1 {
					t.Fatalf("stream count = %d, want 1", r.Parsed.Streams)
				}
			},
		},
		{
			name: "auto-run JavaScript dropper (OpenAction -> JavaScript)",
			data: buildPDF("1.5",
				"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>",
				"<< /Type /Pages /Kids [] /Count 0 >>",
				"<< /S /JavaScript /JS (app.alert\\(1\\);) >>",
			),
			wantDetected: true,
			wantClasses: map[string]string{
				"pdf.action.openaction": techUserExec,
				"pdf.javascript":        techJS,
			},
			absentClass: []string{"pdf.javascript.heuristic"},
			check: func(t *testing.T, r *Result) {
				if r.Score != weightAutoAction+weightJavaScript {
					t.Fatalf("score = %d, want %d", r.Score, weightAutoAction+weightJavaScript)
				}
				if r.Parsed == nil || !r.Parsed.HasOpenAction || !r.Parsed.HasJavaScript {
					t.Fatalf("Parsed flags not set: %+v", r.Parsed)
				}
			},
		},
		{
			name: "JavaScript with exploitation primitives",
			data: buildPDF("1.6",
				"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>",
				"<< /Type /Pages /Kids [] /Count 0 >>",
				"<< /S /JavaScript /JS 4 0 R >>",
				"<< /Length 64 >>\nstream\nvar s=unescape(\"%u9090%u9090%u0c0c\");eval(s);\nendstream",
			),
			wantDetected: true,
			wantClasses: map[string]string{
				"pdf.action.openaction":    techUserExec,
				"pdf.javascript":           techJS,
				"pdf.javascript.heuristic": techObfuscation,
			},
			check: func(t *testing.T, r *Result) {
				if r.Score != weightAutoAction+weightJavaScript+weightJSHeuristic {
					t.Fatalf("score = %d, want %d", r.Score, weightAutoAction+weightJavaScript+weightJSHeuristic)
				}
			},
		},
		{
			name: "Launch action dropper (OpenAction -> Launch)",
			data: buildPDF("1.7",
				"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>",
				"<< /Type /Pages /Kids [] /Count 0 >>",
				"<< /S /Launch /Launch << /F (cmd.exe) >> >>",
			),
			wantDetected: true,
			wantClasses: map[string]string{
				"pdf.action.launch":     techInterp,
				"pdf.action.openaction": techUserExec,
			},
		},
		{
			name: "hex-escaped name obfuscation (/J#61vaScript)",
			data: buildPDF("1.7",
				"<< /Type /Catalog /Pages 2 0 R >>",
				"<< /Type /Pages /Kids [] /Count 0 >>",
				"<< /S /J#61vaScript (var x=1;) >>",
			),
			wantDetected: true,
			wantClasses: map[string]string{
				"pdf.obfuscation.name": techObfuscation,
				"pdf.javascript":       techJS, // recognised THROUGH the #xx decode
			},
			check: func(t *testing.T, r *Result) {
				if r.Score != weightNameObf+weightJavaScript {
					t.Fatalf("score = %d, want %d", r.Score, weightNameObf+weightJavaScript)
				}
				// Prove the JS was recognised only via the decoded name.
				if !r.Parsed.HasJavaScript {
					t.Fatalf("hex-escaped /JavaScript not decoded: %+v", r.Parsed)
				}
			},
		},
		{
			name: "embedded file carrier",
			data: buildPDF("1.7",
				"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 3 0 R >> >>",
				"<< /Type /Pages /Kids [] /Count 0 >>",
				"<< /Type /Filespec /F (invoice.exe) /EF << /F 4 0 R >> >>",
				"<< /Type /EmbeddedFile /Length 4 >>\nstream\nDATA\nendstream",
			),
			wantDetected: false, // a carrier alone (weight 3) stays below threshold
			wantClasses:  map[string]string{"pdf.embeddedfile": techUserExec},
			check: func(t *testing.T, r *Result) {
				if r.Score != weightEmbedded {
					t.Fatalf("score = %d, want %d", r.Score, weightEmbedded)
				}
			},
		},
		{
			name: "encrypted auto-run JavaScript (evasion amplifier)",
			data: buildPDF("1.7",
				"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>",
				"<< /Type /Pages /Kids [] /Count 0 >>",
				"<< /S /JavaScript /JS (x=1;) >>",
				"<< /Filter /Standard /V 2 /R 3 /Encrypt >>",
			),
			wantDetected: true,
			wantClasses: map[string]string{
				"pdf.evasion.encrypted-autojs": techObfuscation,
			},
			check: func(t *testing.T, r *Result) {
				if !r.Parsed.Encrypted {
					t.Fatalf("Encrypt not reflected in Parsed: %+v", r.Parsed)
				}
			},
		},
		{
			name:         "truncated PDF (header + partial object, no trailer)",
			data:         []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R"),
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r == nil {
					t.Fatal("Analyze returned nil on truncated input")
				}
				if r.Score != 0 {
					t.Fatalf("truncated benign PDF scored %d, want 0", r.Score)
				}
			},
		},
		{
			name:         "garbage buffer with a header and a dangling name",
			data:         []byte("%PDF-1.7\n\x00\xff random \x01 bytes 9 9 obj /J#6"),
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r == nil {
					t.Fatal("Analyze returned nil on garbage input")
				}
			},
		},
		{
			name:         "not a PDF at all",
			data:         []byte("MZ\x90\x00 definitely not a pdf"),
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
					t.Fatalf("non-PDF buffer produced analysis: %+v", r)
				}
			},
		},
		{
			name:         "empty buffer",
			data:         nil,
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r == nil || r.Score != 0 {
					t.Fatalf("empty buffer: unexpected result %+v", r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(tc.data, Options{})
			if r == nil {
				t.Fatal("Analyze returned nil")
			}
			// Invariant shared with the fuzzer: score equals the sum of weights.
			sum := 0
			for _, f := range r.Findings {
				sum += f.Score
			}
			if sum != r.Score {
				t.Fatalf("score %d != sum of finding weights %d: %+v", r.Score, sum, r.Findings)
			}
			if got := r.Detected(); got != tc.wantDetected {
				t.Fatalf("Detected()=%v, want %v (score %d, threshold %d, findings %+v)",
					got, tc.wantDetected, r.Score, r.EffectiveThreshold(), r.Findings)
			}
			for class, tech := range tc.wantClasses {
				f, ok := findClass(r.Findings, class)
				if !ok {
					t.Fatalf("missing finding class %q; got %+v", class, r.Findings)
				}
				if f.Technique != tech {
					t.Fatalf("class %q technique=%q, want %q", class, f.Technique, tech)
				}
			}
			for _, class := range tc.absentClass {
				if _, ok := findClass(r.Findings, class); ok {
					t.Fatalf("unexpected finding class %q present; got %+v", class, r.Findings)
				}
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
}

// TestScanFileMissing confirms ScanFile never errors hard and reports a missing
// file as Skipped rather than panicking.
func TestScanFileMissing(t *testing.T) {
	r := ScanFile("/no/such/document.pdf", Options{})
	if r == nil {
		t.Fatal("ScanFile returned nil")
	}
	if r.Skipped == "" {
		t.Fatalf("expected Skipped for a missing file, got %+v", r)
	}
	if r.Detected() {
		t.Fatal("a skipped scan must not report Detected")
	}
}

// TestClassesCatalog checks the catalog is internally consistent: non-empty,
// unique entries, every technique one of the allowed ATT&CK ids, and every class
// the detector can emit present in the catalog.
func TestClassesCatalog(t *testing.T) {
	allowed := map[string]bool{
		techUserExec: true, techMalLink: true, techInterp: true,
		techJS: true, techIngress: true, techObfuscation: true,
	}
	cls := Classes()
	if len(cls) == 0 {
		t.Fatal("Classes() is empty")
	}
	seen := map[string]bool{}
	for _, c := range cls {
		key := c.Class + "|" + c.Technique
		if seen[key] {
			t.Fatalf("duplicate catalog entry %q", key)
		}
		seen[key] = true
		if !allowed[c.Technique] {
			t.Fatalf("class %q uses unexpected technique %q", c.Class, c.Technique)
		}
		if c.Novel != "" {
			t.Fatalf("class %q must not carry a novel id: %q", c.Class, c.Novel)
		}
		if c.Weight <= 0 || c.Description == "" {
			t.Fatalf("class %q has no weight/description: %+v", c.Class, c)
		}
	}
}
