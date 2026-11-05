package scanner

import (
	"strings"
	"testing"

	"github.com/s-b-repo/cau/scanner/fusion"
)

func TestEngineStegoPass(t *testing.T) {
	clean := writeTempFile(t, "README.md", []byte("# Title\n\nPlain prose.\n"))
	hidden := writeTempFile(t, "INSTALL.md", []byte("Run the installer\u200b\u200c\u200c\u200b\u200b\u200c\u200b\u200c and follow the prompts.\n"))
	bin := writeTempFile(t, "blob.bin", append([]byte{0, 1, 2, 3}, []byte("\u200b")...))
	db := NewSignatureDB()

	// Off by default.
	if res, _ := (&Engine{DB: db}).ScanFile(hidden); res.Stego != nil {
		t.Error("stego result present with Stego=false")
	}

	e := &Engine{DB: db, Stego: true}
	res, _ := e.ScanFile(clean)
	if res.Stego == nil || res.Stego.Detected() || res.Stego.FilePath != clean || !res.Stego.IsText {
		t.Errorf("clean: %+v", res.Stego)
	}
	if res.Verdict != VerdictClean || res.Fusion == nil || res.Fusion.Tier != fusion.TierClean {
		t.Errorf("clean verdict = %s fusion = %+v", res.Verdict, res.Fusion)
	}

	res, _ = e.ScanFile(hidden)
	if res.Stego == nil || !res.Stego.Detected() || res.Stego.Suspicious != 8 {
		t.Fatalf("hidden: %+v", res.Stego)
	}
	// Stego is the SUSPICIOUS tier: the hash/YARA verdict stays CLEAN, the
	// fused verdict says suspicious and names the source.
	if res.Verdict != VerdictClean {
		t.Errorf("verdict = %s", res.Verdict)
	}
	if res.Fusion == nil || res.Fusion.Tier != fusion.TierSuspicious || res.Fusion.Corroborated || len(res.Fusion.Agreed) != 1 || res.Fusion.Agreed[0] != fusion.SourceStego {
		t.Errorf("fusion = %+v", res.Fusion)
	}
	if got := res.Fusion.Novel; len(got) != 1 || got[0] != "NOVEL-001" {
		t.Errorf("novel = %v", got)
	}

	res, _ = e.ScanFile(bin)
	if res.Stego == nil || res.Stego.IsText || res.Stego.Skipped == "" || res.Stego.Detected() {
		t.Errorf("binary: %+v", res.Stego)
	}
	if res.Fusion == nil || res.Fusion.Tier != fusion.TierClean {
		t.Fatalf("fusion = %+v", res.Fusion)
	}
	var stegoRole fusion.Role
	for _, s := range res.Fusion.Sources {
		if s.Name == fusion.SourceStego {
			stegoRole = s.Role
		}
	}
	if stegoRole != fusion.RoleSkipped {
		t.Errorf("stego role on binary = %s", stegoRole)
	}

	// Threshold plumbing.
	res, _ = (&Engine{DB: db, Stego: true, StegoThreshold: 42}).ScanFile(hidden)
	if res.Stego.Threshold != 42 || res.Stego.Detected() {
		t.Errorf("threshold = %d detected = %v", res.Stego.Threshold, res.Stego.Detected())
	}
}

func TestEngineFusionCorroboratesSubThresholdSources(t *testing.T) {
	// A text carrier with heuristic evidence below the heuristic threshold
	// (encoded PowerShell + a LOLBin = 3 + 3 = 6 < 7) and an invisible
	// codepoint payload just below the stego threshold (raised to 10 so the
	// stego source alone does not fire: 6 + 2 + 2 = 10 would; use one
	// codepoint without a payload run: 6 + 2 = 8).
	body := "powershell -enc AAAA mshta.exe\u200b\n"
	path := writeTempFile(t, "loader.txt", []byte(body))

	e := &Engine{DB: NewSignatureDB(), Heuristics: true, Stego: true, StegoThreshold: 10}
	res, h := e.ScanFile(path)
	if h == nil || h.Detected() {
		t.Fatalf("heuristics should be below threshold: %+v", h)
	}
	if res.Stego == nil || res.Stego.Detected() {
		t.Fatalf("stego should be below its raised threshold: %+v", res.Stego)
	}
	v := res.Fusion
	if v == nil || v.Tier != fusion.TierSuspicious || !v.Corroborated {
		t.Fatalf("fusion = %+v", v)
	}
	if len(v.Agreed) != 2 {
		t.Errorf("agreed = %v", v.Agreed)
	}
	if !strings.Contains(v.Explanation, "by corroboration") {
		t.Errorf("explanation = %q", v.Explanation)
	}
	wantTech := map[string]bool{"T1027": true, "T1027.010": true, "T1218": true}
	for _, tech := range v.Techniques {
		delete(wantTech, tech)
	}
	if len(wantTech) != 0 {
		t.Errorf("techniques missing %v in %v", wantTech, v.Techniques)
	}

	// Turned off, the view is simply absent; nothing else changes.
	e.NoFusion = true
	res2, _ := e.ScanFile(path)
	if res2.Fusion != nil || res2.Verdict != res.Verdict {
		t.Errorf("NoFusion: %+v", res2.Fusion)
	}
}

func TestEngineFusionDefinitiveHashHit(t *testing.T) {
	body := []byte("known bad content with cmd.exe /c and nothing else of note\n")
	path := writeTempFile(t, "bad.bin", body)
	db := NewSignatureDB()
	d := hashBytes(body)
	if err := db.Add(Signature{HashType: "SHA256", Hash: d.sha256, ThreatName: "Smoke Test Family"}); err != nil {
		t.Fatal(err)
	}
	res, _ := (&Engine{DB: db, Heuristics: true, Static: true, Stego: true}).ScanFile(path)
	if res.Verdict != VerdictMalicious {
		t.Fatalf("verdict = %s", res.Verdict)
	}
	v := res.Fusion
	if v == nil || v.Tier != fusion.TierMalicious || v.Confidence != "high" || v.Sources[0].Name != fusion.SourceHash || v.Sources[0].Role != fusion.RoleDefinitive {
		t.Fatalf("fusion = %+v", v)
	}
	if v.Sources[0].Evidence[0].Label != "hash/sha256" || v.Sources[0].Evidence[0].Detail != "Smoke Test Family" {
		t.Errorf("evidence = %+v", v.Sources[0].Evidence)
	}
	names := map[string]bool{}
	for _, s := range v.Sources {
		names[s.Name] = true
	}
	for _, want := range []string{"hash", "heuristic", "static", "similarity", "stego"} {
		if !names[want] {
			t.Errorf("source %s missing from %v", want, names)
		}
	}
}
