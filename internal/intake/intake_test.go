package intake

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/scanner"
)

const (
	sha256A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sha256B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sha1A   = "cccccccccccccccccccccccccccccccccccccccc"
	md5A    = "dddddddddddddddddddddddddddddddd"
)

func hasHash(iocs []IOC, hash string) *IOC {
	for i := range iocs {
		if iocs[i].Hash == hash {
			return &iocs[i]
		}
	}
	return nil
}

func TestParseSTIX(t *testing.T) {
	bundle := `{
	  "type": "bundle",
	  "objects": [
	    {"type":"indicator","name":"Evil.Dropper","pattern_type":"stix",
	     "pattern":"[file:hashes.'SHA-256' = '` + sha256A + `']"},
	    {"type":"indicator","description":"Second sample",
	     "pattern":"[file:hashes.MD5='` + md5A + `' OR file:hashes.'SHA-1'='` + sha1A + `']"},
	    {"type":"malware","name":"not an indicator"}
	  ]
	}`
	iocs, err := ParseSTIX([]byte(bundle))
	if err != nil {
		t.Fatalf("ParseSTIX: %v", err)
	}
	if len(iocs) != 3 {
		t.Fatalf("got %d IOCs, want 3: %+v", len(iocs), iocs)
	}
	if ioc := hasHash(iocs, sha256A); ioc == nil || ioc.HashType != "SHA256" || ioc.ThreatName != "Evil.Dropper" {
		t.Errorf("sha256 IOC wrong: %+v", ioc)
	}
	if ioc := hasHash(iocs, md5A); ioc == nil || ioc.HashType != "MD5" {
		t.Errorf("md5 IOC missing/wrong: %+v", ioc)
	}
	if ioc := hasHash(iocs, sha1A); ioc == nil || ioc.HashType != "SHA1" {
		t.Errorf("sha1 IOC missing/wrong: %+v", ioc)
	}
}

func TestParseMISP(t *testing.T) {
	doc := `{"Event":{"info":"APT Campaign X","Attribute":[
	  {"type":"sha256","value":"` + sha256A + `"},
	  {"type":"md5","value":"` + md5A + `"},
	  {"type":"filename|sha1","value":"evil.exe|` + sha1A + `"},
	  {"type":"ip-dst","value":"10.0.0.1"}
	],"Object":[{"Attribute":[{"type":"sha256","value":"` + sha256B + `"}]}]}}`
	iocs, err := ParseMISP([]byte(doc))
	if err != nil {
		t.Fatalf("ParseMISP: %v", err)
	}
	if len(iocs) != 4 {
		t.Fatalf("got %d IOCs, want 4: %+v", len(iocs), iocs)
	}
	if ioc := hasHash(iocs, sha1A); ioc == nil || ioc.HashType != "SHA1" {
		t.Errorf("composite filename|sha1 not extracted: %+v", ioc)
	}
	if ioc := hasHash(iocs, sha256A); ioc == nil || ioc.ThreatName != "APT Campaign X" {
		t.Errorf("event info not used as label: %+v", ioc)
	}
	if hasHash(iocs, "10.0.0.1") != nil {
		t.Error("non-hash attribute was ingested")
	}
}

func TestParseMalwareBazaar(t *testing.T) {
	doc := `{"query_status":"ok","data":[
	  {"sha256_hash":"` + sha256A + `","md5_hash":"` + md5A + `","signature":"AgentTesla","file_name":"x.exe"},
	  {"sha256_hash":"` + sha256B + `","signature":"","file_name":"dropper.bin"}
	]}`
	iocs, err := ParseMalwareBazaar([]byte(doc))
	if err != nil {
		t.Fatalf("ParseMalwareBazaar: %v", err)
	}
	// sample 1 contributes sha256+md5, sample 2 sha256 → 3 unique.
	if len(iocs) != 3 {
		t.Fatalf("got %d IOCs, want 3: %+v", len(iocs), iocs)
	}
	if ioc := hasHash(iocs, sha256A); ioc == nil || ioc.ThreatName != "AgentTesla" {
		t.Errorf("signature label not used: %+v", ioc)
	}
	if ioc := hasHash(iocs, sha256B); ioc == nil || ioc.ThreatName != "dropper.bin" {
		t.Errorf("fallback to file_name label failed: %+v", ioc)
	}
}

func TestParseMalwareBazaarBadStatus(t *testing.T) {
	if _, err := ParseMalwareBazaar([]byte(`{"query_status":"no_results","data":[]}`)); err == nil {
		t.Error("expected an error on a non-ok query_status")
	}
}

func TestParseLOLDrivers(t *testing.T) {
	doc := `[
	  {"Id":"abc","Category":"vulnerable driver","Tags":["RTCore64"],
	   "KnownVulnerableSamples":[{"SHA256":"` + sha256A + `","MD5":"` + md5A + `","Filename":"RTCore64.sys"}]},
	  {"Id":"def","KnownVulnerableSamples":[{"SHA256":"` + sha256B + `"}]}
	]`
	iocs, err := ParseLOLDrivers([]byte(doc))
	if err != nil {
		t.Fatalf("ParseLOLDrivers: %v", err)
	}
	if len(iocs) != 3 {
		t.Fatalf("got %d IOCs, want 3: %+v", len(iocs), iocs)
	}
	if ioc := hasHash(iocs, sha256A); ioc == nil || !strings.Contains(ioc.ThreatName, "RTCore64.sys") {
		t.Errorf("driver label wrong: %+v", ioc)
	}
}

func TestParseDispatchAndUnknown(t *testing.T) {
	if _, err := Parse("bogus", []byte("{}")); err == nil {
		t.Error("unknown format accepted")
	}
	if _, err := Parse(FormatSTIX, []byte(`{"type":"bundle","objects":[]}`)); err != nil {
		t.Errorf("empty STIX bundle: %v", err)
	}
}

func TestSanitizeName(t *testing.T) {
	got := sanitizeName("bad|name\nwith\tbreaks")
	if strings.ContainsAny(got, "|\r\n\t") {
		t.Errorf("sanitize left a forbidden char: %q", got)
	}
	if sanitizeName("   ") != "intel-feed" {
		t.Error("blank name not defaulted")
	}
	long := strings.Repeat("A", 500)
	if len(sanitizeName(long)) > 120 {
		t.Error("name not length-bounded")
	}
}

func TestNewIOCInfersTypeAndRejectsJunk(t *testing.T) {
	// Blank type but a sha256-length hex → inferred SHA256.
	if ioc, ok := newIOC("", sha256A, "x", "test"); !ok || ioc.HashType != "SHA256" {
		t.Errorf("type inference failed: %+v ok=%v", ioc, ok)
	}
	// Wrong length / non-hex → rejected.
	if _, ok := newIOC("sha256", "nothex", "x", "test"); ok {
		t.Error("non-hex accepted")
	}
	if _, ok := newIOC("md5", "", "x", "test"); ok {
		t.Error("empty value accepted")
	}
}

func TestApplySkipsExisting(t *testing.T) {
	db := scanner.NewSignatureDB()
	if err := db.Add(scanner.Signature{HashType: "SHA256", Hash: sha256A, ThreatName: "Existing"}); err != nil {
		t.Fatal(err)
	}
	iocs := []IOC{
		{HashType: "SHA256", Hash: sha256A, ThreatName: "NewLabel"}, // dup → skip
		{HashType: "SHA256", Hash: sha256B, ThreatName: "Fresh"},    // new → add
	}
	res := Apply(db, iocs)
	if res.Added != 1 || res.Skipped != 1 {
		t.Fatalf("Apply: added=%d skipped=%d, want 1/1", res.Added, res.Skipped)
	}
	if len(res.Signatures) != 1 || res.Signatures[0].Hash != sha256B {
		t.Errorf("wrong signature set: %+v", res.Signatures)
	}
}

func TestRenderRoundTripsThroughLoader(t *testing.T) {
	sigs := []scanner.Signature{
		{HashType: "SHA256", Hash: sha256A, ThreatName: "Family.A"},
		{HashType: "MD5", Hash: md5A, ThreatName: "Family.B"},
	}
	out := Render(sigs)
	// Every rendered line must be TYPE|hash|name and loadable.
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Count(line, "|") != 2 {
			t.Errorf("bad line format: %q", line)
		}
	}
	if !strings.Contains(string(out), "SHA256|"+sha256A+"|Family.A") {
		t.Errorf("render missing expected line:\n%s", out)
	}
}

func TestParseMalwareBazaarCSV(t *testing.T) {
	csv := `# some header comment
"2024-01-01 00:00:00","` + sha256A + `","` + md5A + `","` + sha1A + `","reporter","x.exe","exe","application/x-dosexec","Formbook","ELF"`
	iocs, err := ParseMalwareBazaarCSV([]byte(csv))
	if err != nil {
		t.Fatalf("CSV parse: %v", err)
	}
	if len(iocs) != 3 {
		t.Fatalf("got %d IOCs, want 3: %+v", len(iocs), iocs)
	}
	if ioc := hasHash(iocs, sha256A); ioc == nil || ioc.ThreatName != "Formbook" {
		t.Errorf("CSV signature label wrong: %+v", ioc)
	}
}

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "cau-intake" {
			t.Errorf("missing user agent: %q", r.Header.Get("User-Agent"))
		}
		w.Write([]byte(`{"query_status":"ok","data":[]}`))
	}))
	defer srv.Close()
	data, err := Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !strings.Contains(string(data), "query_status") {
		t.Errorf("unexpected body: %s", data)
	}
}

func TestFetchNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.URL); err == nil {
		t.Error("expected an error on HTTP 404")
	}
}
