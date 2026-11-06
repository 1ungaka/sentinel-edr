package intake

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stixIndicator(hash string) string {
	return `{"type":"indicator","name":"T-` + hash[:4] + `","pattern":"[file:hashes.'SHA-256' = '` + hash + `']"}`
}

// taxiiServer serves a paginated collection: pages[i] is a list of objects.
type taxiiServer struct {
	t        *testing.T
	pages    [][]string
	requests []*http.Request
	lastHdr  []string // X-TAXII-Date-Added-Last per page
}

func (s *taxiiServer) handler(w http.ResponseWriter, r *http.Request) {
	s.requests = append(s.requests, r.Clone(context.Background()))
	if !strings.HasSuffix(r.URL.Path, "/collections/c1/objects/") {
		http.NotFound(w, r)
		return
	}
	page := 0
	if n := r.URL.Query().Get("next"); n != "" {
		fmt.Sscanf(n, "p%d", &page)
	}
	if page >= len(s.pages) {
		http.Error(w, "bad cursor", http.StatusBadRequest)
		return
	}
	env := map[string]any{"objects": []json.RawMessage{}}
	var objs []json.RawMessage
	for _, o := range s.pages[page] {
		objs = append(objs, json.RawMessage(o))
	}
	if objs != nil {
		env["objects"] = objs
	}
	if page+1 < len(s.pages) {
		env["more"] = true
		env["next"] = fmt.Sprintf("p%d", page+1)
	}
	w.Header().Set("Content-Type", TAXIIMediaType)
	if page < len(s.lastHdr) {
		w.Header().Set("X-TAXII-Date-Added-Last", s.lastHdr[page])
	}
	json.NewEncoder(w).Encode(env)
}

func newTAXII(t *testing.T, pages [][]string, last ...string) (*taxiiServer, *httptest.Server) {
	s := &taxiiServer{t: t, pages: pages, lastHdr: last}
	srv := httptest.NewTLSServer(http.HandlerFunc(s.handler))
	t.Cleanup(srv.Close)
	return s, srv
}

func TestFetchTAXIIPaginates(t *testing.T) {
	s, srv := newTAXII(t,
		[][]string{{stixIndicator(sha256A)}, {stixIndicator(sha256B), `{"type":"malware","name":"x"}`}},
		"2026-11-01T10:00:00.000Z", "2026-11-03T08:30:00.000Z")

	res, err := FetchTAXII(context.Background(), TAXIIOptions{
		CollectionURL: srv.URL + "/api/collections/c1/",
		AddedAfter:    "2026-10-01T00:00:00Z",
		Authorization: "Bearer tok3n",
		PageLimit:     50,
		Client:        srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pages != 2 || len(res.Objects) != 3 || res.Truncated {
		t.Fatalf("result: pages %d objects %d truncated %v", res.Pages, len(res.Objects), res.Truncated)
	}
	if res.LastAdded != "2026-11-03T08:30:00.000Z" {
		t.Errorf("LastAdded %q", res.LastAdded)
	}
	first, second := s.requests[0], s.requests[1]
	if first.Header.Get("Accept") != TAXIIMediaType || first.Header.Get("Authorization") != "Bearer tok3n" {
		t.Errorf("headers: %v", first.Header)
	}
	if q := first.URL.Query(); q.Get("added_after") != "2026-10-01T00:00:00Z" || q.Get("limit") != "50" || q.Get("next") != "" {
		t.Errorf("first query: %v", q)
	}
	if q := second.URL.Query(); q.Get("next") != "p1" || q.Get("added_after") != "2026-10-01T00:00:00Z" {
		t.Errorf("second query: %v", q)
	}

	// The polled objects feed the existing STIX parser unchanged.
	iocs, err := ParseSTIX(res.Bundle())
	if err != nil || len(iocs) != 2 || hasHash(iocs, sha256A) == nil || hasHash(iocs, sha256B) == nil {
		t.Fatalf("ParseSTIX over the polled bundle: %v %+v", err, iocs)
	}
}

func TestFetchTAXIIAcceptsObjectsURLAndEmptyCollection(t *testing.T) {
	_, srv := newTAXII(t, [][]string{{}})
	res, err := FetchTAXII(context.Background(), TAXIIOptions{CollectionURL: srv.URL + "/collections/c1/objects/", Client: srv.Client()})
	if err != nil || len(res.Objects) != 0 || res.Pages != 1 {
		t.Fatalf("empty collection: %v %+v", err, res)
	}
	if string(res.Bundle()) != `{"type":"bundle","objects":[]}` {
		t.Errorf("empty bundle: %s", res.Bundle())
	}
}

func TestFetchTAXIIBounds(t *testing.T) {
	pages := [][]string{{stixIndicator(sha256A)}, {stixIndicator(sha256B)}, {stixIndicator(sha256A)}}
	_, srv := newTAXII(t, pages)
	col := srv.URL + "/collections/c1/"

	res, err := FetchTAXII(context.Background(), TAXIIOptions{CollectionURL: col, MaxPages: 2, Client: srv.Client()})
	if err != nil || !res.Truncated || res.Pages != 2 || len(res.Objects) != 2 {
		t.Errorf("page bound: %v %+v", err, res)
	}
	res, err = FetchTAXII(context.Background(), TAXIIOptions{CollectionURL: col, MaxObjects: 1, Client: srv.Client()})
	if err != nil || !res.Truncated || len(res.Objects) != 1 {
		t.Errorf("object bound: %v %+v", err, res)
	}
}

func TestFetchTAXIIRejects(t *testing.T) {
	ctx := context.Background()
	bad := map[string]TAXIIOptions{
		"cleartext":  {CollectionURL: "http://intel.example/collections/c1/"},
		"scheme":     {CollectionURL: "ftp://intel.example/collections/c1/"},
		"collection": {CollectionURL: "https://intel.example/api/"},
		"credential": {CollectionURL: "https://user:pw@intel.example/collections/c1/"},
		"RFC 3339":   {CollectionURL: "https://intel.example/collections/c1/", AddedAfter: "yesterday"},
	}
	for want, opts := range bad {
		if _, err := FetchTAXII(ctx, opts); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v", want, err)
		}
	}

	// A server that loops its cursor, or says "more" with no cursor.
	loop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", TAXIIMediaType)
		fmt.Fprint(w, `{"more":true,"next":"same","objects":[]}`)
	}))
	defer loop.Close()
	if _, err := FetchTAXII(ctx, TAXIIOptions{CollectionURL: loop.URL + "/collections/c1/", Client: loop.Client()}); err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Errorf("cursor loop: %v", err)
	}
	nocursor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", TAXIIMediaType)
		fmt.Fprint(w, `{"more":true,"objects":[]}`)
	}))
	defer nocursor.Close()
	if _, err := FetchTAXII(ctx, TAXIIOptions{CollectionURL: nocursor.URL + "/collections/c1/", Client: nocursor.Client()}); err == nil || !strings.Contains(err.Error(), "no next cursor") {
		t.Errorf("missing cursor: %v", err)
	}

	// Non-200, non-JSON.
	deny := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer deny.Close()
	if _, err := FetchTAXII(ctx, TAXIIOptions{CollectionURL: deny.URL + "/collections/c1/", Client: deny.Client()}); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("401: %v", err)
	}
	html := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>login</html>")
	}))
	defer html.Close()
	if _, err := FetchTAXII(ctx, TAXIIOptions{CollectionURL: html.URL + "/collections/c1/", Client: html.Client()}); err == nil || !strings.Contains(err.Error(), "content type") {
		t.Errorf("html: %v", err)
	}
}

// A redirect to another host must not be followed: it would carry the
// credential there and take detection content from an unnamed source.
func TestFetchTAXIIDoesNotFollowCrossHostRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"objects":[`+stixIndicator(sha256A)+`]}`)
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collections/c1/objects/", http.StatusFound)
	}))
	defer srv.Close()
	res, err := FetchTAXII(context.Background(), TAXIIOptions{
		CollectionURL: srv.URL + "/collections/c1/", Authorization: "Bearer s3cret", Client: srv.Client(),
	})
	if err == nil || len(res.Objects) != 0 || leaked != "" {
		t.Fatalf("redirect followed: err %v objects %d leaked %q", err, len(res.Objects), leaked)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("credential in error: %v", err)
	}
}

func TestTAXIIStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taxii.state")
	const col = "https://intel.example/collections/c1/"

	st, err := LoadTAXIIState(path, col)
	if err != nil || st.AddedAfter != "" || st.Collection != col {
		t.Fatalf("missing state should be an empty cursor: %v %+v", err, st)
	}
	st.AddedAfter = "2026-11-03T08:30:00.000Z"
	if err := SaveTAXIIState(path, st, time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	got, err := LoadTAXIIState(path, col)
	if err != nil || got.AddedAfter != st.AddedAfter || got.Updated != "2026-11-06T09:00:00Z" {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	if _, err := LoadTAXIIState(path, "https://other.example/collections/c2/"); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("a cursor for another collection must be refused: %v", err)
	}
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := LoadTAXIIState(path, col); err == nil {
		t.Error("corrupt state must be an error, not an empty cursor")
	}
	os.WriteFile(path, []byte(`{"collection":"`+col+`","added_after":"soon"}`), 0o600)
	if _, err := LoadTAXIIState(path, col); err == nil {
		t.Error("a bad timestamp in the state must be an error")
	}
}

func TestSTIXSkipsRevokedAndExpired(t *testing.T) {
	old := stixNow
	stixNow = func() time.Time { return time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC) }
	defer func() { stixNow = old }()
	bundle := `{"objects":[
	  {"type":"indicator","name":"live","confidence":85,"pattern":"[file:hashes.'SHA-256' = '` + sha256A + `']"},
	  {"type":"indicator","name":"revoked","revoked":true,"pattern":"[file:hashes.'SHA-256' = '` + sha256B + `']"},
	  {"type":"indicator","name":"expired","valid_until":"2025-01-01T00:00:00Z","pattern":"[file:hashes.'SHA-1' = '` + sha1A + `']"},
	  {"type":"indicator","name":"still valid","confidence":20,"valid_until":"2027-01-01T00:00:00Z","pattern":"[file:hashes.MD5 = '` + md5A + `']"}
	]}`
	iocs, err := ParseSTIX([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if hasHash(iocs, sha256B) != nil || hasHash(iocs, sha1A) != nil {
		t.Errorf("revoked or expired indicators were ingested: %+v", iocs)
	}
	if i := hasHash(iocs, sha256A); i == nil || i.Confidence != "high" {
		t.Errorf("live indicator: %+v", i)
	}
	if i := hasHash(iocs, md5A); i == nil || i.Confidence != "low" {
		t.Errorf("still-valid indicator: %+v", i)
	}
}

func TestSTIXConfidenceScale(t *testing.T) {
	p := func(n int) *int { return &n }
	for want, c := range map[string]*int{"unstated": nil, "none": p(0), "low": p(29), "medium": p(30), "high": p(70)} {
		if got := stixConfidence(c); got != want {
			t.Errorf("stixConfidence(%v) = %q, want %q", c, got, want)
		}
	}
	if stixConfidence(p(69)) != "medium" || stixConfidence(p(100)) != "high" || stixConfidence(p(1)) != "low" {
		t.Error("scale boundaries wrong")
	}
}

func TestMISPHonoursToIDS(t *testing.T) {
	doc := `{"Event":{"info":"Campaign","Attribute":[
	  {"type":"sha256","value":"` + sha256A + `","to_ids":true},
	  {"type":"sha256","value":"` + sha256B + `","to_ids":false},
	  {"type":"md5","value":"` + md5A + `"}
	]}}`
	iocs, err := ParseMISP([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if hasHash(iocs, sha256B) != nil {
		t.Error("a to_ids:false attribute is context, not a signature")
	}
	if hasHash(iocs, sha256A) == nil || hasHash(iocs, md5A) == nil {
		t.Errorf("to_ids:true and unflagged attributes must be kept: %+v", iocs)
	}
}

func TestProvenanceRecords(t *testing.T) {
	iocs, err := ParseSTIX([]byte(`{"objects":[{"type":"indicator","name":"Evil","confidence":75,"pattern":"[file:hashes.'SHA-256' = '` + sha256A + `']"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 11, 6, 9, 30, 0, 0, time.FixedZone("x", 3600))
	Stamp(iocs, "https://intel.example/collections/c1/", when)
	res := Apply(nil, iocs)
	if len(res.Accepted) != 1 || len(res.Signatures) != 1 || res.Accepted[0].Hash != res.Signatures[0].Hash {
		t.Fatalf("Accepted must mirror Signatures: %+v", res)
	}
	raw, err := Provenance(res.Accepted)
	if err != nil {
		t.Fatal(err)
	}
	var rec ProvenanceRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("one JSON object per line: %v\n%s", err, raw)
	}
	want := ProvenanceRecord{HashType: "SHA256", Hash: sha256A, ThreatName: "Evil", Source: "stix",
		Origin: "https://intel.example/collections/c1/", RetrievedAt: "2026-11-06T08:30:00Z", Confidence: "high"}
	if rec != want {
		t.Errorf("record\n got %+v\nwant %+v", rec, want)
	}

	// A source that states nothing is recorded as unstated, never guessed.
	mb, _ := ParseMalwareBazaar([]byte(`{"query_status":"ok","data":[{"sha256_hash":"` + sha256B + `","signature":"Fam"}]}`))
	raw, _ = Provenance(mb)
	if !strings.Contains(string(raw), `"confidence":"unstated"`) || strings.Contains(string(raw), "retrieved_at") {
		t.Errorf("unstamped, unstated record: %s", raw)
	}
}
