package forward

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/correlate"
	"github.com/1ungaka/sentinel-edr/internal/report"
)

func confirmedIncident() correlate.Incident {
	return correlate.Incident{
		ID:         "abc123",
		Files:      []string{"/tmp/dropper.bin"},
		PIDs:       []int{4242},
		Layers:     []correlate.Layer{"file", "process"},
		Techniques: []string{"T1003"},
		Score:      10,
		Confirmed:  true,
		Why:        "known-bad content: file.malicious",
		Signals: []correlate.Signal{
			{Layer: "file", Class: "file.malicious", Score: 10, Technique: "T1003",
				Detail: "YARA:mimikatz_strings", Files: []string{"/tmp/dropper.bin"}, Definitive: true},
			{Layer: "process", Class: "proc.memfd", Score: 6, Detail: "anonymous in-memory executable", PID: 4242, Live: true},
		},
	}
}

// encode round-trips the event the way the transport will, so the test checks
// what the SIEM actually receives rather than the in-memory map.
func encode(t *testing.T, ev map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	return out
}

func TestOCSFIncidentEnvelopeMatchesScanner(t *testing.T) {
	inc := confirmedIncident()
	ev := encode(t, OCSFIncident(inc, DefaultProduct("host-1"), time.Unix(1700000000, 0)))

	// The envelope has to be the one `cau scan --format ocsf` writes, or a SIEM
	// rule written for one surface silently misses the other.
	for field, want := range map[string]float64{
		"class_uid":    float64(report.OCSFClassUID),
		"category_uid": float64(report.OCSFCategoryUID),
		"type_uid":     float64(report.OCSFTypeUID),
		"activity_id":  float64(report.OCSFActivityID),
		"status_id":    float64(report.OCSFStatusNew),
		"time":         float64(time.Unix(1700000000, 0).UTC().UnixMilli()),
	} {
		if got, ok := ev[field].(float64); !ok || got != want {
			t.Errorf("%s = %v, want %v", field, ev[field], want)
		}
	}
	if ev["class_name"] != report.OCSFClassName {
		t.Errorf("class_name = %v, want %q", ev["class_name"], report.OCSFClassName)
	}
	meta := ev["metadata"].(map[string]any)
	if meta["version"] != report.OCSFVersion {
		t.Errorf("metadata.version = %v, want %q", meta["version"], report.OCSFVersion)
	}
	if prod := meta["product"].(map[string]any); prod["vendor_name"] != "CAU" {
		t.Errorf("vendor_name = %v, want CAU", prod["vendor_name"])
	}
}

func TestOCSFIncidentConfirmedIsHighAlert(t *testing.T) {
	ev := encode(t, OCSFIncident(confirmedIncident(), DefaultProduct("h"), time.Now()))
	if ev["is_alert"] != true {
		t.Error("a confirmed incident must be is_alert: it is what the daemon would act on")
	}
	if ev["severity"] != "High" {
		t.Errorf("severity = %v, want High", ev["severity"])
	}
}

// An unconfirmed incident is one layer's opinion. The daemon says so, and the
// forwarded event has to say so too, or a SIEM pages on `grep /dev/tcp notes`.
func TestOCSFIncidentUnconfirmedIsNotAnAlert(t *testing.T) {
	inc := confirmedIncident()
	inc.Confirmed = false
	inc.Why = "one layer, no live state: alert only"
	ev := encode(t, OCSFIncident(inc, DefaultProduct("h"), time.Now()))
	if ev["is_alert"] != false {
		t.Error("an unconfirmed incident must not be is_alert")
	}
	if ev["severity"] != "Medium" {
		t.Errorf("severity = %v, want Medium", ev["severity"])
	}
}

// The uid is the fingerprint the daemon dedupes on, so the same incident raised
// twice is collapsible in the SIEM rather than paging twice.
func TestOCSFIncidentUIDIsFingerprint(t *testing.T) {
	inc := confirmedIncident()
	ev := encode(t, OCSFIncident(inc, DefaultProduct("h"), time.Now()))
	fi := ev["finding_info"].(map[string]any)
	if got, want := fi["uid"], inc.Fingerprint(); got != want {
		t.Errorf("finding_info.uid = %v, want fingerprint %v", got, want)
	}
	// analytic.uid names the kind of detection, not this instance of it. The
	// incident's own id stays reachable in unmapped.
	if got := fi["analytic"].(map[string]any)["uid"]; got == inc.ID {
		t.Error("analytic.uid must not be the incident id: formats that use it as their event id could then never group two incidents of the same kind")
	}
	native := ev["unmapped"].(map[string]any)["incident"].(map[string]any)
	if native["id"] != inc.ID {
		t.Errorf("unmapped.incident.id = %v, want the incident id %v", native["id"], inc.ID)
	}
}

// The property the fix is for: two incidents about different artefacts, found
// the same way, must share an analytic uid so a CEF/LEEF class map groups them.
func TestOCSFAnalyticUIDGroupsLikeDetections(t *testing.T) {
	a := confirmedIncident()
	b := confirmedIncident()
	b.ID = "different-artefact"
	b.Files = []string{"/tmp/another.bin"}

	evA := encode(t, OCSFIncident(a, DefaultProduct("h"), time.Now()))
	evB := encode(t, OCSFIncident(b, DefaultProduct("h"), time.Now()))
	uid := func(e map[string]any) any {
		return e["finding_info"].(map[string]any)["analytic"].(map[string]any)["uid"]
	}
	if uid(evA) != uid(evB) {
		t.Errorf("analytic.uid differs for two incidents of the same kind (%v vs %v), so a class map cannot group them", uid(evA), uid(evB))
	}
	// And the two findings are still individually identifiable.
	fa := evA["finding_info"].(map[string]any)["uid"]
	fb := evB["finding_info"].(map[string]any)["uid"]
	if fa == fb {
		t.Error("finding_info.uid must still distinguish the two incidents")
	}
}

// A different kind of detection must not collapse into the same analytic.
func TestOCSFAnalyticUIDSeparatesDifferentDetections(t *testing.T) {
	a := confirmedIncident()
	b := confirmedIncident()
	b.Signals = []correlate.Signal{{
		Layer: "self", Class: "defend.tamper.feed", Score: 10, Live: true,
		Detail: "the feed was replaced",
	}}
	uid := func(inc correlate.Incident) any {
		return encode(t, OCSFIncident(inc, DefaultProduct("h"), time.Now()))["finding_info"].(map[string]any)["analytic"].(map[string]any)["uid"]
	}
	if uid(a) == uid(b) {
		t.Error("a YARA hit and a feed tamper must not share an analytic uid")
	}
}

// The verdict field the wire formats read, in the same place `cau scan` puts a
// file's verdict, carrying the distinction the daemon acts on.
func TestOCSFCarriesTheDaemonsVerdict(t *testing.T) {
	ev := encode(t, OCSFIncident(confirmedIncident(), DefaultProduct("h"), time.Now()))
	if got := ev["unmapped"].(map[string]any)["verdict"]; got != "CONFIRMED" {
		t.Errorf("unmapped.verdict = %v, want CONFIRMED", got)
	}
	inc := confirmedIncident()
	inc.Confirmed = false
	ev = encode(t, OCSFIncident(inc, DefaultProduct("h"), time.Now()))
	if got := ev["unmapped"].(map[string]any)["verdict"]; got != "ALERT" {
		t.Errorf("unmapped.verdict = %v, want ALERT", got)
	}
}

func TestOCSFIncidentResolvesTechniques(t *testing.T) {
	ev := encode(t, OCSFIncident(confirmedIncident(), DefaultProduct("h"), time.Now()))
	attacks, ok := ev["finding_info"].(map[string]any)["attacks"].([]any)
	if !ok || len(attacks) != 1 {
		t.Fatalf("attacks = %v, want one entry", ev["finding_info"])
	}
	tech := attacks[0].(map[string]any)["technique"].(map[string]any)
	if tech["uid"] != "T1003" {
		t.Errorf("technique uid = %v, want T1003", tech["uid"])
	}
	// The name is resolved from the bundled catalogue so the SIEM need not.
	if name, _ := tech["name"].(string); name == "" {
		t.Error("technique name should be resolved locally")
	}
}

// Garbage in a technique field must not become a malformed attack object.
func TestOCSFIncidentSkipsInvalidTechniques(t *testing.T) {
	inc := confirmedIncident()
	inc.Techniques = []string{"not-a-technique", "T1059.001", ""}
	ev := encode(t, OCSFIncident(inc, DefaultProduct("h"), time.Now()))
	attacks, _ := ev["finding_info"].(map[string]any)["attacks"].([]any)
	if len(attacks) != 1 {
		t.Fatalf("got %d attacks, want only the valid one", len(attacks))
	}
	if attacks[0].(map[string]any)["technique"].(map[string]any)["uid"] != "T1059.001" {
		t.Error("the valid technique should survive and the rest be dropped")
	}
}

func TestOCSFIncidentCarriesFilesAndProcesses(t *testing.T) {
	ev := encode(t, OCSFIncident(confirmedIncident(), DefaultProduct("h"), time.Now()))
	evs, ok := ev["evidences"].([]any)
	if !ok || len(evs) != 2 {
		t.Fatalf("evidences = %v, want a file and a process", ev["evidences"])
	}
	file := evs[0].(map[string]any)["file"].(map[string]any)
	if file["path"] != "/tmp/dropper.bin" || file["name"] != "dropper.bin" {
		t.Errorf("file evidence = %v", file)
	}
	proc := evs[1].(map[string]any)["process"].(map[string]any)
	if proc["pid"].(float64) != 4242 {
		t.Errorf("process evidence = %v", proc)
	}
}

// Only an exact identification becomes a malware name; a score is a suspicion.
func TestOCSFIncidentMalwareOnlyFromDefinitive(t *testing.T) {
	ev := encode(t, OCSFIncident(confirmedIncident(), DefaultProduct("h"), time.Now()))
	mw, ok := ev["malware"].([]any)
	if !ok || len(mw) != 1 {
		t.Fatalf("malware = %v, want one definitive name", ev["malware"])
	}
	if mw[0].(map[string]any)["name"] != "YARA:mimikatz_strings" {
		t.Errorf("malware name = %v", mw[0])
	}

	inc := confirmedIncident()
	for i := range inc.Signals {
		inc.Signals[i].Definitive = false
	}
	if ev := encode(t, OCSFIncident(inc, DefaultProduct("h"), time.Now())); ev["malware"] != nil {
		t.Error("a scored-only incident must not claim a malware name")
	}
}

// The mapping must not be lossier than the host's own log.
func TestOCSFIncidentKeepsNativeIncident(t *testing.T) {
	ev := encode(t, OCSFIncident(confirmedIncident(), DefaultProduct("host-7"), time.Now()))
	un := ev["unmapped"].(map[string]any)
	if un["agent_host"] != "host-7" {
		t.Errorf("agent_host = %v, want host-7", un["agent_host"])
	}
	native, ok := un["incident"].(map[string]any)
	if !ok {
		t.Fatalf("unmapped.incident missing: %v", un)
	}
	if native["why"] != "known-bad content: file.malicious" {
		t.Errorf("why = %v", native["why"])
	}
	sigs, _ := native["signals"].([]any)
	if len(sigs) != 2 {
		t.Fatalf("signals = %v, want both preserved", native["signals"])
	}
}

func TestOCSFIncidentMessageNamesStateAndLead(t *testing.T) {
	msg, _ := encode(t, OCSFIncident(confirmedIncident(), DefaultProduct("h"), time.Now()))["message"].(string)
	if !strings.HasPrefix(msg, "CONFIRMED") {
		t.Errorf("message = %q, want it to lead with the state", msg)
	}
	// The definitive signal leads even though another has a comparable score.
	if !strings.Contains(msg, "mimikatz_strings") {
		t.Errorf("message = %q, want the definitive signal named", msg)
	}
	if !strings.Contains(msg, "file+process") {
		t.Errorf("message = %q, want the agreeing layers named", msg)
	}
}

// A detail long enough to be a whole file's worth of text must not become the
// event's message: one incident cannot be allowed to blow a batch's size up.
func TestOCSFIncidentMessageIsBounded(t *testing.T) {
	inc := confirmedIncident()
	inc.Signals[0].Detail = strings.Repeat("A", 10000)
	msg, _ := encode(t, OCSFIncident(inc, DefaultProduct("h"), time.Now()))["message"].(string)
	if len(msg) > 500 {
		t.Errorf("message length %d, want it bounded", len(msg))
	}
}
