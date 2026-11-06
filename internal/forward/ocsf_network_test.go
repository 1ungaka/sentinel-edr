package forward

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/correlate"
)

// A network incident must carry its peer where a SIEM rule can find it, not
// only inside the message text.
func TestOCSFCarriesThePeer(t *testing.T) {
	inc := correlate.Build([]correlate.Signal{
		{Layer: correlate.LayerNetwork, Class: "netscan.egress.fileless", Score: 9, Live: true,
			Technique: "T1620,T1071", Detail: "bash pid 900 is connected to 203.0.113.9:443",
			Peers: []string{"203.0.113.9"}, PID: 900},
	})[0]
	ev := OCSFIncident(inc, DefaultProduct("host-a"), time.Now())

	dst, ok := ev["dst_endpoint"].(map[string]any)
	if !ok || dst["ip"] != "203.0.113.9" {
		t.Fatalf("dst_endpoint = %v", ev["dst_endpoint"])
	}
	evs, ok := ev["evidences"].([]map[string]any)
	if !ok {
		t.Fatalf("evidences = %v", ev["evidences"])
	}
	found := false
	for _, e := range evs {
		if ep, ok := e["dst_endpoint"].(map[string]any); ok && ep["ip"] == "203.0.113.9" {
			found = true
			if ep["type"] != "IPv4" {
				t.Errorf("endpoint type = %v, want IPv4", ep["type"])
			}
		}
	}
	if !found {
		t.Errorf("the peer is not in evidences: %v", evs)
	}
	// The envelope still round-trips the incident verbatim, peers included.
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Unmapped struct {
			Incident correlate.Incident `json:"incident"`
		} `json:"unmapped"`
	}
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Unmapped.Incident.Peers) != 1 {
		t.Errorf("the incident's peers did not survive the envelope: %+v", back.Unmapped.Incident)
	}
}

func TestOCSFWithSeveralPeersNamesNoneAtTheTop(t *testing.T) {
	inc := correlate.Build([]correlate.Signal{
		{Layer: correlate.LayerNetwork, Class: "netscan.sweep.pending", Score: 7, PID: 930,
			Peers: []string{"203.0.113.9", "203.0.113.10"}},
	})[0]
	ev := OCSFIncident(inc, DefaultProduct("host-a"), time.Now())
	if _, ok := ev["dst_endpoint"]; ok {
		t.Errorf("dst_endpoint should be absent when the incident has several peers: %v", ev["dst_endpoint"])
	}
}
