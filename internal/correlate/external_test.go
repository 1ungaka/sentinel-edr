package correlate

import (
	"slices"
	"testing"
)

// A peer host's sensor saying "something happened, severity unknown" is not a
// second opinion about this host: it must not turn a local alert into a
// confirmed incident, and it must not be what stops a process or blocks a peer.
func TestInformationalTelemetryDoesNotCorroborate(t *testing.T) {
	for _, score := range []int{0, 1, 2} {
		inc := Build([]Signal{
			{Layer: LayerNetwork, Class: "netscan.egress.handler-port", Score: 3,
				PID: 500, Peers: []string{"203.0.113.9"}},
			{Layer: LayerExternal, Class: "external.egress", Score: score,
				Peers: []string{"203.0.113.9"}, Host: "fw-1"},
		})[0]
		if inc.Confirmed {
			t.Fatalf("score %d telemetry from elsewhere confirmed the incident: %s", score, inc.Why)
		}
		if p := PlanFor(inc); len(p.Stop) != 0 || len(p.Block) != 0 {
			t.Errorf("score %d telemetry licensed a response: %+v", score, p)
		}
	}
}

// The join still happens — the incident is one incident with the sensor named —
// so the alert keeps its cross-host context, and a real finding from the same
// sensor still confirms and still acts on what is local.
func TestRealTelemetryStillCorroborates(t *testing.T) {
	inc := Build([]Signal{
		{Layer: LayerNetwork, Class: "netscan.egress.handler-port", Score: 3,
			PID: 500, Peers: []string{"203.0.113.9"}},
		{Layer: LayerExternal, Class: "external.egress", Score: 7,
			Peers: []string{"203.0.113.9"}, Host: "fw-1"},
	})[0]
	if !inc.Confirmed || inc.Why == "" {
		t.Fatalf("a medium-or-better finding from elsewhere must still confirm: %s", inc.Why)
	}
	if len(inc.Layers) != 2 {
		t.Errorf("layers = %v, want both, named for the report", inc.Layers)
	}
	if !slices.Equal(inc.Hosts, []string{"fw-1"}) {
		t.Errorf("hosts = %v", inc.Hosts)
	}
	p := PlanFor(inc)
	if !slices.Equal(p.Stop, []int{500}) {
		t.Errorf("plan.Stop = %v: the holder of the connection may be stopped", p.Stop)
	}
	if !slices.Equal(p.Block, []string{"203.0.113.9"}) {
		t.Errorf("plan.Block = %v", p.Block)
	}
}

// Live local evidence never needed a second opinion, and still does not: the
// external layer's score changes nothing about it.
func TestLiveLocalEvidenceActsWithoutTelemetry(t *testing.T) {
	inc := Build([]Signal{
		{Layer: LayerNetwork, Class: "netscan.egress.fileless", Score: 9, Live: true,
			PID: 900, Peers: []string{"203.0.113.9"}},
		{Layer: LayerExternal, Class: "external.egress", Score: 1,
			Peers: []string{"203.0.113.9"}, Host: "fw-1"},
	})[0]
	if !inc.Confirmed {
		t.Fatal("live evidence must confirm on its own")
	}
	if p := PlanFor(inc); !slices.Equal(p.Stop, []int{900}) || !slices.Equal(p.Block, []string{"203.0.113.9"}) {
		t.Errorf("plan = %+v, want the live shell's holder stopped and the peer blocked", p)
	}
}
