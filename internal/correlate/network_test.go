package correlate

import (
	"slices"
	"testing"
)

func TestLinkablePeer(t *testing.T) {
	yes := []string{"203.0.113.9", "10.0.0.5", "192.168.1.1", "2001:db8::1", " 198.51.100.7 "}
	no := []string{"", "nonsense", "127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.251", "ff02::fb", "169.254.1.1", "fe80::1", "example.com"}
	for _, a := range yes {
		if !LinkablePeer(a) {
			t.Errorf("LinkablePeer(%q) = false, want true", a)
		}
	}
	for _, a := range no {
		if LinkablePeer(a) {
			t.Errorf("LinkablePeer(%q) = true, want false", a)
		}
	}
}

// TestPeerJoinsSignals is what makes a network finding actionable: the socket
// the kernel reports, the file the scanner flagged and the process that holds
// both become one incident.
func TestPeerJoinsSignals(t *testing.T) {
	incidents := Build([]Signal{
		{Layer: LayerNetwork, Class: "netscan.egress.fileless", Score: 9, Live: true, PID: 900,
			Peers: []string{"203.0.113.9"}},
		{Layer: LayerNetwork, Class: "netscan.beacon.periodic", Score: 6, Peers: []string{"203.0.113.9"}},
	})
	if len(incidents) != 1 {
		t.Fatalf("two signals about one peer are one incident, got %d", len(incidents))
	}
	inc := incidents[0]
	if !slices.Equal(inc.Peers, []string{"203.0.113.9"}) {
		t.Errorf("peers = %v", inc.Peers)
	}
	if !inc.Confirmed || inc.Why != "live attack state: netscan.egress.fileless" {
		t.Errorf("confirmed %v why %q", inc.Confirmed, inc.Why)
	}
	plan := PlanFor(inc)
	if !slices.Equal(plan.Block, []string{"203.0.113.9"}) {
		t.Errorf("plan.Block = %v", plan.Block)
	}
	if !slices.Equal(plan.Stop, []int{900}) {
		t.Errorf("plan.Stop = %v: the holder of the socket may be stopped", plan.Stop)
	}
}

// TestHostScopingKeepsArtefactsApart: two machines each have a /tmp/payload and
// each have a PID 900. Without scoping they would be joined into one incident
// and a response planned for the wrong machine.
func TestHostScopingKeepsArtefactsApart(t *testing.T) {
	incidents := Build([]Signal{
		{Layer: LayerFile, Class: "yara", Score: 10, Definitive: true, Files: []string{"/tmp/payload"}, PID: 900},
		{Layer: LayerExternal, Class: "file/yara", Score: 10, Definitive: true, Files: []string{"/tmp/payload"}, PID: 900, Host: "host-b"},
	})
	if len(incidents) != 2 {
		t.Fatalf("two hosts' artefacts must stay apart, got %d incident(s)", len(incidents))
	}
	for _, inc := range incidents {
		if len(inc.Layers) != 1 {
			t.Errorf("incident %s has layers %v: the hosts were joined", inc.ID, inc.Layers)
		}
	}
	if incidents[0].ID == incidents[1].ID {
		t.Error("the two incidents must not share an id")
	}
}

// TestRemoteSignalNeverDirectsALocalResponse: evidence from elsewhere
// corroborates, and nothing more. A peer host saying "stop PID 42" must not
// stop this host's PID 42.
func TestRemoteSignalNeverDirectsALocalResponse(t *testing.T) {
	inc := Build([]Signal{
		{Layer: LayerExternal, Class: "process/procscan.netshell.socket-stdio", Score: 9, Live: true,
			PID: 42, Files: []string{"/tmp/implant"}, Peers: []string{"203.0.113.9"}, Host: "host-b"},
	})[0]
	if !inc.Confirmed {
		t.Fatal("a peer host's live evidence still confirms an incident worth reporting")
	}
	plan := PlanFor(inc)
	if len(plan.Stop) != 0 || len(plan.Quarantine) != 0 || len(plan.Block) != 0 {
		t.Fatalf("a remote signal licensed a local action: %+v", plan)
	}
}

func TestOnlyTheNetworkLayerLicensesABlock(t *testing.T) {
	// A peer named by the file scanner is text inside a file. The kernel did not
	// report a connection to it, so it is not blocked.
	inc := Build([]Signal{
		{Layer: LayerFile, Class: "yara", Score: 10, Definitive: true,
			Files: []string{"/tmp/payload"}, Peers: []string{"203.0.113.9"}},
	})[0]
	if plan := PlanFor(inc); len(plan.Block) != 0 {
		t.Errorf("plan.Block = %v, want nothing: a string in a file is not a connection", plan.Block)
	}
}

func TestUnconfirmedIncidentPermitsNothing(t *testing.T) {
	inc := Build([]Signal{
		{Layer: LayerNetwork, Class: "netscan.listen.relay-tool", Score: 7, PID: 910, Peers: []string{"203.0.113.9"}},
	})[0]
	if inc.Confirmed {
		t.Fatal("one layer with no live state is an alert, not a confirmed incident")
	}
	if plan := PlanFor(inc); len(plan.Stop) != 0 || len(plan.Block) != 0 || len(plan.Quarantine) != 0 {
		t.Errorf("an unconfirmed incident permitted %+v", plan)
	}
}

func TestFingerprintChangesWhenAPeerIsAdded(t *testing.T) {
	a := Build([]Signal{{Layer: LayerNetwork, Class: "c", Score: 5, PID: 7}})[0]
	b := Build([]Signal{{Layer: LayerNetwork, Class: "c", Score: 5, PID: 7, Peers: []string{"203.0.113.9"}}})[0]
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("learning which peer a process is talking to is new evidence and must raise the incident again")
	}
}
