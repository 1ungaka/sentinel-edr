package correlate

import (
	"slices"
	"testing"
)

// A traversal that cleans into /etc is a cron table, not a dropped file: the
// store resolves the path with filepath.Abs before it acts, so the check has to
// see the same path the store will.
func TestQuarantinableJudgesTheCleanedPath(t *testing.T) {
	yes := []string{"/tmp/implant", "/var/tmp/x/../payload", "/dev/shm/.x", "/srv/data/dropper"}
	no := []string{
		"/etc/cron.d/job", "/etc/pam.d/sshd", "/etc/sudoers.d/x", "/etc", "/etc/",
		"/tmp/../etc/cron.d/job", // the finding's spelling
		"/var/tmp/../../etc/pam.d/sshd",
		"/tmp/./x/../../etc/systemd",
		"/tmp/x/..//../etc/cron.d/job",
		"etc/cron.d/job", // relative: not judgeable here
		"../etc/cron.d/job",
		"",
	}
	for _, p := range yes {
		if !Quarantinable(p) {
			t.Errorf("Quarantinable(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if Quarantinable(p) {
			t.Errorf("Quarantinable(%q) = true, want false", p)
		}
	}
}

// The policy is what PlanFor does, not what a predicate alone says: a confirmed
// malicious verdict on a traversal-named cron table must still alert only.
func TestPlanDoesNotQuarantineATraversalIntoEtc(t *testing.T) {
	inc := Build([]Signal{
		{Layer: LayerProcess, Class: "procscan.netshell.socket-stdio", Score: 9, PID: 9, Files: []string{"/tmp/.x/run"}, Live: true},
		{Layer: LayerFile, Class: "file.malicious", Score: 10, Definitive: true, Files: []string{"/tmp/.x/run"},
			Detail: "a cron table written through a traversal"},
	})[0]
	if !inc.Confirmed {
		t.Fatalf("fixture must be confirmed: %s", inc.Why)
	}
	// The incident names a cron table the file layer flagged, spelled through a
	// traversal from a writable directory.
	inc.Signals = append(inc.Signals, Signal{Layer: LayerFile, Class: "file.malicious", Score: 10, Definitive: true,
		Files: []string{"/tmp/.x/../../etc/cron.d/job"}})
	plan := PlanFor(inc)
	if !slices.Equal(plan.Quarantine, []string{"/tmp/.x/run"}) {
		t.Fatalf("plan.Quarantine = %v, want only the dropped file", plan.Quarantine)
	}
	if !slices.Equal(plan.Stop, []int{9}) {
		t.Errorf("plan.Stop = %v, want the shell still stopped", plan.Stop)
	}
}
