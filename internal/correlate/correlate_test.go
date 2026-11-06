package correlate

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

func TestChainAcrossLayers(t *testing.T) {
	got := Build([]Signal{
		{Layer: LayerProcess, Class: "procscan.netshell.socket-stdio", Score: 9, PID: 42, Files: []string{"/tmp/.x/run"}, Live: true},
		{Layer: LayerFile, Class: "file.suspicious", Score: 8, Files: []string{"/tmp/.x/run"}},
		{Layer: LayerPersistence, Class: "persist.cron.writable-path", Score: 8, Files: []string{"/etc/cron.d/job", "/tmp/.x/run"}},
	})
	if len(got) != 1 {
		t.Fatalf("one artefact is one incident, got %d: %+v", len(got), got)
	}
	if !got[0].Confirmed || len(got[0].Layers) != 3 || got[0].Score != 25 {
		t.Fatalf("got %+v", got[0])
	}
}

// Every shell's exe is /usr/bin/bash. Joining on it would collapse the host.
func TestSystemPathsDoNotLink(t *testing.T) {
	got := Build([]Signal{
		{Layer: LayerProcess, Class: "a", PID: 1, Files: []string{"/usr/bin/bash"}},
		{Layer: LayerProcess, Class: "b", PID: 2, Files: []string{"/usr/bin/bash"}},
	})
	if len(got) != 2 {
		t.Fatalf("unrelated shells merged: %+v", got)
	}
}

func TestConfirmationPolicy(t *testing.T) {
	cases := []struct {
		name    string
		signals []Signal
		want    bool
	}{
		{"argv text alone is not enough", []Signal{{Layer: LayerProcess, Class: "procscan.cmdline.reverse-shell", Score: 9, PID: 7}}, false},
		{"file heuristics alone are not enough", []Signal{{Layer: LayerFile, Class: "file.suspicious", Score: 8, Files: []string{"/tmp/a"}}}, false},
		{"persistence alone is not enough", []Signal{{Layer: LayerPersistence, Class: "persist.cron.x", Score: 8, Files: []string{"/etc/cron.d/j"}}}, false},
		{"live state is", []Signal{{Layer: LayerProcess, Class: "procscan.netshell.socket-stdio", Score: 9, PID: 7, Live: true}}, true},
		{"known-bad content is", []Signal{{Layer: LayerFile, Class: "file.malicious", Score: 10, Files: []string{"/tmp/a"}, Definitive: true}}, true},
		{"two layers are", []Signal{
			{Layer: LayerProcess, Class: "procscan.cmdline.reverse-shell", Score: 9, PID: 7, Files: []string{"/tmp/a"}},
			{Layer: LayerFile, Class: "file.suspicious", Score: 8, Files: []string{"/tmp/a"}},
		}, true},
		{"two signals from one layer are not", []Signal{
			{Layer: LayerFile, Class: "file.a", Score: 8, Files: []string{"/tmp/a"}},
			{Layer: LayerFile, Class: "file.b", Score: 8, Files: []string{"/tmp/a"}},
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Build(c.signals); len(got) != 1 || got[0].Confirmed != c.want {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestPlanNeverTouchesConfigOrUnconfirmed(t *testing.T) {
	inc := Build([]Signal{
		{Layer: LayerProcess, Class: "p", Score: 9, PID: 9, Files: []string{"/tmp/a"}, Live: true},
		{Layer: LayerFile, Class: "f", Score: 8, Files: []string{"/tmp/a"}},
		{Layer: LayerPersistence, Class: "c", Score: 8, Files: []string{"/etc/cron.d/j", "/tmp/a"}},
	})[0]
	want := Plan{Stop: []int{9}, Quarantine: []string{"/tmp/a"}}
	if got := PlanFor(inc); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	lone := Build([]Signal{{Layer: LayerProcess, Class: "p", PID: 9}})[0]
	if got := PlanFor(lone); got.Stop != nil || got.Quarantine != nil {
		t.Fatalf("an unconfirmed incident permits nothing: %+v", got)
	}
}

func TestReferencedPaths(t *testing.T) {
	got := ReferencedPaths(`* * * * * root /usr/bin/python3 /opt/app/run.py --log=/var/log/a.log; /tmp/.x/y`)
	want := []string{"/opt/app/run.py", "/var/log/a.log", "/tmp/.x/y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestFingerprintChangesWithNewEvidence(t *testing.T) {
	a := Build([]Signal{{Layer: LayerProcess, Class: "x", PID: 3}})[0]
	b := Build([]Signal{{Layer: LayerProcess, Class: "x", PID: 3}, {Layer: LayerKernel, Class: "y", PID: 3}})[0]
	if a.ID != b.ID {
		t.Fatal("the same artefact must keep its id")
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("new evidence must raise the incident again")
	}
}

func BenchmarkBuild(b *testing.B) {
	for _, n := range []int{10, 1000, 65536} {
		signals := make([]Signal, n)
		for i := range signals {
			signals[i] = Signal{Layer: LayerFile, Class: "file.suspicious", Score: 8, Files: []string{fmt.Sprintf("/tmp/f%d", i)}}
		}
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			for b.Loop() {
				Build(append([]Signal(nil), signals...))
			}
		})
	}
}

// Moving a PAM stack or a cron table aside by machine locks an operator out and
// destroys the evidence, however the file was flagged.
func TestConfigurationIsNeverQuarantined(t *testing.T) {
	for _, path := range []string{"/etc/pam.d/sshd", "/etc/cron.d/job", "/etc/sudoers.d/x", "/etc/systemd/system/a.service"} {
		inc := Incident{Confirmed: true, Signals: []Signal{{Layer: LayerFile, Class: "file.malicious", Definitive: true, Files: []string{path}}}}
		if p := PlanFor(inc); len(p.Quarantine) != 0 {
			t.Errorf("%s was planned for quarantine", path)
		}
	}
	inc := Incident{Confirmed: true, Signals: []Signal{{Layer: LayerFile, Files: []string{"/tmp/implant"}}}}
	if p := PlanFor(inc); !slices.Equal(p.Quarantine, []string{"/tmp/implant"}) {
		t.Fatalf("a dropped file must still be quarantined: %+v", p)
	}
}

// Sharing an interpreter outside the system paths must not extend a live process's
// confirmation to an unrelated one with only text against it.
func TestSharingAnInterpreterDoesNotStopAnArgvOnlyProcess(t *testing.T) {
	py := "/opt/conda/bin/python"
	got := Build([]Signal{
		{Layer: LayerProcess, Class: "procscan.shell.socket", Score: 9, PID: 100, Files: []string{py}, Live: true},
		{Layer: LayerProcess, Class: "procscan.argv.reverse-shell", Score: 8, PID: 200, Files: []string{py}},
	})
	if len(got) != 1 || !got[0].Confirmed {
		t.Fatalf("got %+v", got)
	}
	if p := PlanFor(got[0]); !slices.Equal(p.Stop, []int{100}) {
		t.Fatalf("argv text alone must never act: %+v", p)
	}
}

// What corroboration still has to reach: a file the scanner flagged, and a process
// running it, whatever that process's own signal was.
func TestCorroboratedProcessIsStillStopped(t *testing.T) {
	impl := "/tmp/implant"
	got := Build([]Signal{
		{Layer: LayerFile, Class: "file.suspicious", Score: 8, Files: []string{impl}},
		{Layer: LayerProcess, Class: "procscan.argv.reverse-shell", Score: 8, PID: 200, Files: []string{impl}},
	})
	if p := PlanFor(got[0]); !slices.Equal(p.Stop, []int{200}) {
		t.Fatalf("got %+v", p)
	}
	byPID := Build([]Signal{
		{Layer: LayerProcess, Class: "procscan.argv.x", Score: 8, PID: 300},
		{Layer: LayerNetwork, Class: "netscan.beacon", Score: 7, PID: 300, Peers: []string{"198.51.100.1"}},
	})
	if p := PlanFor(byPID[0]); !slices.Equal(p.Stop, []int{300}) {
		t.Fatalf("two layers on one process must stop it: %+v", p)
	}
}
