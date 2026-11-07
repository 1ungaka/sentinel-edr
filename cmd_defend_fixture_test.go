package main

import (
	"testing"

	"github.com/s-b-repo/cau/internal/procscan"
)

// TestArmedActions backs the warning a fixture /proc root deserves. The hazard
// is real and was measured: a fixture describes processes that do not exist, but
// a signal has one kernel to go to, so a scenario built around a made-up PID 900
// stopped this host's real process 900.
func TestArmedActions(t *testing.T) {
	if got := armedActions("", false, false, false); got != "" {
		t.Errorf("nothing armed should name nothing, got %q", got)
	}
	if got := armedActions(procscan.ActionStop, false, false, false); got != "--respond stop" {
		t.Errorf("got %q", got)
	}
	if got := armedActions(procscan.ActionKill, true, true, true); got != "--respond kill, --quarantine, --netblock, --block-exe" {
		t.Errorf("got %q", got)
	}
	if got := armedActions("", true, false, false); got != "--quarantine" {
		t.Errorf("a response that is not a signal still acts, got %q", got)
	}
}
