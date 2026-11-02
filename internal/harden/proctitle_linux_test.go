//go:build linux

package harden

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRandName(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		n := randName()
		if len(n) < 6 || len(n) > 12 {
			t.Fatalf("randName %q length %d, want 6..12", n, len(n))
		}
		for _, c := range n {
			if !strings.ContainsRune(nameAlphabet, c) {
				t.Fatalf("randName %q has out-of-alphabet rune %q", n, c)
			}
		}
		seen[n] = true
	}
	if len(seen) < 150 {
		t.Errorf("randName looks non-random: %d distinct of 200", len(seen))
	}
}

func TestSanitizeEnv(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("GCONV_PATH", "/tmp/g")
	t.Setenv("LD_AUDIT", "/tmp/a.so")
	stripped := sanitizeEnv()
	for _, v := range []string{"LD_PRELOAD", "GCONV_PATH", "LD_AUDIT"} {
		if _, ok := os.LookupEnv(v); ok {
			t.Errorf("%s still set after sanitizeEnv", v)
		}
		found := false
		for _, s := range stripped {
			if s == v {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not reported in stripped list %v", v, stripped)
		}
	}
}

func TestDetectTracerNonNegative(t *testing.T) {
	// Normally 0; under a debugger it is the tracer PID. Either way it must be
	// a clean read, never negative.
	if n := detectTracer(); n < 0 {
		t.Errorf("detectTracer = %d, want >= 0", n)
	}
}

// The destructive parts (comm + argv rewrite) are verified in a disposable
// child so the test runner's own /proc view is never mutated.
func TestConcealChild(t *testing.T) {
	if os.Getenv("CAU_HARDEN_CHILD") != "1" {
		t.Skip("helper invoked by TestConcealInSubprocess")
	}
	c := ConcealProcess()
	comm, _ := os.ReadFile("/proc/self/comm")
	cmdline, _ := os.ReadFile("/proc/self/cmdline")
	first := cmdline
	if i := bytes.IndexByte(cmdline, 0); i >= 0 {
		first = cmdline[:i]
	}
	// Single line the parent parses, then exit before the test summary prints.
	os.Stdout.WriteString("RESULT" +
		" name=" + c.ProcessName +
		" comm=" + strings.TrimSpace(string(comm)) +
		" cmdline0=" + string(first) +
		" commset=" + btoa(c.CommSet) +
		" cmdmask=" + btoa(c.CmdlineMasked) +
		" stripped=" + strings.Join(c.EnvStripped, ",") +
		"\n")
	os.Exit(0)
}

func btoa(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func TestConcealInSubprocess(t *testing.T) {
	// Use os.Executable(), not os.Args[0]: an earlier in-process Apply() (from
	// TestApplyReportsSupported) rewrites this process's argv in place, so
	// os.Args[0] may already be masked. /proc/self/exe is unaffected.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(self, "-test.run=TestConcealChild")
	cmd.Env = append(os.Environ(), "CAU_HARDEN_CHILD=1", "LD_PRELOAD=/tmp/x.so")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	var line string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "RESULT ") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no RESULT line in child output:\n%s", out)
	}
	kv := map[string]string{}
	for _, f := range strings.Fields(strings.TrimPrefix(line, "RESULT ")) {
		if i := strings.IndexByte(f, '='); i >= 0 {
			kv[f[:i]] = f[i+1:]
		}
	}
	name := kv["name"]
	if name == "" {
		t.Fatal("child chose no name")
	}
	if kv["commset"] != "1" {
		t.Error("comm was not set in child")
	}
	// comm is capped at 15 chars; randName is <= 12, so it should match in full.
	if kv["comm"] != name {
		t.Errorf("comm = %q, want %q", kv["comm"], name)
	}
	// cmdline masking is best-effort; when it reports success, /proc must agree.
	if kv["cmdmask"] == "1" && kv["cmdline0"] != name {
		t.Errorf("cmdline0 = %q, want %q", kv["cmdline0"], name)
	}
	if !strings.Contains(kv["stripped"], "LD_PRELOAD") {
		t.Errorf("LD_PRELOAD not stripped (stripped=%q)", kv["stripped"])
	}
}
