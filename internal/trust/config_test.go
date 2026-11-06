package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeConf(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "cau.conf")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigReadsSettings(t *testing.T) {
	p := writeConf(t, `
# where incidents go
siem      = 10.0.0.5
siem-user = cau-agent
siem-ca   = /etc/cau/ca.pem
siem-insecure = true

respond     = kill      # trailing comment
quarantine  = false
block-exe   = true
netblock    = false
report-only = true
feed        = /var/lib/cau/feed.txt
`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SIEM != "10.0.0.5" || cfg.SIEMUser != "cau-agent" || cfg.SIEMCA != "/etc/cau/ca.pem" {
		t.Errorf("siem settings = %+v", cfg)
	}
	if !cfg.SIEMInsecure {
		t.Error("siem-insecure should be true")
	}
	if cfg.Respond != "kill" {
		t.Errorf("respond = %q, want kill (a trailing comment must not become part of the value)", cfg.Respond)
	}
	for name, got := range map[string]*bool{
		"quarantine": cfg.Quarantine, "block-exe": cfg.BlockExe,
		"netblock": cfg.Netblock, "report-only": cfg.ReportOnly,
	} {
		if got == nil {
			t.Errorf("%s was not set", name)
		}
	}
	if *cfg.Quarantine || *cfg.Netblock || !*cfg.BlockExe || !*cfg.ReportOnly {
		t.Errorf("booleans parsed wrong: %+v", cfg)
	}
	if cfg.Feed != "/var/lib/cau/feed.txt" {
		t.Errorf("feed = %q", cfg.Feed)
	}
	if cfg.Path != p {
		t.Errorf("Path = %q, want %q", cfg.Path, p)
	}
}

// Running without a configuration file is the normal case on a fresh host and
// must not be an error.
func TestLoadConfigMissingFileIsNotAnError(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "absent.conf"))
	if err != nil {
		t.Fatalf("a missing config must not fail: %v", err)
	}
	if cfg.Path != "" || cfg.SIEM != "" {
		t.Errorf("want a zero config, got %+v", cfg)
	}
}

// A typo in a file nobody is watching should be reported, not silently obeyed
// as "nothing".
func TestLoadConfigKeepsUnknownKeys(t *testing.T) {
	cfg, err := LoadConfig(writeConf(t, "siem = 1.2.3.4\nsiemm = 9.9.9.9\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Unknown) != 1 || cfg.Unknown[0] != "siemm" {
		t.Errorf("Unknown = %v, want [siemm]", cfg.Unknown)
	}
}

func TestLoadConfigRejectsBadValues(t *testing.T) {
	for _, body := range []string{
		"quarantine = maybe\n",
		"respond = freeze\n",
		"siem 1.2.3.4\n",
	} {
		if _, err := LoadConfig(writeConf(t, body)); err == nil {
			t.Errorf("%q should not parse", body)
		}
	}
}

// A configuration file that exists but cannot be trusted must be an error, not
// a silent fall back to defaults: making the file unreadable or replacing it
// with a symlink is otherwise a way to choose the agent's behaviour.
func TestLoadConfigRefusesSymlink(t *testing.T) {
	real := writeConf(t, "siem = 1.2.3.4\n")
	link := filepath.Join(filepath.Dir(real), "link.conf")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := LoadConfig(link)
	if !errors.Is(err, ErrUnsafePath) {
		t.Errorf("a symlinked config must be refused, got %v", err)
	}
}

func TestCheckFileRefusesWorldWritable(t *testing.T) {
	p := writeConf(t, "siem = 1.2.3.4\n")
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(p); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("a world-writable file must be refused, got %v", err)
	}
}

func TestCheckFileRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	if err := CheckFile(dir); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("a directory is not a config file, got %v", err)
	}
}

// The ordinary case has to pass, or every check above is just an outage: a
// root-owned 0644 file in a 0755 directory is what the packages install.
func TestCheckFileAcceptsNormalFile(t *testing.T) {
	if err := CheckFile(writeConf(t, "siem = 1.2.3.4\n")); err != nil {
		t.Errorf("a normal 0644 file should be accepted, got %v", err)
	}
}

func TestSIEMURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"10.0.0.5", "https://10.0.0.5:55000"},
		{"10.0.0.5:9200", "https://10.0.0.5:9200"},
		{"wazuh.example.com", "https://wazuh.example.com:55000"},
		{"https://wazuh.example.com:55000", "https://wazuh.example.com:55000"},
		{"http://lab:55000", "http://lab:55000"},
		{"https://wazuh.example.com:55000/", "https://wazuh.example.com:55000"},
		// A bare IPv6 address has colons but no port, and must be bracketed.
		{"2001:db8::1", "https://[2001:db8::1]:55000"},
		{"[2001:db8::1]:55000", "https://[2001:db8::1]:55000"},
	} {
		if got := SIEMURL(tc.in); got != tc.want {
			t.Errorf("SIEMURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
