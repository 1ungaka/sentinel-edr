package linuxpkg

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"regexp"
	"strings"
)

// Defensive caps. A hostile package must degrade to a partial result with a
// warning, never make the scanner allocate without bound, hang, or read out of
// range. These mirror the philosophy of the sibling iso9660 reader.
const (
	maxMembers         = 4096     // directory/archive entries walked
	maxScripts         = 128      // extracted scripts inspected
	maxScriptBytes     = 1 << 20  // 1 MiB per extracted script
	maxDecompressBytes = 64 << 20 // ceiling on any single decompressed stream
	maxManifestBytes   = 4 << 20  // flatpak/appstream manifest text
	maxRPMHeaderStore  = 32 << 20 // RPM header data-store size ceiling
	maxRPMIndexEntries = 1 << 16  // RPM header index-entry ceiling
)

// container is the parsed, format-neutral view the detector scores: which
// package format it is, an optional package name for context, the install-time
// scripts pulled out of it, and the bundle-level signals (flatpak permissions,
// compression we could not open) collected along the way.
type container struct {
	format      Format
	name        string
	scripts     []scriptSource
	findings    []Finding // bundle-level findings (not from script text)
	scriptNames []string  // names of scripts found (for the summary)
	warning     string
}

// ── format sniffing ────────────────────────────────────────────────────────────

// Format identifies the kind of Linux package a buffer is.
type Format string

const (
	FormatUnknown  Format = ""
	FormatDeb      Format = "deb"
	FormatRPM      Format = "rpm"
	FormatArch     Format = "arch"     // .pkg.tar(.zst/.xz/.gz) or a loose tar with pacman metadata
	FormatFlatpak  Format = "flatpak"  // single-file bundle or a flatpak-builder manifest
	FormatAppImage Format = "appimage" // type-2 AppImage (ELF + appended squashfs)
	FormatSnap     Format = "snap"     // Snap package (squashfs with snap.yaml + hooks)
	FormatArchive  Format = "archive"  // a generic .zip / .tar wrapper around a payload+script
	FormatDocker   Format = "docker"   // docker/podman save or OCI image tarball
	FormatPKGBUILD Format = "pkgbuild" // a bare PKGBUILD recipe
	FormatScript   Format = "script"   // a bare maintainer/install shell script
	FormatConfig   Format = "config"   // an executable config: .desktop/autostart, systemd unit, shell-rc
)

var (
	magicDeb      = []byte("!<arch>\n")
	magicRPM      = []byte{0xed, 0xab, 0xee, 0xdb}
	magicGzip     = []byte{0x1f, 0x8b}
	magicXz       = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	magicZstd     = []byte{0x28, 0xb5, 0x2f, 0xfd}
	magicBzip2    = []byte("BZh")
	magicELF      = []byte{0x7f, 'E', 'L', 'F'}
	magicAppImage = []byte{0x41, 0x49, 0x02}       // "AI\x02" at offset 8 = AppImage type 2
	magicSquashfs = []byte{0x68, 0x73, 0x71, 0x73} // "hsqs" = SquashFS (snap payload)
)

// Detect reports which package format data is, or FormatUnknown. It is cheap:
// magic-byte and small-prefix checks only.
func Detect(data []byte) Format {
	switch {
	case bytes.HasPrefix(data, magicDeb) && bytes.Contains(data[:min(len(data), 512)], []byte("debian-binary")):
		return FormatDeb
	case bytes.HasPrefix(data, magicRPM):
		return FormatRPM
	case len(data) >= 11 && bytes.HasPrefix(data, magicELF) && bytes.Equal(data[8:11], magicAppImage):
		return FormatAppImage
	case isSnap(data):
		return FormatSnap
	case isDockerImage(data):
		return FormatDocker
	case isArchPkg(data):
		return FormatArch
	case isFlatpakBundle(data), isFlatpakManifest(data):
		return FormatFlatpak
	case isGenericArchive(data):
		return FormatArchive
	case isPKGBUILD(data):
		return FormatPKGBUILD
	case isShellScript(data):
		return FormatScript
	case isExecConfig(data):
		return FormatConfig
	}
	return FormatUnknown
}

// parse dispatches to the per-format parser. It never returns nil.
func parse(data []byte) *container {
	switch Detect(data) {
	case FormatDeb:
		return parseDeb(data)
	case FormatRPM:
		return parseRPM(data)
	case FormatArch:
		return parseArch(data)
	case FormatFlatpak:
		return parseFlatpak(data)
	case FormatAppImage:
		return parseAppImage(data)
	case FormatSnap:
		return parseSnap(data)
	case FormatArchive:
		return parseArchive(data)
	case FormatDocker:
		return parseDocker(data)
	case FormatPKGBUILD:
		return parsePKGBUILD(data)
	case FormatConfig:
		return parseConfig(data)
	case FormatScript:
		return &container{format: FormatScript, scripts: []scriptSource{{name: "script", body: capStr(string(data))}}, scriptNames: []string{"script"}}
	}
	return &container{format: FormatUnknown}
}

// ── .deb (ar archive → control.tar.* → maintainer scripts) ──────────────────────

// debMaintainerScripts are the control-member names the package manager runs,
// in escalation order. Each runs as root around (un)installation.
var debMaintainerScripts = map[string]bool{
	"preinst": true, "postinst": true, "prerm": true, "postrm": true,
	"config": true, "triggers": false, // triggers is data, not a script
}

func parseDeb(data []byte) *container {
	c := &container{format: FormatDeb}
	members, warn := readAr(data)
	if warn != "" {
		c.warning = warn
	}
	for _, m := range members {
		if !strings.HasPrefix(m.name, "control.tar") {
			continue
		}
		body, cerr := decompressByName(m.name, m.data)
		if cerr != "" {
			c.warning = joinWarn(c.warning, "control member "+cerr)
			c.findings = append(c.findings, Finding{
				Class: "linuxpkg.deb.scripts-not-decoded", Score: 1, Technique: techSupplyChain,
				Detail:   "maintainer scripts are present but packed with a codec the pure-Go scanner does not decompress — they were not inspected",
				Evidence: m.name,
			})
			continue
		}
		c.extractTarScripts([]byte(body), func(name string) (string, bool) {
			base := name[strings.LastIndexByte(name, '/')+1:]
			if script, ok := debMaintainerScripts[base]; ok && script {
				return base, true
			}
			return "", false
		})
	}
	return c
}

// ── Arch (.pkg.tar.* → .INSTALL / .PKGBUILD) ─────────────────────────────────────

func isArchPkg(data []byte) bool {
	// A compressed tar whose decompressed stream carries Arch's metadata members.
	// We only cheaply confirm "looks like a (compressed) tar"; parseArch confirms
	// the members. A plain tar is also accepted so loose extractions still scan.
	body, _ := decompressAny(data)
	if body == nil {
		body = data
	}
	return tarHasMember(body, func(n string) bool {
		return n == ".INSTALL" || n == ".PKGBUILD" || n == ".PKGINFO" || n == ".MTREE"
	})
}

func parseArch(data []byte) *container {
	c := &container{format: FormatArch}
	body, warn := decompressAny(data)
	if body == nil {
		body = data
	}
	if warn != "" {
		c.warning = warn
	}
	c.extractTarScripts(body, func(name string) (string, bool) {
		switch name {
		case ".INSTALL":
			return ".INSTALL", true
		case ".PKGBUILD", "PKGBUILD":
			return "PKGBUILD", true
		}
		return "", false
	})
	return c
}

// ── Flatpak (single-file bundle, or a flatpak-builder manifest) ──────────────────

func isFlatpakBundle(data []byte) bool {
	// A .flatpak single-file bundle is an OSTree static-delta wrapped in a GVariant
	// container; it begins with the ASCII tag "flatpak" near the top.
	return bytes.Contains(data[:min(len(data), 256)], []byte("flatpak")) &&
		bytes.Contains(data[:min(len(data), 256)], []byte("xa.metadata"))
}

func isFlatpakManifest(data []byte) bool {
	head := data[:min(len(data), maxManifestBytes)]
	// A flatpak-builder manifest (JSON or YAML) names an app-id and finish-args /
	// modules. Keep the probe specific so ordinary JSON/YAML is not misfiled.
	hasID := bytes.Contains(head, []byte("app-id")) || bytes.Contains(head, []byte("\"id\"")) || bytes.Contains(head, []byte("id:"))
	hasFlatpakKey := bytes.Contains(head, []byte("finish-args")) || bytes.Contains(head, []byte("runtime")) && bytes.Contains(head, []byte("modules"))
	return hasID && hasFlatpakKey
}

// flatpakPerms are finish-args permission grants that widen the sandbox; the
// riskiest ones are a near-full sandbox escape.
var flatpakPerms = []vector{
	{class: "linuxpkg.flatpak.talk-portal-escape", score: 6, technique: techSupplyChain,
		detail: "requests org.freedesktop.Flatpak on the session bus — a full sandbox escape (can spawn host processes)",
		re:     regexp.MustCompile(`(?i)--talk-name=org\.freedesktop\.Flatpak`)},
	{class: "linuxpkg.flatpak.filesystem-host", score: 3, technique: techSupplyChain,
		detail: "grants --filesystem=host (full access to the host filesystem)",
		re:     regexp.MustCompile(`(?i)--filesystem=host\b`)},
	{class: "linuxpkg.flatpak.device-all", score: 2, technique: techSupplyChain,
		detail: "grants --device=all (raw access to every device node)",
		re:     regexp.MustCompile(`(?i)--device=all\b`)},
	{class: "linuxpkg.flatpak.session-bus-all", score: 3, technique: techSupplyChain,
		detail: "grants unrestricted session-bus access (--socket=session-bus with broad talk)",
		re:     regexp.MustCompile(`(?i)--socket=session-bus`)},
}

func parseFlatpak(data []byte) *container {
	c := &container{format: FormatFlatpak}
	if isFlatpakBundle(data) && !isFlatpakManifest(data) {
		c.findings = append(c.findings, Finding{
			Class: "linuxpkg.flatpak.bundle", Score: 0, Technique: techSupplyChain,
			Detail:   "flatpak single-file bundle detected; its OSTree payload is not unpacked by the pure-Go scanner",
			Evidence: "flatpak bundle",
		})
		c.warning = "flatpak bundle payload not unpacked"
		return c
	}
	text := string(data[:min(len(data), maxManifestBytes)])
	for _, p := range flatpakPerms {
		if loc := p.re.FindStringIndex(text); loc != nil {
			c.findings = append(c.findings, Finding{
				Class: p.class, Score: p.score, Technique: p.technique, Detail: p.detail,
				Evidence: excerpt(text, loc[0], loc[1]),
			})
		}
	}
	// build-commands and module sources are shell; run the script heuristic on the
	// whole manifest so an embedded curl|bash in a build step is caught.
	c.scripts = append(c.scripts, scriptSource{name: "flatpak-manifest", body: capStr(text)})
	c.scriptNames = append(c.scriptNames, "flatpak-manifest")
	return c
}

// ── AppImage (type-2: ELF stub + appended squashfs) ──────────────────────────────

// ── Snap (squashfs image with snap.yaml + meta/hooks) ────────────────────────────

func isSnap(data []byte) bool {
	// A .snap is a SquashFS image. Confirm the snap-specific metadata is present
	// so an arbitrary SquashFS filesystem is not misfiled as a snap.
	if !bytes.HasPrefix(data, magicSquashfs) {
		return false
	}
	head := data[:min(len(data), 1<<20)]
	return bytes.Contains(head, []byte("snap.yaml")) || bytes.Contains(head, []byte("meta/hooks")) || bytes.Contains(head, []byte("meta/snap.yaml"))
}

func parseSnap(data []byte) *container {
	c := &container{format: FormatSnap}
	c.findings = append(c.findings, Finding{
		Class: "linuxpkg.snap.package", Score: 0, Technique: techSupplyChain,
		Detail:   "Snap package (SquashFS); its install/configure hooks run on install under confinement set by the snap",
		Evidence: "snap.yaml",
	})
	// Snap hooks (meta/hooks/{install,configure,post-refresh,…}) and snap.yaml
	// `command:` entries live inside the SquashFS, which the pure-Go scanner does
	// not mount. Scan whichever hook/script text is readable in uncompressed
	// regions and note the rest honestly.
	if region := printableShellRegion(data); region != "" {
		c.scripts = append(c.scripts, scriptSource{name: "snap-hook", body: region})
		c.scriptNames = append(c.scriptNames, "snap-hook")
	} else {
		c.warning = "SquashFS payload compressed; hooks not inspected"
	}
	// `classic` confinement removes the sandbox entirely — worth surfacing.
	if bytes.Contains(data[:min(len(data), 1<<20)], []byte("confinement: classic")) {
		c.findings = append(c.findings, Finding{
			Class: "linuxpkg.snap.classic-confinement", Score: 3, Technique: techSupplyChain,
			Detail:   "snap declares classic confinement — it runs with full access to the host, outside the snap sandbox",
			Evidence: "confinement: classic",
		})
	}
	return c
}

func parseAppImage(data []byte) *container {
	c := &container{format: FormatAppImage}
	c.findings = append(c.findings, Finding{
		Class: "linuxpkg.appimage.type2", Score: 0, Technique: techSupplyChain,
		Detail:   "AppImage type-2 (self-mounting ELF with an appended SquashFS) — runs unsandboxed with the user's full privileges",
		Evidence: "AI\\x02",
	})
	// The squashfs payload may be uncompressed or packed (gzip/xz/zstd/lzo). We do
	// not mount it, but AppRun stubs and .desktop lures frequently leave readable
	// shell text in uncompressed regions; scan the whole buffer's printable runs.
	if region := printableShellRegion(data); region != "" {
		c.scripts = append(c.scripts, scriptSource{name: "appimage-embedded", body: region})
		c.scriptNames = append(c.scriptNames, "appimage-embedded")
	} else {
		c.warning = "squashfs payload compressed; embedded scripts not inspected"
	}
	return c
}

// ── bare PKGBUILD / shell maintainer script ──────────────────────────────────────

func isPKGBUILD(data []byte) bool {
	head := data[:min(len(data), 4096)]
	return (bytes.Contains(head, []byte("pkgname=")) || bytes.Contains(head, []byte("# Maintainer"))) &&
		(bytes.Contains(data, []byte("package()")) || bytes.Contains(data, []byte("build()")) || bytes.Contains(data, []byte("source=")))
}

func isShellScript(data []byte) bool {
	if bytes.HasPrefix(data, []byte("#!")) {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			nl = len(data)
		}
		first := string(data[:nl])
		return strings.Contains(first, "sh") || strings.Contains(first, "bash") || strings.Contains(first, "zsh")
	}
	return false
}

func parsePKGBUILD(data []byte) *container {
	return &container{
		format:      FormatPKGBUILD,
		scripts:     []scriptSource{{name: "PKGBUILD", body: capStr(string(data))}},
		scriptNames: []string{"PKGBUILD"},
	}
}

// ── shared tar/compression helpers ───────────────────────────────────────────────

// extractTarScripts walks a (decompressed) tar stream and, for each member whose
// name pick() accepts, appends the member body as a script. Bounded by maxMembers
// / maxScripts / maxScriptBytes.
func (c *container) extractTarScripts(tarData []byte, pick func(name string) (string, bool)) {
	tr := tar.NewReader(bytes.NewReader(tarData))
	members := 0
	for {
		if members >= maxMembers || len(c.scripts) >= maxScripts {
			c.warning = joinWarn(c.warning, "archive member cap reached")
			return
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			c.warning = joinWarn(c.warning, "tar: "+err.Error())
			return
		}
		members++
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		label, ok := pick(name)
		if !ok {
			continue
		}
		buf := make([]byte, 0, min64(hdr.Size, maxScriptBytes))
		w := bytes.NewBuffer(buf)
		if _, err := io.CopyN(w, tr, min64(hdr.Size, maxScriptBytes)); err != nil && err != io.EOF {
			continue
		}
		c.scripts = append(c.scripts, scriptSource{name: label, body: w.String()})
		c.scriptNames = append(c.scriptNames, label)
	}
}

// arMember is one member of an ar archive (the .deb outer container).
type arMember struct {
	name string
	data []byte
}

// readAr parses the ar archive used by .deb. It is tolerant: a truncated member
// stops the walk with a warning rather than erroring.
func readAr(data []byte) ([]arMember, string) {
	if !bytes.HasPrefix(data, magicDeb) {
		return nil, "not an ar archive"
	}
	off := len(magicDeb)
	var out []arMember
	for off+60 <= len(data) {
		if len(out) >= maxMembers {
			return out, "ar member cap reached"
		}
		hdr := data[off : off+60]
		if hdr[58] != 0x60 || hdr[59] != 0x0a {
			return out, "malformed ar header"
		}
		name := strings.TrimRight(string(hdr[0:16]), " ")
		name = strings.TrimSuffix(name, "/") // GNU ar terminates names with '/'
		size := parseDecimal(string(hdr[48:58]))
		off += 60
		if size < 0 || off+int(size) > len(data) {
			return out, "truncated ar member"
		}
		out = append(out, arMember{name: name, data: data[off : off+int(size)]})
		off += int(size)
		if size%2 == 1 {
			off++ // members are 2-byte aligned
		}
	}
	return out, ""
}

// decompressByName decompresses an archive member by the codec its name implies.
// It returns ("", reason) when the codec is one the stdlib cannot open (xz/zstd),
// so the caller can record an honest "not inspected" note instead of a verdict.
func decompressByName(name string, data []byte) (string, string) {
	switch {
	case strings.HasSuffix(name, ".tar"):
		return string(cap64(data)), ""
	case strings.HasSuffix(name, ".gz"):
		b, err := gunzip(data)
		if err != nil {
			return "", "gzip: " + err.Error()
		}
		return string(b), ""
	case strings.HasSuffix(name, ".bz2"):
		return string(cap64(readAllCapped(bzip2.NewReader(bytes.NewReader(data))))), ""
	case strings.HasSuffix(name, ".xz"):
		return "", "is xz-compressed (not decoded)"
	case strings.HasSuffix(name, ".zst"):
		return "", "is zstd-compressed (not decoded)"
	case strings.HasSuffix(name, ".lzma"):
		return "", "is lzma-compressed (not decoded)"
	}
	return string(cap64(data)), ""
}

// decompressAny sniffs the leading magic and decompresses with the stdlib where
// it can. It returns (nil, reason) for codecs the stdlib cannot open.
func decompressAny(data []byte) ([]byte, string) {
	switch {
	case bytes.HasPrefix(data, magicGzip):
		b, err := gunzip(data)
		if err != nil {
			return nil, "gzip: " + err.Error()
		}
		return b, ""
	case bytes.HasPrefix(data, magicBzip2):
		return readAllCapped(bzip2.NewReader(bytes.NewReader(data))), ""
	case bytes.HasPrefix(data, magicXz):
		return nil, "xz-compressed (not decoded)"
	case bytes.HasPrefix(data, magicZstd):
		return nil, "zstd-compressed (not decoded)"
	}
	return data, "" // assume already a plain tar
}

func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return readAllCapped(zr), nil
}

func readAllCapped(r io.Reader) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, maxDecompressBytes))
	return b
}

// tarHasMember decompresses (if needed) and reports whether any member name
// satisfies match. Bounded walk.
func tarHasMember(data []byte, match func(name string) bool) bool {
	tr := tar.NewReader(bytes.NewReader(data))
	for i := 0; i < maxMembers; i++ {
		hdr, err := tr.Next()
		if err != nil {
			return false
		}
		if match(strings.TrimPrefix(hdr.Name, "./")) {
			return true
		}
	}
	return false
}

// printableShellRegion extracts the largest run of printable ASCII that looks
// like shell text from an AppImage ELF region, capped. It is a best-effort read
// of uncompressed stub/AppRun text, never a squashfs mount.
func printableShellRegion(data []byte) string {
	window := data
	if len(window) > maxDecompressBytes {
		window = window[:maxDecompressBytes]
	}
	idx := bytes.Index(window, []byte("#!/"))
	if idx < 0 {
		return ""
	}
	end := idx + maxScriptBytes
	if end > len(window) {
		end = len(window)
	}
	seg := window[idx:end]
	// Trim at the first NUL run (end of a readable string region).
	if z := bytes.IndexByte(seg, 0x00); z > 0 {
		seg = seg[:z]
	}
	return string(seg)
}

// ── small helpers ────────────────────────────────────────────────────────────────

func parseDecimal(s string) int64 {
	s = strings.TrimSpace(s)
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int64(s[i]-'0')
	}
	if s == "" {
		return -1
	}
	return n
}

func capStr(s string) string {
	if len(s) > maxScriptBytes {
		return s[:maxScriptBytes]
	}
	return s
}

func cap64(b []byte) []byte {
	if len(b) > maxDecompressBytes {
		return b[:maxDecompressBytes]
	}
	return b
}

func joinWarn(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
