package static

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// machoSystemLibDirs are where Apple's and Homebrew's dylibs live; a load path
// under one of these, or a relocatable @-token, is not suspicious.
var machoSystemLibDirs = []string{
	"/usr/lib", "/System/", "/Library/", "/opt/homebrew/", "/usr/local/",
}

// machoRelocTokens are the dynamic-loader path tokens that resolve relative to
// the image or its loader — the Mach-O equivalent of $ORIGIN.
var machoRelocTokens = []string{"@executable_path", "@loader_path", "@rpath"}

// machoAnomalies derives the structural findings from a parsed Mach-O. For a
// universal binary it folds every slice's findings together, emitting each
// class at most once (the scorer requires it) and naming the architectures in
// the detail.
func machoAnomalies(m *MachO) []Anomaly {
	var out []Anomaly
	seen := map[string]bool{}
	add := func(class, cat string, score int, tech, format string, a ...interface{}) {
		if seen[class] {
			return
		}
		seen[class] = true
		out = append(out, Anomaly{Class: class, Category: cat, Score: score, Technique: tech, Detail: fmt.Sprintf(format, a...)})
	}

	if m.Fat {
		var arches []string
		for _, img := range m.Arches {
			arches = append(arches, img.CPUType)
		}
		add("macho.universal", CatInfo, 0, "", "universal binary with %d architecture(s): %s", len(m.Arches), strings.Join(arches, ", "))
	}

	for _, img := range m.Arches {
		tag := ""
		if m.Fat {
			tag = "[" + img.CPUType + "] "
		}
		image := img.FileTypeNum == mhExecute || img.FileTypeNum == mhDylib || img.FileTypeNum == mhBundle || img.FileTypeNum == mhKextBundle

		// ── Segments and sections ──
		var rwx, hiEnt, mismatch []string
		for _, s := range img.Segments {
			if s.Executable() && s.Writable() {
				rwx = append(rwx, fmt.Sprintf("%s(%s)", s.Name, s.Perms))
			}
			if s.Executable() && s.FileSize >= 1024 && s.Entropy > techMinEntropyExec && s.Name != "__LINKEDIT" {
				hiEnt = append(hiEnt, fmt.Sprintf("%s(%.2f)", s.Name, s.Entropy))
			}
			for _, sec := range s.Sections {
				if sec.Instructions() && s.Writable() {
					mismatch = append(mismatch, fmt.Sprintf("%s,%s is code in a writable segment", sec.Seg, sec.Name))
				}
			}
		}
		if len(rwx) > 0 {
			add("macho.segment-rwx", CatSections, 3, techEmbeddedPay, "%swritable+executable segment(s): %s", tag, strings.Join(rwx, ", "))
		}
		if len(hiEnt) > 0 {
			add("macho.segment-high-entropy", CatSections, 2, techObfuscated, "%sexecutable segment(s) above %.1f bits/byte: %s", tag, techMinEntropyExec, strings.Join(hiEnt, ", "))
		}
		if len(mismatch) > 0 {
			add("macho.section-exec-writable", CatSections, 2, techMasquerade, "%s%s", tag, strings.Join(mismatch, "; "))
		}

		// ── Entry point ──
		if image && img.Entry != 0 {
			switch {
			case img.EntrySegment < 0:
				add("macho.entry-outside-segments", CatEntry, 3, techObfuscated, "%sentry point 0x%x is mapped by no segment", tag, img.Entry)
			case !img.EntryExecutable:
				add("macho.entry-non-exec", CatEntry, 2, techObfuscated, "%sentry point 0x%x lies in a non-executable segment", tag, img.Entry)
			}
		}
		if img.Flags&mhAllowStackExecution != 0 {
			add("macho.stack-exec", CatEntry, 2, "", "%sheader requests an executable stack (MH_ALLOW_STACK_EXECUTION)", tag)
		}

		// ── Encryption / packer ──
		if img.Encrypted {
			// FairPlay (App Store) and protectors both set cryptid; low weight
			// with the honest note, like a named PE packer.
			add("macho.encrypted", CatPacker, 2, techPacking, "%sencrypted load region (LC_ENCRYPTION_INFO cryptid %d): FairPlay on App Store builds, a protector elsewhere", tag, img.CryptID)
		}

		// ── Imports / linkage ──
		if image && img.FileTypeNum == mhExecute && len(img.Dylibs) == 0 && img.ImportCount == 0 && m.Packer == nil {
			add("macho.imports-none", CatImports, 2, techDynamicAPI, "%sexecutable links no libraries and imports nothing", tag)
		}

		// ── Load paths ──
		if bad := machoInsecurePaths(img.RPaths); len(bad) > 0 {
			add("macho.rpath-insecure", CatDynamic, 2, techHijackFlow, "%sLC_RPATH searches attacker-writable or relative location(s): %s", tag, strings.Join(bad, ", "))
		}
		var badDylibs []string
		for _, d := range img.Dylibs {
			if machoSuspiciousLoad(d.Name) {
				badDylibs = append(badDylibs, d.Name)
			}
		}
		if len(badDylibs) > 0 {
			add("macho.dylib-suspicious-path", CatDynamic, 2, techHijackFlow, "%sloads library from a non-system, non-relocatable path: %s", tag, strings.Join(boundList(dedupe(badDylibs), 6), ", "))
		}

		// ── Signature (unverified) ──
		if img.Signed {
			add("macho.signature-unverified", CatInfo, 0, "", "%s%d byte code signature present; not verified (the trust store is not available to a file scanner)", tag, img.SignatureSize)
		} else if img.FileTypeNum == mhExecute {
			add("macho.unsigned", CatInfo, 0, "", "%sno LC_CODE_SIGNATURE (Gatekeeper enforces signing at launch, not from the file)", tag)
		}
	}

	// ── Overlay (thin only) ──
	if ov := m.Overlay; ov.Size >= minOverlayBytes {
		if ov.Size >= minHighOverlay && ov.Entropy > HighEntropy {
			add("macho.overlay-high-entropy", CatOverlay, 2, techEmbeddedPay, "%d bytes appended after the last segment at %.2f bits/byte", ov.Size, ov.Entropy)
		} else {
			add("macho.overlay-present", CatOverlay, 1, techEmbeddedPay, "%d bytes appended after the last segment (%.2f bits/byte)", ov.Size, ov.Entropy)
		}
	}

	// ── Packer ──
	if pk := m.Packer; pk != nil {
		if pk.Generic {
			add("macho.packer-generic", CatPacker, 3, techPacking, "packed executable profile: %s", strings.Join(pk.Evidence, "; "))
		} else {
			add("macho.packer", CatPacker, 2, techPacking, "packed with %s (%s)", pk.Name, strings.Join(pk.Evidence, "; "))
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}

// machoSuspiciousLoad reports whether a dylib load path is neither a system
// location nor a relocatable @-token: an absolute path under a writable tree,
// or a bare relative path, either of which is a dylib-hijack vector.
func machoSuspiciousLoad(name string) bool {
	if name == "" {
		return false
	}
	for _, t := range machoRelocTokens {
		if strings.HasPrefix(name, t) {
			return false
		}
	}
	if !strings.HasPrefix(name, "/") {
		// A bare name (libfoo.dylib) binds through the default search / rpath
		// and is normal; a relative path with a separator is not.
		return strings.Contains(name, "/")
	}
	for _, d := range machoSystemLibDirs {
		if strings.HasPrefix(name, d) {
			return false
		}
	}
	clean := path.Clean(name)
	for _, root := range insecureRPathRoots {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}

// machoInsecurePaths returns the LC_RPATH entries a local attacker can
// populate: relative paths and world-writable trees. @-tokens are safe.
func machoInsecurePaths(paths []string) []string {
	var bad []string
	for _, p := range paths {
		switch {
		case p == "" || p == ".":
			bad = append(bad, `"" (current directory)`)
		case strings.HasPrefix(p, "@"):
			// @executable_path / @loader_path / @rpath: relocatable, safe.
		case !strings.HasPrefix(p, "/"):
			bad = append(bad, p)
		default:
			clean := path.Clean(p)
			for _, root := range insecureRPathRoots {
				if clean == root || strings.HasPrefix(clean, root+"/") {
					bad = append(bad, p)
					break
				}
			}
		}
	}
	return boundList(bad, 6)
}
