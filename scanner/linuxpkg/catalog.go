package linuxpkg

// Class describes one finding class the linuxpkg detector can emit, per
// technique it is evidence for, for the ATT&CK coverage matrix. Field names and
// tags match the sibling iso.Class / pdf.Class so the matrix builder treats
// every detector alike. Novel is empty: every class maps to an established
// ATT&CK technique.
type Class struct {
	Class       string `json:"class"`
	Technique   string `json:"technique"`
	Novel       string `json:"novel,omitempty"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
}

// Classes returns the catalog in a stable, report-friendly order: the install-
// script behaviours (shared with vectors.go), then the Flatpak permission grants,
// then the per-format structural notes.
func Classes() []Class {
	out := make([]Class, 0, len(scriptVectors)+len(flatpakPerms)+len(configVectors)+4)
	for _, v := range scriptVectors {
		out = append(out, Class{v.class, v.technique, "", v.score, v.detail})
	}
	for _, p := range flatpakPerms {
		out = append(out, Class{p.class, p.technique, "", p.score, p.detail})
	}
	for _, v := range configVectors {
		out = append(out, Class{v.class, v.technique, "", v.score, v.detail})
	}
	for _, v := range aptSourceVectors {
		out = append(out, Class{v.class, v.technique, "", v.score, v.detail})
	}
	out = append(out,
		Class{"linuxpkg.flatpak.bundle", techSupplyChain, "", 0,
			"a Flatpak single-file bundle (its OSTree payload is not unpacked by the pure-Go scanner)"},
		Class{"linuxpkg.rpm.scriptlet-interpreter", techUnixShell, "", 3,
			"an RPM scriptlet declared to run under a non-shell interpreter"},
		Class{"linuxpkg.appimage.type2", techSupplyChain, "", 0,
			"an AppImage type-2 image (self-mounting ELF with an appended SquashFS, runs unsandboxed)"},
		Class{"linuxpkg.deb.scripts-not-decoded", techSupplyChain, "", 1,
			"a .deb whose maintainer scripts are packed with xz/zstd and were not inspected"},
		Class{"linuxpkg.snap.package", techSupplyChain, "", 0,
			"a Snap package (SquashFS); its install/configure hooks run on install (payload not unpacked by the pure-Go scanner)"},
		Class{"linuxpkg.snap.classic-confinement", techSupplyChain, "", 3,
			"a Snap that declares classic confinement — it runs outside the snap sandbox with full host access"},
	)
	return out
}
