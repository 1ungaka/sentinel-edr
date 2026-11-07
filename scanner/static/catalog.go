package static

import "sort"

// Class describes one anomaly class the structural pass can emit. The
// catalog is detection content in its own right: the coverage matrix reads
// it to say which ATT&CK techniques the pass is evidence for, and a test pins
// it to the classes the analysis code actually emits so the two cannot drift.
type Class struct {
	// Class is the stable identifier ("section.rwx"). A trailing ".*" marks a
	// family whose suffix is decided at scan time ("packer.*" becomes
	// "packer.upx").
	Class string `json:"class"`
	// Category is the capped scoring category the class contributes to.
	Category string `json:"category"`
	// Weight is the largest score the class contributes before the category
	// cap applies; 0 marks an informational, never-scored class.
	Weight int `json:"weight"`
	// Technique is the ATT&CK technique id the class is evidence for, or ""
	// when the observation has no defensible mapping.
	Technique string `json:"technique,omitempty"`
	// Formats names the image types the class applies to: "pe", "elf" or
	// both. Fuzzy classes apply to every file type.
	Formats []string `json:"formats,omitempty"`
	// Description is one line for the matrix and the model card.
	Description string `json:"description"`
}

var (
	fmtPE    = []string{"pe"}
	fmtELF   = []string{"elf"}
	fmtMachO = []string{"macho"}
	fmtBoth  = []string{"pe", "elf"}
	fmtAny   = []string{"any"}
)

// classCatalog is hand-maintained; TestClassCatalogMatchesSource fails when a
// class is emitted by the analysis but missing here, or when a technique or
// weight disagrees with the emitting call.
var classCatalog = []Class{
	// Sections and segments.
	{"section.rwx", CatSections, 3, techEmbeddedPay, fmtPE, "writable and executable section; a kernel driver's INIT is exempt"},
	{"segment.rwx", CatSections, 3, techEmbeddedPay, fmtELF, "writable and executable PT_LOAD segment"},
	{"section.exec-high-entropy", CatSections, 2, techObfuscated, fmtPE, "executable section above 7.0 bits/byte"},
	{"segment.exec-high-entropy", CatSections, 2, techObfuscated, fmtELF, "executable segment above 7.0 bits/byte"},
	{"section.name-perm-mismatch", CatSections, 2, techMasquerade, fmtBoth, ".text not executable, or a data section executable"},
	{"section.virtual-raw-mismatch", CatSections, 2, techPacking, fmtPE, "executable section far larger in memory than on disk (unpack target)"},
	{"segment.virtual-raw-mismatch", CatSections, 2, techPacking, fmtELF, "executable segment far larger in memory than on disk (unpack target)"},
	{"section.exec-unusual-name", CatSections, 1, "", fmtBoth, "executable section with a non-compiler name"},
	{"section.headers-missing", CatSections, 2, techPacking, fmtELF, "no section header table: sstrip, a packer or a hand-built loader"},
	{"elf.tiny-loader", CatSections, 3, techPacking, fmtELF, "an ELF too small to be linker output, with no sections and no interpreter: a hand-built stub"},

	// Entry point.
	{"entrypoint.zero", CatEntry, 2, "", fmtBoth, "entry point is 0 in an executable"},
	{"entrypoint.outside-sections", CatEntry, 3, techObfuscated, fmtBoth, "entry point lies in no section"},
	{"entrypoint.outside-segments", CatEntry, 3, techObfuscated, fmtELF, "entry point is mapped by no PT_LOAD segment"},
	{"entrypoint.non-exec-section", CatEntry, 2, techObfuscated, fmtBoth, "entry point in a non-executable section"},
	{"entrypoint.non-exec-segment", CatEntry, 2, techObfuscated, fmtELF, "entry point in a non-executable segment"},
	{"entrypoint.zero-raw-section", CatEntry, 3, techPacking, fmtPE, "entry point in a section with no data on disk"},
	{"entrypoint.last-writable-section", CatEntry, 1, techPacking, fmtPE, "entry point in the last section, which is writable"},
	{"tls.callbacks", CatEntry, 1, "", fmtPE, "TLS callbacks run before the entry point"},
	{"segment.exec-stack", CatEntry, 2, "", fmtELF, "PT_GNU_STACK requests an executable stack"},
	{"segment.no-gnu-stack", CatEntry, 1, "", fmtELF, "dynamically linked image without PT_GNU_STACK"},

	// Headers and build record.
	{"header.timestamp-zero", CatHeaders, 1, techTimestomp, fmtPE, "link timestamp is zero"},
	{"header.timestamp-future", CatHeaders, 2, techTimestomp, fmtPE, "link timestamp is in the future"},
	{"header.timestamp-ancient", CatHeaders, 1, techTimestomp, fmtPE, "link timestamp predates 1995"},
	{"header.timestamp-mismatch", CatHeaders, 2, techTimestomp, fmtPE, "debug or export directory timestamp disagrees with the header"},
	{"header.timestamp-reproducible", CatInfo, 0, "", fmtPE, "reproducible build: the timestamp is a content hash (informational)"},
	{"header.timestamp-delphi", CatInfo, 0, "", fmtPE, "Borland/Delphi constant link timestamp (informational)"},
	{"rich.checksum-invalid", CatHeaders, 2, techMasquerade, fmtPE, "Rich header checksum mismatch: copied or hand-edited build record"},
	{"rich.missing-msvc", CatHeaders, 1, techMasquerade, fmtPE, "imports the MSVC runtime but carries no Rich header"},
	{"header.low-alignment", CatHeaders, 1, "", fmtPE, "hand-built or heavily squeezed alignment"},
	{"header.class-machine-mismatch", CatHeaders, 1, "", fmtELF, "ELF class disagrees with the declared machine"},
	{"dynamic.preinit-in-library", CatHeaders, 1, "", fmtELF, "shared object carries .preinit_array entries the loader ignores"},
	{"clr.present", CatInfo, 0, "", fmtPE, ".NET assembly; import analytics do not apply (informational)"},

	// Imports.
	{"imports.none", CatImports, 2, techDynamicAPI, fmtBoth, "no import table, or nothing imported through the loader"},
	{"imports.empty-descriptors", CatImports, 2, techDynamicAPI, fmtPE, "import descriptors present but no functions resolved"},
	{"imports.loader-only", CatImports, 2, techDynamicAPI, fmtBoth, "import table is only the loader stub"},
	{"imports.minimal", CatImports, 2, techDynamicAPI, fmtBoth, "three or fewer substantive imports"},

	// Packers.
	{"packer.generic", CatPacker, 3, techPacking, fmtBoth, "packed executable profile with no recognised packer"},
	{"packer.*", CatPacker, 2, techPacking, fmtBoth, "a recognised packer (UPX, ASPack, Themida, VMProtect, ...) named by its markers"},
	{"packer.installer-stub", CatInfo, 0, "", fmtPE, "self-extracting installer stub; a compressed payload is expected (informational)"},

	// Overlay.
	{"overlay.high-entropy", CatOverlay, 2, techEmbeddedPay, fmtBoth, "high-entropy data appended past the last section"},
	{"overlay.present", CatOverlay, 1, techEmbeddedPay, fmtBoth, "data appended past the last section"},
	{"overlay.appimage", CatInfo, 0, "", fmtELF, "AppImage: the appended filesystem is expected (informational)"},

	// Authenticode.
	{"authenticode.unverified", CatInfo, 0, "", fmtPE, "signature present; nothing is verified against a trust store (informational)"},
	{"authenticode.parse-error", CatSignature, 1, techInvalidSig, fmtPE, "security directory present but unparseable"},
	{"authenticode.vendor-name-self-signed", CatSignature, 6, techInvalidSig, fmtPE, "self-signed certificate wearing a well-known vendor's name"},
	{"authenticode.self-signed", CatSignature, 3, techCodeSigning, fmtPE, "signer certificate is self-signed"},
	{"authenticode.no-codesign-eku", CatSignature, 2, techCodeSigning, fmtPE, "signer certificate lacks the code-signing extended key usage"},
	{"authenticode.long-validity", CatSignature, 1, techCodeSigning, fmtPE, "signer certificate with an implausibly long validity"},
	{"authenticode.compiled-outside-validity", CatSignature, 2, techTimestomp, fmtPE, "link time outside the signer's validity with no countersignature"},
	{"authenticode.known-abused-signer", CatSignature, 9, techCodeSigning, fmtPE, "signed by a certificate on the known-abused-signer blocklist (lolcerts); a valid signature from a stolen/abused key"},

	// Dynamic linking (ELF).
	{"dynamic.interp-unusual", CatDynamic, 2, techHijackFlow, fmtELF, "program interpreter is not a system loader path"},
	{"dynamic.rpath-insecure", CatDynamic, 2, techHijackFlow, fmtELF, "RPATH/RUNPATH searches attacker-writable or relative locations"},
	{"dynamic.rpath", CatInfo, 0, "", fmtELF, "library search path baked in (informational)"},
	{"dynamic.needed-path", CatDynamic, 1, techHijackFlow, fmtELF, "DT_NEEDED names a path instead of a library name"},
	{"dynamic.textrel", CatDynamic, 1, techObfuscated, fmtELF, "text relocations: code pages rewritten by the loader"},
	{"dynamic.init-outside-code", CatDynamic, 2, techHijackFlow, fmtELF, "DT_INIT outside an executable segment"},
	{"dynamic.init-array-outside-code", CatDynamic, 2, techHijackFlow, fmtELF, "a resolved .init_array/.preinit_array constructor pointer lands outside executable code"},
	{"dynamic.symbol-versions", CatInfo, 0, "", fmtELF, "GNU symbol-version requirements read from .gnu.version_r (informational)"},
	{"dynamic.preload-interposer", CatDynamic, 3, techPreload, fmtELF, "shared object redefining libc entry points and resolving the originals with dlsym"},
	{"dynamic.preload-interposer-syscall", CatDynamic, 3, techPreload, fmtELF, "shared object redefining libc entry points and reaching the kernel through raw syscalls instead of dlsym"},
	{"dynamic.preload-interposer-known", CatInfo, 0, "", fmtELF, "a known interposer (sanitizers, fakeroot, libeatmydata, ...) named at weight 0 (informational)"},
	{"static.linked", CatInfo, 0, "", fmtELF, "statically linked; import analytics do not apply (informational)"},

	// Content of the loadable image (ELF): what a compiled binary carries.
	{"content.direct-syscalls", CatImports, 2, techNativeAPI, fmtELF, "dynamically linked image whose code loads sensitive system-call numbers (execve, memfd_create, ptrace, socket, ...) and traps directly instead of calling libc"},
	{"content.ssh-authorized-key", CatPersist, 3, techSSHKeys, fmtELF, "an authorized_keys path together with a complete embedded OpenSSH public key"},
	{"content.sshd-config-edit", CatPersist, 3, techSSHKeys, fmtELF, "the sshd_config path together with a login-widening directive written with its value (PermitRootLogin yes, ...)"},
	{"content.cron-job", CatPersist, 3, techCron, fmtELF, "a crontab location or crontab invocation together with a crontab line (five schedule fields or @reboot, then a command)"},
	{"content.systemd-unit", CatPersist, 2, techSystemdUnit, fmtELF, "a persistent systemd unit directory together with a whole unit-file body"},
	{"content.autostart-multi", CatPersist, 3, techAutostart, fmtELF, "three or more autostart mechanisms named (systemd, cron, init scripts, XDG autostart, shell start-up files, ld.so.preload), at least one with the body to install"},

	// Kernel modules (ELF).
	{"module.kernel", CatInfo, 0, "", fmtELF, "Linux kernel module identified (informational)"},
	{"module.unsigned", CatModule, 1, techRootkit, fmtELF, "kernel module without an appended signature"},
	{"module.signature-unverified", CatInfo, 0, "", fmtELF, "module signature present, not verified (informational)"},
	{"module.info-missing", CatModule, 2, techRootkit, fmtELF, "kernel module without .modinfo vermagic"},
	{"module.license-proprietary", CatInfo, 0, "", fmtELF, "module license taints the kernel (informational)"},

	// Format.
	{"format.truncated", CatFormat, 2, "", fmtBoth, "sections or segments claim data past the end of the file"},
	{"format.section-overlap", CatFormat, 2, techObfuscated, fmtPE, "sections overlap on disk"},
	{"format.no-sections", CatFormat, 2, "", fmtPE, "PE image declares no sections"},
	{"format.unparseable", CatFormat, 2, "", fmtBoth, "looks like an image but the headers cannot be parsed"},
	{"format.program-table-invalid", CatFormat, 2, "", fmtELF, "program header table the kernel cannot load"},
	{"format.section-table-invalid", CatFormat, 2, techObfuscated, fmtELF, "section table the loader ignores and analysis tools trip over"},
	{"format.interp-without-dynamic", CatFormat, 2, "", fmtELF, "program interpreter requested but no dynamic section"},
	{"format.type-unknown", CatFormat, 2, "", fmtELF, "ELF type that is neither executable, shared object, relocatable nor core"},
	{"format.core-dump", CatInfo, 0, "", fmtELF, "core dump; image rules do not apply (informational)"},

	// Mach-O.
	{"macho.universal", CatInfo, 0, "", fmtMachO, "universal (fat) binary; architecture list (informational)"},
	{"macho.segment-rwx", CatSections, 3, techEmbeddedPay, fmtMachO, "writable and executable segment"},
	{"macho.segment-high-entropy", CatSections, 2, techObfuscated, fmtMachO, "executable segment above 7.0 bits/byte"},
	{"macho.section-exec-writable", CatSections, 2, techMasquerade, fmtMachO, "section marked as code in a writable segment"},
	{"macho.entry-outside-segments", CatEntry, 3, techObfuscated, fmtMachO, "entry point mapped by no segment"},
	{"macho.entry-non-exec", CatEntry, 2, techObfuscated, fmtMachO, "entry point in a non-executable segment"},
	{"macho.stack-exec", CatEntry, 2, "", fmtMachO, "header requests an executable stack (MH_ALLOW_STACK_EXECUTION)"},
	{"macho.encrypted", CatPacker, 2, techPacking, fmtMachO, "encrypted load region (FairPlay on App Store builds, a protector elsewhere)"},
	{"macho.imports-none", CatImports, 2, techDynamicAPI, fmtMachO, "executable links no libraries and imports nothing"},
	{"macho.rpath-insecure", CatDynamic, 2, techHijackFlow, fmtMachO, "LC_RPATH searches an attacker-writable or relative location"},
	{"macho.dylib-suspicious-path", CatDynamic, 2, techHijackFlow, fmtMachO, "loads a library from a non-system, non-relocatable path"},
	{"macho.signature-unverified", CatInfo, 0, "", fmtMachO, "code signature present, not verified (informational)"},
	{"macho.unsigned", CatInfo, 0, "", fmtMachO, "executable without a code signature (informational)"},
	{"macho.overlay-present", CatOverlay, 1, techEmbeddedPay, fmtMachO, "bytes appended after the last segment"},
	{"macho.overlay-high-entropy", CatOverlay, 2, techEmbeddedPay, fmtMachO, "high-entropy bytes appended after the last segment"},
	{"macho.packer", CatPacker, 2, techPacking, fmtMachO, "packed with a recognised packer"},
	{"macho.packer-generic", CatPacker, 3, techPacking, fmtMachO, "packed executable profile without a named packer"},

	// Similarity.
	{"fuzzy.tlsh", CatFuzzy, 8, "", fmtAny, "TLSH distance at or below 30 to a database entry"},
	{"fuzzy.ssdeep", CatFuzzy, 8, "", fmtAny, "ssdeep score at or above 70 to a database entry"},
	{"fuzzy.imphash", CatFuzzy, 4, "", fmtAny, "exact import-hash match to a database entry"},
}

// Classes returns every anomaly class the structural pass can emit, sorted by
// class name. The slice is a copy; callers may modify it.
func Classes() []Class {
	out := make([]Class, len(classCatalog))
	copy(out, classCatalog)
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}

// Caps returns the per-category score caps.
func Caps() map[string]int {
	out := make(map[string]int, len(categoryCaps))
	for k, v := range categoryCaps {
		out[k] = v
	}
	return out
}
