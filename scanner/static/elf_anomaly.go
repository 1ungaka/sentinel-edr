package static

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// ELF-specific categories. The PE categories (Sections, Entry Point, Headers,
// Imports, Packer, Overlay, Format) are shared; these two have no PE analogue.
const (
	CatDynamic = "Dynamic Linking"
	CatModule  = "Kernel Module"
)

// ATT&CK techniques used only by the ELF rules.
const (
	techHijackFlow = "T1574"     // Hijack Execution Flow
	techPreload    = "T1574.006" // Dynamic Linker Hijacking
	techRootkit    = "T1014"
)

// standardExecELFNames are the executable section names compilers, linkers
// and the kernel build emit. Anything else that is executable is hand-made.
var standardExecELFNames = map[string]bool{
	".text": true, ".init": true, ".fini": true, ".plt": true, ".plt.got": true, ".plt.sec": true,
	".iplt": true, ".init.text": true, ".exit.text": true, ".altinstr_replacement": true,
	".fixup": true, ".noinstr.text": true, ".entry.text": true, ".irqentry.text": true,
	".softirqentry.text": true, ".kprobes.text": true, ".cpuidle.text": true, ".sched.text": true,
	".spinlock.text": true, ".static_call.text": true, ".head.text": true, ".ltext": true,
	".meminit.text": true, ".ref.text": true, ".cpuinit.text": true, ".devinit.text": true,
	".devexit.text": true, ".memexit.text": true, ".gnu.warning": true, ".MIPS.stubs": true,
	".glink": true, ".sfpr": true, ".opd": true, "__libc_freeres_fn": true,
	".__libc_freeres_fn": true, ".text_env": true, ".ARM.exidx": false, ".sframe": false,
}

// dataSectionNames are names whose content is never instructions.
var dataSectionNames = map[string]bool{
	".data": true, ".rodata": true, ".bss": true, ".got": true, ".got.plt": true, ".dynamic": true,
	".data.rel.ro": true, ".eh_frame": true, ".eh_frame_hdr": true, ".dynsym": true, ".dynstr": true,
	".interp": true, ".note.gnu.build-id": true, ".tdata": true, ".tbss": true, ".init_array": true,
	".fini_array": true, ".rela.dyn": true, ".rela.plt": true, ".rel.dyn": true, ".rel.plt": true,
	".comment": true, ".symtab": true, ".strtab": true, ".shstrtab": true, ".gnu.hash": true,
}

// elfLinkBoilerplate are undefined symbols every glibc-linked object carries
// whether or not it calls anything; they never count as imports of substance.
var elfLinkBoilerplate = map[string]bool{
	"__gmon_start__": true, "_ITM_deregisterTMCloneTable": true, "_ITM_registerTMCloneTable": true,
	"__cxa_finalize": true, "__stack_chk_fail": true, "_Jv_RegisterClasses": true,
	"__libc_start_main": true, "__libc_csu_init": true, "__libc_csu_fini": true,
	"_init": true, "_fini": true, "__deregister_frame_info": true, "__register_frame_info": true,
	"abort": true, "exit": true, "_exit": true, "__errno_location": true,
}

// elfLoaderOnlyImports is the import profile of a stub that resolves
// everything else at run time.
var elfLoaderOnlyImports = map[string]bool{
	"dlopen": true, "dlsym": true, "dlclose": true, "dlerror": true, "dlvsym": true, "dlinfo": true,
	"__libc_dlopen_mode": true, "__libc_dlsym": true, "__libc_dlvsym": true,
	"mmap": true, "mmap64": true, "munmap": true, "mprotect": true, "memcpy": true, "memset": true,
	"memfd_create": true, "syscall": true, "getauxval": true,
}

// elfLoaderTells is the subset of elfLoaderOnlyImports that must be present
// for the loader-only verdict: a tiny program that only calls memcpy is not a
// loader.
var elfLoaderTells = map[string]bool{
	"dlopen": true, "dlsym": true, "dlvsym": true, "__libc_dlopen_mode": true, "__libc_dlsym": true,
	"__libc_dlvsym": true, "memfd_create": true,
}

// interposerTargets are the libc entry points that LD_PRELOAD rootkits
// (Jynx, Azazel, BEURK, libprocesshider and their descendants) replace to
// hide files, processes and connections. Allocator symbols are deliberately
// absent (jemalloc and tcmalloc replace malloc legitimately) and so is the
// PAM API, which libpam itself defines while importing dlsym.
var interposerTargets = map[string]bool{
	"readdir": true, "readdir64": true, "readdir_r": true, "readdir64_r": true,
	"opendir": true, "fdopendir": true, "getdents": true, "getdents64": true,
	"fopen": true, "fopen64": true, "open": true, "open64": true, "openat": true, "openat64": true,
	"stat": true, "stat64": true, "lstat": true, "lstat64": true, "fstatat": true, "fstatat64": true,
	"__xstat": true, "__xstat64": true, "__lxstat": true, "__lxstat64": true, "__fxstatat": true, "__fxstatat64": true,
	"access": true, "faccessat": true, "unlink": true, "unlinkat": true, "rmdir": true, "rename": true, "link": true,
	"accept": true, "accept4": true, "connect": true, "bind": true,
	"execve": true, "execv": true, "execvp": true, "execvpe": true, "ptrace": true, "kill": true,
	"getpwnam": true, "getpwuid": true, "pcap_loop": true, "pcap_dispatch": true, "pcap_next": true,
}

// knownInterposers are shared objects that interpose libc on purpose and say
// so in their name: sanitizer runtimes, fakeroot, socks wrappers, sudo's
// noexec shims, test harness wrappers. They are reported, not scored.
var knownInterposers = []string{
	"sudo_noexec", "sudo_intercept",
	"libasan", "libtsan", "liblsan", "libhwasan", "libubsan", "libmsan", "libclang_rt",
	"libfakeroot", "libfakechroot", "libeatmydata", "libtsocks", "libtorsocks", "libproxychains",
	"libfaketime", "libsnoopy", "libsegfault", "libpthread", "libc.so", "libc-", "libgcompat",
	"libproot", "libumockdev-preload", "libpreloadvaccine", "libnosync", "libsandbox",
	"libgcov", "libmemusage", "libpcprofile", "libnss_", "libdl", "libsocket_wrapper",
	"libnss_wrapper", "libuid_wrapper", "libpam_wrapper", "libresolv_wrapper", "libefence",
	"libduma", "libmtrace", "libstdbuf", "libtrash", "libnotify-osd", "libgtk3-nocsd",
	"libstrace", "libltrace", "libintercept", "libpreload", "libwrap", "libjemalloc", "libtcmalloc",
}

// systemLoaderDirs are where program interpreters live. The basename must
// also look like a loader (ld-*, ld.so, ld64*, linker*).
var systemLoaderDirs = []string{"/lib", "/usr/lib", "/libexec", "/usr/libexec", "/nix/store/", "/gnu/store/", "/system/bin", "/apex/"}

// insecureRPathRoots are directories any local user can write to.
var insecureRPathRoots = []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/mnt", "/media", "/run/user", "/proc"}

// tinyLoaderMax is the most file-backed bytes an ELF can load and still be too
// small to have come from a linker and a libc. No benign ELF in the lab samples
// (docs/evaluation.md) is below it without a section table or an interpreter.
const tinyLoaderMax = 4096

// loadedBytes is the file-backed size of the loadable segments.
func loadedBytes(e *ELF) uint64 {
	var n uint64
	for _, s := range e.Segments {
		if s.Load() {
			n += s.FileSize
		}
	}
	return n
}

// elfAnomalies derives the structural findings from a parsed ELF.
func elfAnomalies(e *ELF) []Anomaly {
	var out []Anomaly
	add := func(class, cat string, score int, tech, format string, a ...interface{}) {
		out = append(out, Anomaly{Class: class, Category: cat, Score: score, Technique: tech, Detail: fmt.Sprintf(format, a...)})
	}
	image := e.Type == etExec || e.Type == etDyn

	// ── Segments and sections ──
	var rwx, hiEnt, vsz, truncated, mismatch, oddExec []string
	for i, s := range e.Segments {
		if !s.Load() {
			if s.Truncated {
				truncated = append(truncated, fmt.Sprintf("%s segment", s.Type))
			}
			continue
		}
		label := fmt.Sprintf("LOAD[%d]", i)
		if s.Executable() && s.Writable() {
			rwx = append(rwx, fmt.Sprintf("%s(%s)", label, s.Perms))
		}
		if s.Executable() && s.FileSize >= 1024 && s.Entropy > techMinEntropyExec {
			hiEnt = append(hiEnt, fmt.Sprintf("%s(%.2f)", label, s.Entropy))
		}
		if s.Executable() && s.MemSize >= 64<<10 && s.MemSize > 4*s.FileSize {
			vsz = append(vsz, fmt.Sprintf("%s(file %d, memory %d)", label, s.FileSize, s.MemSize))
		}
		if s.Truncated {
			truncated = append(truncated, label)
		}
	}
	for _, s := range e.Sections {
		name := s.Name
		if s.Truncated {
			if name == "" {
				name = "<unnamed>"
			}
			truncated = append(truncated, name)
		}
		if !s.Alloc() || s.Type == shtNull {
			continue
		}
		switch {
		case name == ".text" && !s.Executable():
			mismatch = append(mismatch, ".text is not executable")
		case name == ".text" && s.Writable():
			mismatch = append(mismatch, ".text is writable")
		case dataSectionNames[name] && s.Executable():
			mismatch = append(mismatch, name+" is executable")
		}
		if s.Executable() && e.Packer == nil && !standardExecELFNames[name] && !strings.HasPrefix(name, ".text") &&
			!strings.HasPrefix(name, ".init") && !strings.HasPrefix(name, ".exit") && e.Module == nil {
			if name == "" {
				name = "<unnamed>"
			}
			oddExec = append(oddExec, name)
		}
	}
	if len(rwx) > 0 {
		add("segment.rwx", CatSections, 3, techEmbeddedPay, "writable+executable segment(s): %s", strings.Join(rwx, ", "))
	}
	if len(hiEnt) > 0 {
		add("segment.exec-high-entropy", CatSections, 2, techObfuscated, "executable segment(s) above %.1f bits/byte: %s", techMinEntropyExec, strings.Join(hiEnt, ", "))
	}
	if len(vsz) > 0 {
		add("segment.virtual-raw-mismatch", CatSections, 2, techPacking, "executable segment(s) far larger in memory than on disk (unpack target): %s", strings.Join(vsz, ", "))
	}
	if len(mismatch) > 0 {
		add("section.name-perm-mismatch", CatSections, 2, techMasquerade, "%s", strings.Join(mismatch, "; "))
	}
	if len(oddExec) > 0 {
		sort.Strings(oddExec)
		add("section.exec-unusual-name", CatSections, 1, "", "executable section(s) with non-compiler names: %s", strings.Join(dedupe(oddExec), ", "))
	}
	if image && e.NoSectionHeaders {
		add("section.headers-missing", CatSections, 2, techPacking, "no section header table: stripped below what any linker emits (sstrip, packer or hand-built loader)")
		if n := loadedBytes(e); n <= tinyLoaderMax && e.Interp == "" {
			add("elf.tiny-loader", CatSections, 3, techPacking, "%d loaded bytes with no sections or program interpreter: a hand-built stub, not linker output", n)
		}
	}

	// ── Entry point ──
	if image && e.ProgramTableInvalid == "" {
		switch {
		case e.Entry == 0 && e.Type == etExec:
			add("entrypoint.zero", CatEntry, 2, "", "entry point is 0 in an executable")
		case e.Entry != 0 && e.EntrySegment < 0:
			add("entrypoint.outside-segments", CatEntry, 3, techObfuscated, "entry point 0x%x is mapped by no PT_LOAD segment", e.Entry)
		case e.Entry != 0:
			seg := e.Segments[e.EntrySegment]
			if !seg.Executable() {
				add("entrypoint.non-exec-segment", CatEntry, 2, techObfuscated, "entry point 0x%x lies in a non-executable segment (%s)", e.Entry, seg.Perms)
			}
			if len(e.Sections) > 0 && e.SectionTableInvalid == "" {
				if e.EntrySection == "" && !entryInAnySection(e) {
					add("entrypoint.outside-sections", CatEntry, 2, techObfuscated, "entry point 0x%x lies in no section although a section table exists", e.Entry)
				} else if sec := sectionNamed(e, e.EntrySection); sec != nil && !sec.Executable() {
					add("entrypoint.non-exec-section", CatEntry, 2, techObfuscated, "entry point in non-executable section %s (%s)", sec.Name, sec.Perms)
				}
			}
		}
		if e.StackPresent && e.StackExecutable {
			add("segment.exec-stack", CatEntry, 2, "", "PT_GNU_STACK requests an executable stack")
		} else if !e.StackPresent && e.Interp != "" {
			add("segment.no-gnu-stack", CatEntry, 1, "", "dynamically linked image without PT_GNU_STACK (stack executability left to the kernel default)")
		}
		if e.PreinitCount > 0 && e.Type == etDyn && e.Interp == "" {
			add("dynamic.preinit-in-library", CatHeaders, 1, "", "shared object carries %d .preinit_array entries (ignored by the loader; present only in hand-built objects)", e.PreinitCount)
		}
	}

	// ── Headers ──
	if is64Machine(e.Machine) && !e.is64 || is32Machine(e.Machine) && e.is64 {
		add("header.class-machine-mismatch", CatHeaders, 1, "", "%s image declares machine %s", e.Class, e.MachineName)
	}

	// ── Dynamic linking ──
	if e.Interp != "" && interpUnusual(e.Interp) {
		add("dynamic.interp-unusual", CatDynamic, 2, techHijackFlow, "program interpreter %q is not a system loader path", e.Interp)
	}
	if bad := insecureRPaths(append(append([]string{}, e.RPath...), e.RunPath...)); len(bad) > 0 {
		add("dynamic.rpath-insecure", CatDynamic, 2, techHijackFlow, "RPATH/RUNPATH searches attacker-writable or relative location(s): %s", strings.Join(bad, ", "))
	} else if len(e.RPath)+len(e.RunPath) > 0 {
		add("dynamic.rpath", CatInfo, 0, "", "library search path baked in: %s", strings.Join(boundList(append(append([]string{}, e.RPath...), e.RunPath...), 6), ", "))
	}
	if paths := neededWithPath(e.Needed); len(paths) > 0 {
		add("dynamic.needed-path", CatDynamic, 1, techHijackFlow, "DT_NEEDED names a path instead of a library name: %s", strings.Join(paths, ", "))
	}
	if e.TextRel && image {
		add("dynamic.textrel", CatDynamic, 1, techObfuscated, "text relocations: code pages are rewritten by the loader (DF_TEXTREL)")
	}
	if e.Init != 0 && image && e.ProgramTableInvalid == "" {
		if idx := e.segmentIndexForVA(e.Init); idx < 0 || !e.Segments[idx].Executable() {
			add("dynamic.init-outside-code", CatDynamic, 2, techHijackFlow, "DT_INIT 0x%x is not in an executable segment", e.Init)
		}
	}
	if image && e.ProgramTableInvalid == "" {
		var bad []string
		for _, t := range e.InitArrayTargets {
			if t.Source == "unresolved" || t.Executable {
				continue
			}
			where := t.Section
			if where == "" {
				where = "no executable segment"
			}
			bad = append(bad, fmt.Sprintf("%s->0x%x in %s", t.Array, t.VA, where))
		}
		if len(bad) > 0 {
			add("dynamic.init-array-outside-code", CatDynamic, 2, techHijackFlow, "%d constructor pointer(s) resolve outside executable code: %s", len(bad), strings.Join(boundList(bad, 6), ", "))
		}
	}
	if len(e.VersionsNeeded) > 0 {
		var parts []string
		for _, v := range e.VersionsNeeded {
			if len(v.Versions) > 0 {
				parts = append(parts, fmt.Sprintf("%s (%s)", v.File, strings.Join(boundList(v.Versions, 4), ", ")))
			}
		}
		if len(parts) > 0 {
			add("dynamic.symbol-versions", CatInfo, 0, "", "symbol-version requirements: %s", strings.Join(boundList(parts, 6), "; "))
		}
	}
	if e.Type == etDyn && e.Interp == "" {
		if hits := interposerHits(e); len(hits) >= 2 {
			switch {
			case importsDlsym(e):
				if k := knownInterposer(e); k != "" {
					add("dynamic.preload-interposer-known", CatInfo, 0, "", "%s replaces libc entry points by design (%s)", k, strings.Join(boundList(hits, 6), ", "))
				} else {
					add("dynamic.preload-interposer", CatDynamic, 3, techPreload, "shared object redefines %d libc entry point(s) and resolves the originals with dlsym: %s", len(hits), strings.Join(boundList(hits, 8), ", "))
				}
			case e.SyscallStubs > 0:
				// The dlsym-free variant the old rule missed: a preload library
				// that reaches libc through raw syscalls instead of resolving
				// the originals. Known interposers (libc itself included) are
				// named, not scored.
				if k := knownInterposer(e); k != "" {
					add("dynamic.preload-interposer-known", CatInfo, 0, "", "%s replaces libc entry points by design (%s)", k, strings.Join(boundList(hits, 6), ", "))
				} else {
					add("dynamic.preload-interposer-syscall", CatDynamic, 3, techPreload, "shared object redefines %d libc entry point(s) and reaches the kernel through %d raw syscall instruction(s) rather than dlsym: %s", len(hits), e.SyscallStubs, strings.Join(boundList(hits, 8), ", "))
				}
			}
		}
	}

	// ── Imports ──
	real := substantiveImports(e.Imports)
	switch {
	case e.Static:
		add("static.linked", CatInfo, 0, "", "statically linked: no program interpreter or dynamic section; import analytics do not apply")
	case e.Interp != "" && !e.HasDynamic:
		add("format.interp-without-dynamic", CatFormat, 2, "", "program interpreter requested but no dynamic section for it to process")
	case e.Interp != "" && e.ImportCount == 0:
		add("imports.none", CatImports, 2, techDynamicAPI, "dynamically linked image imports nothing through the loader")
	case e.Interp != "" && len(real) > 0 && len(real) <= 8 && allLoaderOnly(real):
		add("imports.loader-only", CatImports, 2, techDynamicAPI, "imports are only the loader stub (%s)", strings.Join(real, ", "))
	case e.Interp != "" && len(real) > 0 && len(real) <= 3:
		w := 1
		if len(hiEnt) > 0 {
			w = 2
		}
		add("imports.minimal", CatImports, w, techDynamicAPI, "only %d substantive import(s): %s", len(real), strings.Join(real, ", "))
	}

	// ── Packer ──
	if pk := e.Packer; pk != nil {
		if pk.Generic {
			add("packer.generic", CatPacker, 3, techPacking, "packed executable profile: %s", strings.Join(pk.Evidence, "; "))
		} else {
			add("packer."+slug(pk.Name), CatPacker, 2, techPacking, "packed with %s (%s)", pk.Name, strings.Join(pk.Evidence, "; "))
		}
	}

	// ── Overlay ──
	if ov := e.Overlay; ov.Size >= minOverlayBytes {
		switch {
		case e.AppImage != 0:
			add("overlay.appimage", CatInfo, 0, "", "AppImage type %d: %d byte filesystem image appended after the runtime is expected", e.AppImage, ov.Size)
		case ov.Size >= minHighOverlay && ov.Entropy > HighEntropy:
			add("overlay.high-entropy", CatOverlay, 2, techEmbeddedPay, "%d bytes appended after the last section at %.2f bits/byte", ov.Size, ov.Entropy)
		default:
			add("overlay.present", CatOverlay, 1, techEmbeddedPay, "%d bytes appended after the last section (%.2f bits/byte)", ov.Size, ov.Entropy)
		}
	}

	// ── Kernel module ──
	if m := e.Module; m != nil {
		add("module.kernel", CatInfo, 0, "", "Linux kernel module %q (vermagic %q, license %q)", m.Name, m.Vermagic, m.License)
		if !m.Signed {
			add("module.unsigned", CatModule, 1, techRootkit, "kernel module carries no appended signature (whether the kernel enforces one is not knowable from the file)")
		} else {
			add("module.signature-unverified", CatInfo, 0, "", "%d byte module signature present; not verified (the kernel keyring is not available to a file scanner)", m.SignatureBytes)
		}
		if !m.InfoPresent || m.Vermagic == "" {
			add("module.info-missing", CatModule, 2, techRootkit, "kernel module without .modinfo vermagic: hand-built, or stripped so modinfo says nothing")
		}
		if m.License != "" && !strings.Contains(m.License, "GPL") && !strings.Contains(m.License, "BSD") && !strings.Contains(m.License, "MIT") && !strings.Contains(m.License, "Dual") {
			add("module.license-proprietary", CatInfo, 0, "", "module license %q taints the kernel; not an anomaly by itself", m.License)
		}
	}

	// ── Format ──
	if e.ProgramTableInvalid != "" && image {
		add("format.program-table-invalid", CatFormat, 2, "", "%s: the kernel cannot load this image as declared", e.ProgramTableInvalid)
	}
	if e.SectionTableInvalid != "" {
		add("format.section-table-invalid", CatFormat, 2, techObfuscated, "%s: the loader ignores it, analysis tools do not", e.SectionTableInvalid)
	}
	if len(truncated) > 0 {
		add("format.truncated", CatFormat, 2, "", "segment(s)/section(s) claim data past the end of the file: %s", strings.Join(boundList(truncated, 8), ", "))
	}
	if e.Type == etCore {
		add("format.core-dump", CatInfo, 0, "", "core dump; structural rules for images do not apply")
	}
	if !image && e.Type != etRel && e.Type != etCore {
		add("format.type-unknown", CatFormat, 2, "", "ELF type %s is neither executable, shared object, relocatable nor core", e.TypeName)
	}

	// ── Content (elf_content.go) ──
	out = append(out, elfContentAnomalies(e)...)
	return out
}

func entryInAnySection(e *ELF) bool {
	for _, s := range e.Sections {
		if s.Alloc() && s.Size > 0 && e.Entry >= s.Addr && e.Entry < s.Addr+s.Size {
			return true
		}
	}
	return false
}

func sectionNamed(e *ELF, name string) *ELFSection {
	if name == "" {
		return nil
	}
	for i := range e.Sections {
		if e.Sections[i].Entry {
			return &e.Sections[i]
		}
	}
	return nil
}

func is64Machine(m uint16) bool {
	switch m {
	case 62, 183, 21, 50, 258: // x86-64, aarch64, powerpc64, ia64, loongarch
		return true
	}
	return false
}

func is32Machine(m uint16) bool {
	switch m {
	case 3, 40, 20, 42: // i386, arm, powerpc, superh
		return true
	}
	return false
}

// interpUnusual reports whether the program interpreter is outside the
// directories system loaders live in, or does not look like a loader.
func interpUnusual(interp string) bool {
	if !strings.HasPrefix(interp, "/") {
		return true
	}
	dir, base := path.Split(path.Clean(interp))
	okDir := false
	for _, d := range systemLoaderDirs {
		if strings.HasSuffix(d, "/") {
			if strings.HasPrefix(dir, d) {
				okDir = true
			}
		} else if dir == d+"/" || strings.HasPrefix(dir, d) && (len(dir) == len(d)+1 || dir[len(d)] == '/' || strings.HasPrefix(dir[len(d):], "64") || strings.HasPrefix(dir[len(d):], "32") || strings.HasPrefix(dir[len(d):], "x32") || strings.HasPrefix(dir[len(d):], "exec")) {
			okDir = true
		}
	}
	if !okDir {
		return true
	}
	lb := strings.ToLower(base)
	return !(strings.HasPrefix(lb, "ld-") || strings.HasPrefix(lb, "ld.") || strings.HasPrefix(lb, "ld64") || strings.HasPrefix(lb, "linker") || strings.HasPrefix(lb, "ld-elf") || strings.HasPrefix(lb, "ld-musl"))
}

// insecureRPaths returns the search-path components a local attacker can
// populate: relative paths (including the empty component, which means the
// current directory) and world-writable trees. $ORIGIN, $LIB and $PLATFORM
// are legitimate relocatable-install idioms.
func insecureRPaths(paths []string) []string {
	var bad []string
	for _, p := range paths {
		switch {
		case p == "" || p == ".":
			bad = append(bad, `"" (current directory)`)
		case strings.HasPrefix(p, "$ORIGIN"), strings.HasPrefix(p, "${ORIGIN}"), strings.HasPrefix(p, "$LIB"), strings.HasPrefix(p, "${LIB}"), strings.HasPrefix(p, "$PLATFORM"), strings.HasPrefix(p, "${PLATFORM}"):
			// Relative to the object's own location: the relocatable-install
			// idiom ($ORIGIN/../lib), safe as long as the install tree is.
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

func neededWithPath(needed []string) []string {
	var out []string
	for _, n := range needed {
		if strings.Contains(n, "/") {
			out = append(out, n)
		}
	}
	return boundList(out, 6)
}

func substantiveImports(imports []string) []string {
	var out []string
	for _, n := range imports {
		if !elfLinkBoilerplate[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func allLoaderOnly(real []string) bool {
	tell := false
	for _, n := range real {
		if !elfLoaderOnlyImports[n] {
			return false
		}
		if elfLoaderTells[n] {
			tell = true
		}
	}
	return tell
}

func interposerHits(e *ELF) []string {
	var hits []string
	seen := map[string]bool{}
	for _, n := range e.Exports {
		if interposerTargets[n] && !seen[n] {
			seen[n] = true
			hits = append(hits, n)
		}
	}
	sort.Strings(hits)
	return hits
}

func importsDlsym(e *ELF) bool {
	for _, n := range e.Imports {
		switch n {
		case "dlsym", "dlvsym", "__libc_dlsym", "__libc_dlvsym":
			return true
		}
	}
	return false
}

func knownInterposer(e *ELF) string {
	name := strings.ToLower(e.SOName)
	if name == "" {
		return ""
	}
	for _, k := range knownInterposers {
		if strings.HasPrefix(name, strings.ToLower(k)) {
			return e.SOName
		}
	}
	return ""
}

func boundList(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	out := append([]string{}, items[:max]...)
	return append(out, fmt.Sprintf("+%d more", len(items)-max))
}

func dedupe(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	return out
}
