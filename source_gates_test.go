package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Build gates over the engine's own source. Three promises the documentation
// makes are checked here against the code, so that each holds because the
// build fails when it stops holding, not because a paragraph says so:
//
//  1. No injection primitives. The engine observes and, when told to,
//     signals or blocks; it never attaches to, writes into or loads code
//     into another process or the kernel.
//  2. Scanning never executes and never writes sample content. The packages
//     that touch untrusted bytes cannot start a process or open a socket,
//     and may write in exactly two places, both of which append to a
//     signature database the operator named.
//  3. Starting another program is rare and deliberate. Every importer of
//     os/exec is listed here with its reason, so a new one is a reviewed
//     decision.
//
// The checks read the syntax tree, not the text: detection content is full of
// strings such as "process_vm_writev" and "ptrace", which are patterns the
// engine looks for, and a text search would trip over exactly the code that
// detects the thing being forbidden.

// sourceFile is one parsed, non-test Go file of the engine.
type sourceFile struct {
	path string // slash-separated, relative to the repository root
	file *ast.File
	fset *token.FileSet
}

// engineSource parses every non-test Go file that ships in the engine. The
// vendored dependencies and the nested cau-kernel repository are not the
// engine's own source.
func engineSource(t *testing.T) []sourceFile {
	t.Helper()
	var out []sourceFile
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "cau-kernel", "testdata", ".git", "debian", "eval-out", "corpus":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			// Another change in progress can leave a file unparseable for a
			// moment; that is the compiler's failure to report, not this gate's.
			t.Logf("skipped unparseable %s: %v", path, perr)
			return nil
		}
		out = append(out, sourceFile{path: filepath.ToSlash(path), file: f, fset: fset})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 100 {
		t.Fatalf("only %d source files found; the gate is not looking at the engine", len(out))
	}
	return out
}

func (s sourceFile) imports(path string) bool {
	for _, imp := range s.file.Imports {
		if strings.Trim(imp.Path.Value, `"`) == path {
			return true
		}
	}
	return false
}

// selectors calls fn for every pkg.Name selector in the file, with the
// function it appears in ("" at package level).
func (s sourceFile) selectors(fn func(pkg, name, inFunc string, pos token.Position)) {
	for _, decl := range s.file.Decls {
		inFunc := ""
		if fd, ok := decl.(*ast.FuncDecl); ok {
			inFunc = fd.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				fn(id.Name, sel.Sel.Name, inFunc, s.fset.Position(sel.Pos()))
			}
			return true
		})
	}
}

// injectionAPI reports an identifier that is a process- or kernel-injection
// primitive in the syscall and x/sys/unix packages.
func injectionAPI(name string) (string, bool) {
	switch {
	case strings.HasPrefix(name, "Ptrace"), name == "SYS_PTRACE", strings.HasPrefix(name, "PTRACE_"):
		return "ptrace attaches to and rewrites another process", true
	case name == "SYS_PROCESS_VM_WRITEV", name == "ProcessVMWritev":
		return "process_vm_writev writes into another process's memory", true
	case name == "SYS_INIT_MODULE", name == "SYS_FINIT_MODULE", name == "InitModule", name == "FinitModule":
		return "init_module loads code into the kernel", true
	case name == "SYS_MEMFD_CREATE", name == "MemfdCreate":
		return "memfd_create is the fileless-staging primitive the engine detects, not one it uses", true
	case name == "SYS_BPF":
		return "raw bpf(2) loads programs into the kernel; enforcement lives in the separate cau-kernel repository", true
	}
	return "", false
}

func TestNoInjectionPrimitives(t *testing.T) {
	for _, src := range engineSource(t) {
		src.selectors(func(pkg, name, _ string, pos token.Position) {
			if pkg != "syscall" && pkg != "unix" {
				return
			}
			if why, bad := injectionAPI(name); bad {
				t.Errorf("%s: %s.%s: %s. The engine ships no injection primitive.", pos, pkg, name, why)
			}
		})
		for _, forbidden := range []string{"plugin"} {
			if src.imports(forbidden) {
				t.Errorf("%s imports %q: the engine does not load code at run time", src.path, forbidden)
			}
		}
	}
}

// The gate must actually recognise what it forbids.
func TestInjectionGateRecognisesPrimitives(t *testing.T) {
	for _, name := range []string{"PtraceAttach", "PtracePokeText", "PtraceSeize", "SYS_PTRACE", "PTRACE_POKEDATA",
		"SYS_PROCESS_VM_WRITEV", "ProcessVMWritev", "SYS_FINIT_MODULE", "MemfdCreate", "SYS_BPF"} {
		if _, bad := injectionAPI(name); !bad {
			t.Errorf("%s should be recognised as an injection primitive", name)
		}
	}
	// What the engine legitimately uses must stay allowed: signals for
	// response, file locks, inotify, prctl hardening, reading memory maps.
	for _, name := range []string{"Kill", "SIGSTOP", "SIGKILL", "Flock", "InotifyInit1", "Prctl", "Stat_t", "O_NOFOLLOW",
		"SYS_PROCESS_VM_READV", "Setrlimit"} {
		if why, bad := injectionAPI(name); bad {
			t.Errorf("%s must not be treated as an injection primitive (%s)", name, why)
		}
	}
}

// samplePackages are the trees that parse untrusted sample bytes.
var samplePackages = []string{"scanner/", "internal/peeler/"}

func touchesSamples(path string) bool {
	for _, p := range samplePackages {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// sampleWriteAllowlist is every place sample-handling code may open a file
// for writing: "file:function". Both append one line to a signature database
// whose path the operator passed; neither writes sample content.
var sampleWriteAllowlist = map[string]string{
	"scanner/scanner.go:AddSignature":           "appends a hash signature to the database (cau add-hash)",
	"scanner/static/fuzzy.go:AddFuzzySignature": "appends a fuzzy signature to the database (cau add-fuzzy)",
}

var writeCalls = map[string]bool{
	"Create": true, "OpenFile": true, "WriteFile": true, "Remove": true, "RemoveAll": true, "Rename": true,
	"Mkdir": true, "MkdirAll": true, "MkdirTemp": true, "CreateTemp": true, "Truncate": true, "Chmod": true,
	"Chown": true, "Chtimes": true, "Symlink": true, "Link": true,
}

func TestScanningNeverExecutesOrWritesSamples(t *testing.T) {
	checked := 0
	used := map[string]bool{}
	for _, src := range engineSource(t) {
		if !touchesSamples(src.path) {
			continue
		}
		checked++
		for _, forbidden := range []string{"os/exec", "net", "net/http", "plugin"} {
			if src.imports(forbidden) {
				t.Errorf("%s imports %q: code that parses samples cannot start a process or open a socket", src.path, forbidden)
			}
		}
		src.selectors(func(pkg, name, inFunc string, pos token.Position) {
			switch {
			case (pkg == "syscall" || pkg == "unix") && (name == "Exec" || name == "ForkExec" || name == "StartProcess"):
				t.Errorf("%s: %s.%s starts a process from sample-handling code", pos, pkg, name)
			case pkg == "os" && name == "StartProcess":
				t.Errorf("%s: os.StartProcess starts a process from sample-handling code", pos)
			case pkg == "os" && writeCalls[name]:
				key := src.path + ":" + inFunc
				if _, ok := sampleWriteAllowlist[key]; ok {
					used[key] = true
					return
				}
				t.Errorf("%s: os.%s in %s can modify the filesystem from sample-handling code. Scanning is read-only; if this write is to an operator-named database, add %q to sampleWriteAllowlist with the reason.",
					pos, name, inFunc, key)
			}
		})
	}
	if checked < 40 {
		t.Fatalf("only %d sample-handling files checked; the gate is not looking at the scanner", checked)
	}
	// An allowlist entry that no longer matches anything is a stale
	// exemption waiting to cover something else.
	for key := range sampleWriteAllowlist {
		if !used[key] {
			t.Errorf("sampleWriteAllowlist entry %q matches no write call any more; remove it", key)
		}
	}
}

// execAllowlist is every file that may import os/exec, with what it runs.
var execAllowlist = map[string]string{
	"cmd_ps.go":                     "runs the operator-named cau-kernel binary to block a confirmed process's executable (--kernel-bin)",
	"internal/netblock/netblock.go": "runs nft or iptables to add and remove the operator-requested egress blocks",
}

func TestProcessExecutionIsAllowlisted(t *testing.T) {
	var importers []string
	for _, src := range engineSource(t) {
		if src.imports("os/exec") {
			importers = append(importers, src.path)
		}
	}
	sort.Strings(importers)
	seen := map[string]bool{}
	for _, path := range importers {
		seen[path] = true
		if _, ok := execAllowlist[path]; !ok {
			t.Errorf("%s imports os/exec and is not in execAllowlist. Starting another program from the engine is a reviewed decision: add the file with what it runs and why, or do the work in-process.", path)
		}
	}
	for path := range execAllowlist {
		if !seen[path] {
			t.Errorf("execAllowlist names %s, which no longer imports os/exec; remove the entry", path)
		}
	}
}
