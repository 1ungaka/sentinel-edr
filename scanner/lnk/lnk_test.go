package lnk

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// ── synthetic .lnk builder ─────────────────────────────────────────────────────
//
// buildLNK assembles a structurally valid Shell Link from a spec. It constructs
// ONLY shortcut bytes for the detector to read; it never writes, weaponises or
// executes anything. StringData is emitted in ANSI or UTF-16LE per spec.unicode,
// which also sets the IsUnicode LinkFlag.

type lnkSpec struct {
	unicode                                  bool
	hasName, hasRel, hasWD, hasArgs, hasIcon bool
	name, relPath, workingDir, args, iconLoc string
	showCommand                              uint32
	envTarget                                string // adds an ENVIRONMENT_VARIABLE_DATA_BLOCK
	trailing                                 int    // bytes appended after the terminal block
	omitTerminal                             bool
}

func u16b(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func u32b(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func buildLNK(s lnkSpec) []byte {
	var flags uint32
	if s.unicode {
		flags |= flagIsUnicode
	}
	if s.hasName {
		flags |= flagHasName
	}
	if s.hasRel {
		flags |= flagHasRelativePath
	}
	if s.hasWD {
		flags |= flagHasWorkingDir
	}
	if s.hasArgs {
		flags |= flagHasArguments
	}
	if s.hasIcon {
		flags |= flagHasIconLocation
	}

	var buf []byte
	buf = append(buf, u32b(headerSize)...) // HeaderSize 0x4C
	buf = append(buf, linkCLSID[:]...)     // LinkCLSID
	buf = append(buf, u32b(flags)...)      // LinkFlags
	buf = append(buf, u32b(0x20)...)       // FileAttributes (FILE_ATTRIBUTE_ARCHIVE)
	buf = append(buf, make([]byte, 24)...) // CreationTime, AccessTime, WriteTime
	buf = append(buf, u32b(0)...)          // FileSize
	buf = append(buf, u32b(0)...)          // IconIndex
	sc := s.showCommand
	if sc == 0 {
		sc = 1 // SW_SHOWNORMAL
	}
	buf = append(buf, u32b(sc)...)         // ShowCommand
	buf = append(buf, make([]byte, 12)...) // HotKey + Reserved1/2/3 -> header is 76 bytes

	writeStr := func(str string) {
		if s.unicode {
			u := utf16.Encode([]rune(str))
			buf = append(buf, u16b(uint16(len(u)))...)
			for _, c := range u {
				buf = append(buf, u16b(c)...)
			}
			return
		}
		buf = append(buf, u16b(uint16(len(str)))...)
		buf = append(buf, []byte(str)...)
	}
	if s.hasName {
		writeStr(s.name)
	}
	if s.hasRel {
		writeStr(s.relPath)
	}
	if s.hasWD {
		writeStr(s.workingDir)
	}
	if s.hasArgs {
		writeStr(s.args)
	}
	if s.hasIcon {
		writeStr(s.iconLoc)
	}

	if s.envTarget != "" {
		block := make([]byte, envBlockSize)
		binary.LittleEndian.PutUint32(block[0:], uint32(envBlockSize))   // BlockSize
		binary.LittleEndian.PutUint32(block[4:], sigEnvironmentVariable) // BlockSignature
		copy(block[8:8+260], []byte(s.envTarget))                        // TargetAnsi
		for i, c := range utf16.Encode([]rune(s.envTarget)) {            // TargetUnicode
			if 268+2*i+2 > len(block) {
				break
			}
			binary.LittleEndian.PutUint16(block[268+2*i:], c)
		}
		buf = append(buf, block...)
	}

	if !s.omitTerminal {
		buf = append(buf, u32b(0)...) // TerminalBlock (size < 4)
	}
	if s.trailing > 0 {
		buf = append(buf, bytes.Repeat([]byte{0x90}, s.trailing)...)
	}
	return buf
}

func findClass(fs []Finding, class string) (Finding, bool) {
	for _, f := range fs {
		if f.Class == class {
			return f, true
		}
	}
	return Finding{}, false
}

// ── IsLNK ──────────────────────────────────────────────────────────────────────

func TestIsLNK(t *testing.T) {
	valid := buildLNK(lnkSpec{hasName: true, name: "x"})
	if !IsLNK(valid) {
		t.Fatal("valid synthetic .lnk not recognised")
	}
	// Wrong CLSID.
	bad := append([]byte(nil), valid...)
	bad[4] ^= 0xFF
	if IsLNK(bad) {
		t.Fatal("buffer with corrupt CLSID accepted")
	}
	// Wrong HeaderSize.
	bad2 := append([]byte(nil), valid...)
	bad2[0] = 0x4D
	if IsLNK(bad2) {
		t.Fatal("buffer with wrong HeaderSize accepted")
	}
	// Too short.
	if IsLNK(valid[:8]) {
		t.Fatal("8-byte buffer accepted as a Shell Link")
	}
	if IsLNK(nil) {
		t.Fatal("nil accepted as a Shell Link")
	}
}

// ── Analyze table ──────────────────────────────────────────────────────────────

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name         string
		data         []byte
		wantDetected bool
		wantClasses  map[string]string // class -> required technique
		absentClass  []string
		check        func(t *testing.T, r *Result)
	}{
		{
			name: "benign ANSI shortcut",
			data: buildLNK(lnkSpec{
				hasName: true, hasRel: true, hasWD: true, hasArgs: true,
				name: "Quarterly Report", relPath: ".\\notepad.exe",
				workingDir: "C:\\Users\\alice", args: "/A report.txt",
			}),
			wantDetected: false,
			absentClass:  []string{"lnk.command.powershell", "lnk.command.cmd", "lnk.obfuscation.encoded"},
			check: func(t *testing.T, r *Result) {
				if r.Score >= DefaultThreshold {
					t.Fatalf("benign shortcut scored %d (>= threshold %d)", r.Score, DefaultThreshold)
				}
			},
		},
		{
			name: "benign Unicode shortcut",
			data: buildLNK(lnkSpec{
				unicode: true, hasName: true, hasRel: true, hasWD: true,
				name: "Résumé", relPath: ".\\notepad.exe", workingDir: "C:\\docs",
			}),
			wantDetected: false,
		},
		{
			name: "powershell encoded (Unicode)",
			data: buildLNK(lnkSpec{
				unicode: true, hasName: true, hasArgs: true, name: "Invoice",
				args: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
			}),
			wantDetected: true,
			wantClasses: map[string]string{
				"lnk.command.powershell":  techPowerShell,
				"lnk.obfuscation.encoded": techObfuscation,
			},
		},
		{
			name: "mshta with env-var obfuscation (ANSI)",
			data: buildLNK(lnkSpec{
				hasName: true, hasRel: true, hasArgs: true, name: "Statement",
				relPath: "..\\x.hta", args: "mshta.exe %APPDATA%\\x.hta",
			}),
			wantDetected: true,
			wantClasses: map[string]string{
				"lnk.command.lolbin":      techInterp,
				"lnk.obfuscation.env-var": techObfuscation,
				"lnk.target.executable":   techUserExec,
			},
		},
		{
			name: "rundll32 with temp path (Unicode)",
			data: buildLNK(lnkSpec{
				unicode: true, hasName: true, hasArgs: true, name: "Photo",
				args: "rundll32.exe shell32.dll,Control_RunDLL %TEMP%\\p.dll",
			}),
			wantDetected: true,
			wantClasses: map[string]string{
				"lnk.command.lolbin":      techInterp,
				"lnk.obfuscation.env-var": techObfuscation,
			},
		},
		{
			name: "hidden-window cmd shortcut (ANSI)",
			data: buildLNK(lnkSpec{
				hasName: true, hasArgs: true, name: "Setup",
				args: "cmd.exe /c powershell -w hidden -nop calc.exe",
			}),
			wantDetected: true,
			wantClasses: map[string]string{
				"lnk.command.cmd":           techCmd,
				"lnk.evasion.hidden-window": techObfuscation,
			},
		},
		{
			name: "icon lure fronting an interpreter (Unicode)",
			data: buildLNK(lnkSpec{
				unicode: true, hasName: true, hasArgs: true, hasIcon: true, name: "Agenda",
				args:    "powershell -enc QQBBAEEA",
				iconLoc: "%SystemRoot%\\system32\\imageres.dll",
			}),
			wantDetected: true,
			wantClasses: map[string]string{
				"lnk.lure.icon-mismatch": techUserExec,
			},
		},
		{
			name: "environment-variable data block to an exe (ANSI)",
			data: buildLNK(lnkSpec{
				hasName: true, name: "readme",
				envTarget: "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe",
			}),
			wantDetected: false,
			wantClasses: map[string]string{
				"lnk.obfuscation.env-var": techObfuscation,
			},
			check: func(t *testing.T, r *Result) {
				if r.Parsed == nil || len(r.Parsed.ExtraBlocks) == 0 {
					t.Fatalf("ENVIRONMENT_VARIABLE_DATA_BLOCK not reflected in Parsed: %+v", r.Parsed)
				}
			},
		},
		{
			name: "appended trailing payload",
			data: buildLNK(lnkSpec{
				hasName: true, name: "clean", trailing: 4096,
			}),
			wantDetected: false,
			wantClasses: map[string]string{
				"lnk.overlay.trailing": techObfuscation,
			},
			check: func(t *testing.T, r *Result) {
				if r.Parsed == nil || r.Parsed.TrailingBytes != 4096 {
					t.Fatalf("trailing bytes not summarised: %+v", r.Parsed)
				}
			},
		},
		{
			name:         "truncated after a valid header",
			data:         buildLNK(lnkSpec{hasName: true, hasArgs: true, name: "x", args: "powershell -enc AAAA"})[:40],
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r.Score != 0 {
					t.Fatalf("truncated shortcut scored %d, want 0", r.Score)
				}
				if r.Parsed == nil || r.Parsed.Warning == "" {
					t.Fatalf("expected a parse warning on truncation, got %+v", r.Parsed)
				}
			},
		},
		{
			name:         "garbage buffer (not a Shell Link)",
			data:         []byte("MZ\x90\x00 this is not a shortcut at all"),
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
					t.Fatalf("non-LNK buffer produced analysis: %+v", r)
				}
			},
		},
		{
			name:         "empty buffer",
			data:         nil,
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r == nil || r.Score != 0 {
					t.Fatalf("empty buffer: unexpected result %+v", r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(tc.data, Options{})
			if r == nil {
				t.Fatal("Analyze returned nil")
			}
			if got := r.Detected(); got != tc.wantDetected {
				t.Fatalf("Detected()=%v, want %v (score %d, threshold %d, findings %+v)",
					got, tc.wantDetected, r.Score, r.EffectiveThreshold(), r.Findings)
			}
			for class, tech := range tc.wantClasses {
				f, ok := findClass(r.Findings, class)
				if !ok {
					t.Fatalf("missing finding class %q; got %+v", class, r.Findings)
				}
				if f.Technique != tech {
					t.Fatalf("class %q technique=%q, want %q", class, f.Technique, tech)
				}
			}
			for _, class := range tc.absentClass {
				if _, ok := findClass(r.Findings, class); ok {
					t.Fatalf("unexpected finding class %q present; got %+v", class, r.Findings)
				}
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
}

// TestScanFileSkipsLarge confirms ScanFile never errors hard and reports a
// missing file as Skipped rather than panicking.
func TestScanFileMissing(t *testing.T) {
	r := ScanFile("/no/such/shortcut.lnk", Options{})
	if r == nil {
		t.Fatal("ScanFile returned nil")
	}
	if r.Skipped == "" {
		t.Fatalf("expected Skipped for a missing file, got %+v", r)
	}
	if r.Detected() {
		t.Fatal("a skipped scan must not report Detected")
	}
}

// TestClassesCatalog checks the catalog is internally consistent: non-empty,
// unique entries, every technique one of the allowed ATT&CK ids.
func TestClassesCatalog(t *testing.T) {
	allowed := map[string]bool{
		techUserExec: true, techInterp: true, techPowerShell: true,
		techCmd: true, techScriptHost: true, techObfuscation: true,
	}
	cls := Classes()
	if len(cls) == 0 {
		t.Fatal("Classes() is empty")
	}
	seen := map[string]bool{}
	for _, c := range cls {
		key := c.Class + "|" + c.Technique
		if seen[key] {
			t.Fatalf("duplicate catalog entry %q", key)
		}
		seen[key] = true
		if !allowed[c.Technique] {
			t.Fatalf("class %q uses unexpected technique %q", c.Class, c.Technique)
		}
		if c.Weight <= 0 || c.Description == "" {
			t.Fatalf("class %q has no weight/description: %+v", c.Class, c)
		}
	}
}
