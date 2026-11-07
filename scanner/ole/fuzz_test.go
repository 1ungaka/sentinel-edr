package ole

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// FuzzAnalyze drives the CFB parser, the MS-OVBA decompressor and the detector
// with mutated input. The parser reads untrusted, attacker-controlled values
// (sector/mini-sector shifts, FAT / MiniFAT / DIFAT chains, directory entry
// sizes and start sectors, and CompressedChunk headers) through bounds-checked
// accessors with visited-set cycle detection and hard step caps. The invariant
// is that Analyze never panics and always returns a non-nil result, and that the
// reported score always equals the sum of the finding weights — however
// truncated or adversarial the bytes are.
//
// Seeds cover an empty buffer, a valid synthetic compound file, a file with a
// cyclic FAT chain, a directory entry declaring an enormous stream size, a
// truncated header, a raw CompressedContainer with adversarial token headers,
// and plain non-OLE bytes.
func FuzzAnalyze(f *testing.F) {
	valid := buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", content: []byte("not a container")},
		oleEntry{name: "Module1", content: moduleStream(
			"Sub AutoOpen()\r\n    Shell \"powershell -enc ZQBjAGgA\"\r\nEnd Sub\r\n")},
	)

	// A valid file whose first FAT entry points at its own sector (a 1-cycle).
	cyclic := append([]byte(nil), valid...)
	firstFatSector := binary.LittleEndian.Uint32(cyclic[76:]) // DIFAT[0]
	if off := (int(firstFatSector) + 1) * 512; off+4 <= len(cyclic) {
		binary.LittleEndian.PutUint32(cyclic[off:], 0) // sector 0 -> sector 0
	}

	// A valid file whose first provided stream declares a 4 GiB+ size.
	hugeSize := buildCFB(oleEntry{name: "Module1", content: moduleStream("x")})
	dirStart := binary.LittleEndian.Uint32(hugeSize[48:])
	if base := (int(dirStart)+1)*512 + 128; base+128 <= len(hugeSize) { // entry index 1
		binary.LittleEndian.PutUint32(hugeSize[base+120:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(hugeSize[base+124:], 0x000000FF)
	}

	// A CompressedContainer with a valid chunk signature but adversarial tokens:
	// a FlagByte of all copy tokens, the first of which sits at the chunk start
	// (an impossible back-reference) — carried inside a module stream.
	adv := []byte{0x01}
	adv = append(adv, u16(uint16(0xB000)|uint16(20))...) // sig=0b011, flag=compressed
	adv = append(adv, 0xFF)                              // FlagByte: 8 copy tokens
	adv = append(adv, 0xFF, 0xFF, 0x00, 0x10, 0xFF, 0x7F, 0x01, 0x80, 0x55, 0xAA)
	advFile := buildCFB(oleEntry{name: "Module1", content: adv})

	// VBA projects with a parseable dir stream: a consistent module, one whose
	// TextOffset points past its stream, one with an Attribute-only source over
	// an opaque p-code stand-in, and a file with two same-named module streams.
	consistent := vbaDoc(vbaProjectStream(0x00B2, "Tidy"),
		[]dirMod{{name: "Module1", offset: 3000}},
		map[string][]byte{"Module1": append(pcodeRegion(3000), compressVBA([]byte(benignSrc))...)})
	beyond := vbaDoc(vbaProjectStream(0x00B2, "AutoOpen"),
		[]dirMod{{name: "Module1", offset: 6000}},
		map[string][]byte{"Module1": pcodeRegion(5000, []byte("WScript.Shell"))})
	blanked := vbaDoc(nil,
		[]dirMod{{name: "ThisDocument", offset: 3000, doc: true}, {name: "Gone", offset: 1}},
		map[string][]byte{"ThisDocument": append(pcodeRegion(3000, utf16le("powershell")), compressVBA([]byte(attrOnly))...)})
	twins := buildCFB(
		oleEntry{name: "Decoy", storage: true},
		oleEntry{name: "Module1", in: "Decoy", content: moduleStream("x = 1")},
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", in: "VBA", content: dirStream(dirMod{name: "Module1", offset: 3000})},
		oleEntry{name: "Module1", in: "VBA", content: pcodeRegion(3000)},
	)

	seeds := [][]byte{
		{},
		consistent,
		beyond,
		blanked,
		twins,
		twins[:len(twins)-700],
		[]byte("not a compound file"),
		valid,
		valid[:len(valid)/2],
		valid[:600], // past the header, into the (now missing) sectors
		valid[:8],   // signature only
		cyclic,
		hugeSize,
		advFile,
		compressVBA([]byte("Sub Document_Open(): Shell \"cmd\": End Sub")), // raw container (not OLE)
		append(append([]byte(nil), oleSignature[:]...), make([]byte, 600)...),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		orig := append([]byte(nil), data...)
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		// Detectors share the input slice: it must come back untouched.
		if !bytes.Equal(orig, data) {
			t.Fatal("Analyze wrote to its input")
		}
		if !IsOLE(data) {
			if r.Score != 0 || len(r.Findings) != 0 {
				t.Fatalf("non-OLE buffer produced findings: %+v", r)
			}
			return
		}
		sum := 0
		for _, fnd := range r.Findings {
			sum += fnd.Score
		}
		if sum != r.Score {
			t.Fatalf("score %d does not match finding sum %d: %+v", r.Score, sum, r.Findings)
		}

		// The dir-record pass stays inside its bounds, and each stomping class
		// scores at most once however many modules a file declares.
		if r.Parsed != nil {
			if len(r.Parsed.VBAProjects) > maxVBAProjects {
				t.Fatalf("%d projects reported, cap %d", len(r.Parsed.VBAProjects), maxVBAProjects)
			}
			for _, p := range r.Parsed.VBAProjects {
				if len(p.Modules) > maxModulesReported || p.ModuleCount > maxDirModules {
					t.Fatalf("module bounds exceeded: listed %d, parsed %d", len(p.Modules), p.ModuleCount)
				}
				for _, m := range p.Modules {
					if m.PCodeBytes < 0 || m.PCodeBytes > m.StreamBytes || m.StreamBytes > maxStreamBytes {
						t.Fatalf("module sizes inconsistent: %+v", m)
					}
					if len(m.Name) > 2*maxVBANameBytes || len(m.Stream) > 2*maxVBANameBytes {
						t.Fatalf("module name over the cap: %d / %d bytes", len(m.Name), len(m.Stream))
					}
				}
			}
		}
		seen := map[string]bool{}
		for _, fnd := range r.Findings {
			if fnd.Technique != techStomping {
				continue
			}
			if seen[fnd.Class] {
				t.Fatalf("stomping class %q raised twice", fnd.Class)
			}
			seen[fnd.Class] = true
		}
	})
}

// FuzzParseVBADir feeds the dir-stream record walker DECOMPRESSED record
// streams directly (FuzzAnalyze only reaches it through a compound file and a
// CompressedContainer, which a mutator rarely keeps intact). Every Id, Size and
// name length is attacker-controlled. The invariant: never panic, never keep
// more than maxDirModules modules, never walk more than maxDirRecords records,
// never keep a name past the cap, and never report both "terminated" and
// "truncated by an overrunning record" for input that fits the size cap.
func FuzzParseVBADir(f *testing.F) {
	good := dirRecords(
		dirMod{name: "ThisDocument", offset: 813, doc: true},
		dirMod{name: "Module1", stream: "Stream1", offset: 4343},
	)
	f.Add([]byte{})
	f.Add(good)
	f.Add(good[:len(good)/2])
	f.Add(good[:7])
	f.Add(dirRecords(dirMod{name: "M", noOffset: true, mbcsOnly: true}))
	f.Add(append(append(u16(recModuleOffset), u32(0xFFFFFFFF)...), 1, 2, 3, 4))       // size overruns
	f.Add(append(u16(recProjectVersion), u32(4)...))                                  // version cut short
	f.Add(bytes.Repeat(rec(recModuleName, []byte("A")), 64))                          // modules, no terminators
	f.Add(rec(recModuleStreamNameU, utf16le(strings.Repeat("\u202e", 300))))          // long non-ASCII name
	f.Add(append(rec(recDirTerminator, nil), rec(recModuleName, []byte("after"))...)) // records after the end

	f.Fuzz(func(t *testing.T, data []byte) {
		orig := append([]byte(nil), data...)
		d := parseVBADir(data)
		if !bytes.Equal(orig, data) {
			t.Fatal("parseVBADir wrote to its input")
		}
		if len(d.modules) > maxDirModules {
			t.Fatalf("%d modules kept, cap %d", len(d.modules), maxDirModules)
		}
		if d.records > maxDirRecords || d.records > len(data)/6 {
			t.Fatalf("%d records walked over %d bytes (cap %d)", d.records, len(data), maxDirRecords)
		}
		if d.declared < -1 || d.declared > 0xFFFF {
			t.Fatalf("declared module count %d out of range", d.declared)
		}
		for _, m := range d.modules {
			// A UTF-16 unit is at most three UTF-8 bytes; the cap is on input bytes.
			if len(m.name) > 2*maxVBANameBytes || len(m.streamName) > 2*maxVBANameBytes {
				t.Fatalf("name over the cap: %d / %d bytes", len(m.name), len(m.streamName))
			}
			if m.moduleType != 0 && m.moduleType != recModuleTypeProc && m.moduleType != recModuleTypeDoc {
				t.Fatalf("module type %#x", m.moduleType)
			}
		}
		if len(data) <= maxDirDecompressed && d.terminated && d.truncated && len(d.modules) < maxDirModules {
			t.Fatalf("terminated and truncated at once: %+v", d)
		}
	})
}
