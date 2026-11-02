package iso

import (
	"strings"
	"testing"
	"unicode/utf16"
)

// ── synthetic ISO 9660 builder ─────────────────────────────────────────────────
//
// buildISO assembles a MINIMAL, structurally valid ISO 9660 image from a spec:
// a 16-sector system area, a Primary Volume Descriptor at sector 16 (optionally
// a Joliet Supplementary Volume Descriptor), a Volume Descriptor Set Terminator,
// and one or more directory extents holding the records for the specified
// entries. It constructs ONLY container bytes for the detector to enumerate; it
// never writes real file content, creates a mountable image, or executes
// anything. Fields are written both-endian with 2048-byte sectors, per the
// public format.

type isoFile struct {
	name     string // e.g. "invoice.lnk" (a ";1" version is added for files)
	isDir    bool
	hidden   bool
	size     uint32
	children []isoFile // one level of nesting (for a directory entry)
}

type isoSpec struct {
	volID  string
	joliet bool
	files  []isoFile
	pad    int // extra zero sectors appended to grow the overall image size
}

func putBoth16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func putBoth32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func ucs2be(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i] = byte(c >> 8)
		b[2*i+1] = byte(c)
	}
	return b
}

func fileID(name string, joliet bool) []byte {
	if joliet {
		return ucs2be(name + ";1")
	}
	return []byte(strings.ToUpper(name) + ";1")
}

func dirID(name string, joliet bool) []byte {
	if joliet {
		return ucs2be(name)
	}
	return []byte(strings.ToUpper(name))
}

// buildDirRecord lays out one Directory Record.
func buildDirRecord(id []byte, isDir, hidden bool, extentLBA, dataLen uint32) []byte {
	fidLen := len(id)
	pad := 0
	if fidLen%2 == 0 {
		pad = 1 // keep the record length even
	}
	recLen := 33 + fidLen + pad
	rec := make([]byte, recLen)
	rec[0] = byte(recLen)
	putBoth32(rec[2:], extentLBA) // Location of Extent
	putBoth32(rec[10:], dataLen)  // Data Length
	var flags byte
	if hidden {
		flags |= flagHidden
	}
	if isDir {
		flags |= flagDir
	}
	rec[25] = flags
	putBoth16(rec[28:], 1) // Volume Sequence Number
	rec[32] = byte(fidLen)
	copy(rec[33:], id)
	return rec
}

// buildDirExtent builds a one-sector directory extent: the "." and ".." records
// followed by the supplied child records.
func buildDirExtent(selfLBA, parentLBA uint32, childRecs [][]byte) []byte {
	sec := make([]byte, sectorSize)
	pos := 0
	place := func(r []byte) {
		if pos+len(r) > sectorSize {
			return
		}
		copy(sec[pos:], r)
		pos += len(r)
	}
	place(buildDirRecord([]byte{0x00}, true, false, selfLBA, sectorSize))   // "."
	place(buildDirRecord([]byte{0x01}, true, false, parentLBA, sectorSize)) // ".."
	for _, r := range childRecs {
		place(r)
	}
	return sec
}

func buildISO(spec isoSpec) []byte {
	// Sector layout.
	pvdLBA := vdSetLBA // 16
	var svdLBA, vdstLBA, rootLBA, firstSubLBA int
	if spec.joliet {
		svdLBA, vdstLBA, rootLBA, firstSubLBA = 17, 18, 19, 20
	} else {
		vdstLBA, rootLBA, firstSubLBA = 17, 18, 19
	}

	// Assign a dedicated extent to each root-level directory entry.
	numDirs := 0
	for _, f := range spec.files {
		if f.isDir {
			numDirs++
		}
	}

	totalSectors := rootLBA + 1 + numDirs + spec.pad
	data := make([]byte, totalSectors*sectorSize)

	fileExtent := uint32(rootLBA) // dummy; the detector never reads file extents

	// Build the root directory records, assigning subdir extents as we go.
	var rootRecs [][]byte
	type pendingDir struct {
		lba      int
		children []isoFile
	}
	var pending []pendingDir
	nextSub := firstSubLBA
	for _, f := range spec.files {
		if f.isDir {
			lba := nextSub
			nextSub++
			rootRecs = append(rootRecs, buildDirRecord(dirID(f.name, spec.joliet), true, f.hidden, uint32(lba), sectorSize))
			pending = append(pending, pendingDir{lba: lba, children: f.children})
		} else {
			rootRecs = append(rootRecs, buildDirRecord(fileID(f.name, spec.joliet), false, f.hidden, fileExtent, f.size))
		}
	}

	// Root directory extent.
	copy(data[rootLBA*sectorSize:], buildDirExtent(uint32(rootLBA), uint32(rootLBA), rootRecs))

	// Subdirectory extents.
	for _, pd := range pending {
		var recs [][]byte
		for _, c := range pd.children {
			if c.isDir {
				continue // tests only nest one level
			}
			recs = append(recs, buildDirRecord(fileID(c.name, spec.joliet), false, c.hidden, fileExtent, c.size))
		}
		copy(data[pd.lba*sectorSize:], buildDirExtent(uint32(pd.lba), uint32(rootLBA), recs))
	}

	// Primary Volume Descriptor.
	pvd := make([]byte, sectorSize)
	pvd[0] = vdTypePrimary
	copy(pvd[1:6], stdIdentifier)
	pvd[6] = 1
	vid := make([]byte, 32)
	for i := range vid {
		vid[i] = ' '
	}
	copy(vid, spec.volID)
	copy(pvd[volumeIDOffset:], vid)
	putBoth32(pvd[80:], uint32(totalSectors)) // Volume Space Size
	putBoth16(pvd[120:], 1)                   // Volume Set Size
	putBoth16(pvd[124:], 1)                   // Volume Sequence Number
	putBoth16(pvd[128:], sectorSize)          // Logical Block Size
	copy(pvd[rootRecOffset:], buildDirRecord([]byte{0x00}, true, false, uint32(rootLBA), sectorSize))
	copy(data[pvdLBA*sectorSize:], pvd)

	// Joliet Supplementary Volume Descriptor.
	if spec.joliet {
		svd := make([]byte, sectorSize)
		svd[0] = vdTypeSupplementary
		copy(svd[1:6], stdIdentifier)
		svd[6] = 1
		svd[escapeSeqOffset] = 0x25 // "%/E" — UCS-2 level 3
		svd[escapeSeqOffset+1] = 0x2F
		svd[escapeSeqOffset+2] = 0x45
		putBoth16(svd[128:], sectorSize)
		copy(svd[rootRecOffset:], buildDirRecord([]byte{0x00}, true, false, uint32(rootLBA), sectorSize))
		copy(data[svdLBA*sectorSize:], svd)
	}

	// Volume Descriptor Set Terminator.
	vdst := make([]byte, sectorSize)
	vdst[0] = vdTypeTerminator
	copy(vdst[1:6], stdIdentifier)
	vdst[6] = 1
	copy(data[vdstLBA*sectorSize:], vdst)

	return data
}

func findClass(fs []Finding, class string) (Finding, bool) {
	for _, f := range fs {
		if f.Class == class {
			return f, true
		}
	}
	return Finding{}, false
}

// ── IsISO ──────────────────────────────────────────────────────────────────────

func TestIsISO(t *testing.T) {
	valid := buildISO(isoSpec{volID: "DATA", files: []isoFile{{name: "readme.txt", size: 10}}})
	if !IsISO(valid) {
		t.Fatal("valid synthetic ISO not recognised")
	}
	// The type byte at 0x8000 may differ; CD001 at 0x8001 is what matters.
	altered := append([]byte(nil), valid...)
	altered[vdSetOffset] = 0xEE
	if !IsISO(altered) {
		t.Fatal("ISO with a non-standard leading type byte should still be recognised")
	}
	if IsISO([]byte("this is not an ISO image at all")) {
		t.Fatal("a short non-ISO buffer was accepted")
	}
	if IsISO(nil) {
		t.Fatal("nil accepted as an ISO")
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
			name:         "non-ISO buffer",
			data:         []byte("MZ\x90\x00 definitely not a disk image"),
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
					t.Fatalf("non-ISO buffer produced analysis: %+v", r)
				}
			},
		},
		{
			name: "benign data ISO with documents",
			data: buildISO(isoSpec{volID: "REPORTS", files: []isoFile{
				{name: "readme.txt", size: 2048},
				{name: "report.pdf", size: 4096},
			}}),
			wantDetected: false,
			absentClass:  []string{"iso.payload.lnk", "iso.payload.executable", "iso.lure.lnk-and-payload"},
			check: func(t *testing.T, r *Result) {
				if r.Score != 0 {
					t.Fatalf("benign ISO scored %d, want 0", r.Score)
				}
				if r.Parsed == nil || r.Parsed.Files != 2 || r.Parsed.Dirs != 0 {
					t.Fatalf("unexpected parsed summary: %+v", r.Parsed)
				}
				if r.Parsed.VolumeID != "REPORTS" {
					t.Fatalf("volume id = %q, want REPORTS", r.Parsed.VolumeID)
				}
			},
		},
		{
			name: "benign ISO with a subdirectory",
			data: buildISO(isoSpec{volID: "DOCS", files: []isoFile{
				{name: "readme.txt", size: 1024},
				{name: "manuals", isDir: true, children: []isoFile{
					{name: "guide.pdf", size: 8192},
				}},
			}}),
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r.Parsed == nil || r.Parsed.Files != 2 || r.Parsed.Dirs != 1 {
					t.Fatalf("subdirectory not enumerated: %+v", r.Parsed)
				}
			},
		},
		{
			name: "malicious ISO: invoice.lnk + hidden payload.exe",
			data: buildISO(isoSpec{volID: "INVOICE", files: []isoFile{
				{name: "invoice.lnk", size: 1500},
				{name: "payload.exe", hidden: true, size: 40000},
			}}),
			wantDetected: true,
			wantClasses: map[string]string{
				"iso.payload.lnk":            techUserExec,
				"iso.payload.executable":     techUserExec,
				"iso.evasion.hidden-payload": techHideArtifacts,
				"iso.lure.lnk-and-payload":   techUserExec,
				"iso.lure.small-image":       techUserExec,
			},
			check: func(t *testing.T, r *Result) {
				if r.Score < DefaultThreshold {
					t.Fatalf("malicious ISO scored %d (< threshold %d)", r.Score, DefaultThreshold)
				}
			},
		},
		{
			name: "lnk + payload, not hidden, not small — just crosses",
			data: buildISO(isoSpec{volID: "SETUP", pad: 6000, files: []isoFile{
				{name: "open-me.lnk", size: 1500},
				{name: "run.exe", size: 6 << 20},
			}}),
			wantDetected: true,
			wantClasses: map[string]string{
				"iso.lure.lnk-and-payload": techUserExec,
			},
			absentClass: []string{"iso.evasion.hidden-payload", "iso.lure.small-image"},
			check: func(t *testing.T, r *Result) {
				if r.Score != 8 {
					t.Fatalf("lnk+payload (not hidden, not small) scored %d, want exactly 8", r.Score)
				}
			},
		},
		{
			name: "hidden directory holding the payload",
			data: buildISO(isoSpec{volID: "SHIP", files: []isoFile{
				{name: "open.lnk", size: 1200},
				{name: "system", isDir: true, hidden: true, children: []isoFile{
					{name: "stage2.dll", size: 20000}, // not individually hidden
				}},
			}}),
			wantDetected: true,
			wantClasses: map[string]string{
				"iso.evasion.hidden-payload": techHideArtifacts,
				"iso.lure.lnk-and-payload":   techUserExec,
			},
		},
		{
			name: "malicious Joliet ISO",
			data: buildISO(isoSpec{volID: "JOLIET", joliet: true, files: []isoFile{
				{name: "Quarterly Invoice.lnk", size: 1500},
				{name: "Update Installer.exe", hidden: true, size: 30000},
			}}),
			wantDetected: true,
			wantClasses: map[string]string{
				"iso.lure.lnk-and-payload":   techUserExec,
				"iso.evasion.hidden-payload": techHideArtifacts,
			},
			check: func(t *testing.T, r *Result) {
				if r.Parsed == nil || !r.Parsed.HasJoliet {
					t.Fatalf("Joliet not detected: %+v", r.Parsed)
				}
				if r.Parsed.Files != 2 {
					t.Fatalf("Joliet names not enumerated: %+v", r.Parsed)
				}
			},
		},
		{
			name: "lone autorun.inf stays below threshold",
			data: buildISO(isoSpec{volID: "MEDIA", files: []isoFile{
				{name: "autorun.inf", size: 64},
				{name: "readme.txt", size: 512},
			}}),
			wantDetected: false,
			wantClasses: map[string]string{
				"iso.autorun.inf": techRemovableMedia,
			},
			check: func(t *testing.T, r *Result) {
				if r.Score != weightAutorun {
					t.Fatalf("lone autorun.inf scored %d, want %d", r.Score, weightAutorun)
				}
			},
		},
		{
			name: "software ISO full of executables does not cross",
			data: buildISO(isoSpec{volID: "APP", files: []isoFile{
				{name: "setup.exe", size: 2 << 20},
				{name: "app.dll", size: 1 << 20},
				{name: "autorun.inf", size: 64},
			}}),
			wantDetected: false,
			absentClass:  []string{"iso.payload.lnk", "iso.lure.lnk-and-payload"},
			check: func(t *testing.T, r *Result) {
				// autorun(4) + executable(2) = 6, below 8.
				if r.Score != weightAutorun+weightExecutable {
					t.Fatalf("software ISO scored %d, want %d", r.Score, weightAutorun+weightExecutable)
				}
			},
		},
		{
			name:         "truncated image (header only)",
			data:         buildISO(isoSpec{volID: "CUT", files: []isoFile{{name: "x.txt", size: 10}}})[:vdSetOffset+200],
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r == nil {
					t.Fatal("Analyze returned nil for a truncated image")
				}
				if r.Parsed == nil || r.Parsed.Warning == "" {
					t.Fatalf("expected a parse warning on truncation, got %+v", r.Parsed)
				}
				if r.Score != 0 {
					t.Fatalf("truncated image scored %d, want 0", r.Score)
				}
			},
		},
		{
			name: "garbage descriptor (CD001 then truncated)",
			data: func() []byte {
				b := make([]byte, vdSetOffset+10)
				b[vdSetOffset] = vdTypePrimary
				copy(b[vdSetOffset+1:], stdIdentifier)
				return b
			}(),
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r == nil || r.Parsed == nil || r.Parsed.Warning == "" {
					t.Fatalf("expected a warning for a truncated descriptor, got %+v", r)
				}
				if r.Score != 0 {
					t.Fatalf("garbage descriptor scored %d, want 0", r.Score)
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
			sum := 0
			for _, f := range r.Findings {
				sum += f.Score
			}
			if sum != r.Score {
				t.Fatalf("score %d != sum of finding weights %d: %+v", r.Score, sum, r.Findings)
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

// TestScanFileMissing confirms ScanFile reports a missing file as Skipped rather
// than panicking or returning an error.
func TestScanFileMissing(t *testing.T) {
	r := ScanFile("/no/such/image.iso", Options{})
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
// unique entries, every technique one of the allowed ATT&CK ids, and each class
// the detector can emit is present.
func TestClassesCatalog(t *testing.T) {
	allowed := map[string]bool{
		techRemovableMedia: true, techUserExec: true, techHideArtifacts: true,
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
		if c.Novel != "" {
			t.Fatalf("class %q has a Novel id; all ISO classes map to ATT&CK", c.Class)
		}
	}
}
