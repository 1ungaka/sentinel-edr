package ole

import (
	"bufio"
	"os"
	"sort"
	"testing"
)

// TestMeasureVBAProjects prints the p-code / source size distribution of every
// VBA module in a list of local compound files, which is what stompMinPCode is
// derived from. It is a measurement, not an assertion, and is skipped unless
// OLE_MEASURE_LIST names a file of paths (one per line). The list used for the
// shipped bound was produced by
//
//	find / -xdev -type f \( -iname '*.doc' -o -iname '*.xls' -o -iname '*.ppt' \
//	  -o -iname '*.dot' -o -iname '*.xlt' -o -iname '*.msi' -o -iname '*.vsd' \)
//
// plus every file under /usr/share and /usr/lib that starts with the compound-
// file signature.
func TestMeasureVBAProjects(t *testing.T) {
	list := os.Getenv("OLE_MEASURE_LIST")
	if list == "" {
		t.Skip("OLE_MEASURE_LIST not set")
	}
	fh, err := os.Open(list)
	if err != nil {
		t.Skip(err)
	}
	defer fh.Close()

	files, compound, withVBA, withDir, detected := 0, 0, 0, 0, 0
	var blankPCode, codePCode []int
	classes := map[string]int{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		path := sc.Text()
		if path == "" {
			continue
		}
		files++
		r := ScanFile(path, Options{})
		if r.Skipped != "" || r.Parsed == nil {
			t.Logf("SKIP %s: %s", path, r.Skipped)
			continue
		}
		compound++
		if r.Parsed.HasVBA {
			withVBA++
		}
		if r.Detected() {
			detected++
			t.Logf("DETECTED score=%d %s", r.Score, path)
		}
		for _, fd := range r.Findings {
			classes[fd.Class]++
			if fd.Technique == techStomping {
				t.Logf("STOMP %s %s: %s", fd.Class, path, fd.Evidence)
			}
		}
		modules := 0
		for _, p := range r.Parsed.VBAProjects {
			modules += len(p.Modules)
			t.Logf("PROJECT %s storage=%q version=%d.%d pcode_version=%#x declared=%d parsed=%d warning=%q",
				path, p.Storage, p.VersionMajor, p.VersionMinor, p.PCodeVersion, p.DeclaredModules, p.ModuleCount, p.Warning)
			for _, m := range p.Modules {
				t.Logf("  MODULE %-24q type=%-10s offset=%-7d stream=%-7d pcode=%-7d source=%-7d state=%s",
					m.Name, m.Type, m.TextOffset, m.StreamBytes, m.PCodeBytes, m.SourceBytes, m.SourceState)
				switch m.SourceState {
				case srcBlank:
					blankPCode = append(blankPCode, m.PCodeBytes)
				case srcPresent:
					codePCode = append(codePCode, m.PCodeBytes)
				}
			}
		}
		if modules > 0 {
			withDir++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", list, err)
	}
	sort.Ints(blankPCode)
	sort.Ints(codePCode)
	t.Logf("files=%d compound=%d has_vba=%d with_dir_modules=%d detected=%d", files, compound, withVBA, withDir, detected)
	t.Logf("finding classes: %v", classes)
	t.Logf("p-code bytes, Attribute-only modules (n=%d): %v", len(blankPCode), blankPCode)
	t.Logf("p-code bytes, modules with code (n=%d): %v", len(codePCode), codePCode)
}
