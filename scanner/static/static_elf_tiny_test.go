package static

import "testing"

func TestTinyLoaderRequiresEverySign(t *testing.T) {
	small := &ELF{Type: etExec, NoSectionHeaders: true, Segments: []ELFSegment{{TypeNum: ptLoad, FileSize: 250}}}
	if !anomalyPresent(elfAnomalies(small), "elf.tiny-loader") {
		t.Fatal("a tiny hand-built ELF must be flagged")
	}
	interp := &ELF{Type: etExec, NoSectionHeaders: true, Interp: "/lib64/ld-linux-x86-64.so.2", Segments: []ELFSegment{{TypeNum: ptLoad, FileSize: 250}}}
	if anomalyPresent(elfAnomalies(interp), "elf.tiny-loader") {
		t.Fatal("an interpreter means the dynamic loader runs it: not a raw stub")
	}
	large := &ELF{Type: etExec, NoSectionHeaders: true, Segments: []ELFSegment{{TypeNum: ptLoad, FileSize: tinyLoaderMax + 1}}}
	if anomalyPresent(elfAnomalies(large), "elf.tiny-loader") {
		t.Fatal("past the size bar this is a stripped binary, not a stub")
	}
}

func anomalyPresent(as []Anomaly, class string) bool {
	for _, a := range as {
		if a.Class == class {
			return true
		}
	}
	return false
}
