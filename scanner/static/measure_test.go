package static

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const windowsTools = "/usr/share/windows-resources"

// TestMeasureRealBinaries prints the structural score of every PE under the
// Kali Windows tool set. It asserts nothing; run it with -v to retune.
func TestMeasureRealBinaries(t *testing.T) {
	if _, err := os.Stat(windowsTools); err != nil {
		t.Skip("windows-resources not installed")
	}
	var paths []string
	filepath.Walk(windowsTools, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			l := strings.ToLower(p)
			if strings.HasSuffix(l, ".exe") || strings.HasSuffix(l, ".dll") || strings.HasSuffix(l, ".sys") {
				paths = append(paths, p)
			}
		}
		return nil
	})
	sort.Strings(paths)
	for _, p := range paths {
		r := AnalyzeFile(p, Options{Now: fixtureNow()})
		if r.Error != nil || !r.IsPE {
			t.Logf("%-70s not PE / error: %v", strings.TrimPrefix(p, windowsTools+"/"), r.Error)
			continue
		}
		var cls []string
		for _, a := range r.Anomalies {
			if a.Score > 0 {
				cls = append(cls, a.Class)
			}
		}
		sig := "-"
		if r.PE.Authenticode != nil {
			sig = "signed"
			if r.PE.Authenticode.ParseErr != "" {
				sig = "sig-err:" + r.PE.Authenticode.ParseErr
			} else if r.PE.Authenticode.SignerSubject != "" {
				sig = "signed:" + r.PE.Authenticode.SignerSubject
			}
		}
		rich := "no-rich"
		if r.PE.Rich != nil {
			rich = "rich-ok"
			if !r.PE.Rich.ChecksumValid {
				rich = "rich-BAD"
			}
		}
		t.Logf("%-55s score=%2d imports=%4d imphash=%s %s %s %s", strings.TrimPrefix(p, windowsTools+"/"),
			r.Score, r.PE.ImportCount, r.PE.Imphash[:8], rich, sig, strings.Join(cls, ","))
		for _, w := range r.PE.Warnings {
			t.Logf("      warn: %s", w)
		}
	}
}

// elfMeasureRoots are where this machine keeps its ELF population. The test
// prints a score for every ELF it finds; run it with -v to retune.
var elfMeasureRoots = []string{"/usr/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu", "/usr/libexec", "/usr/lib/systemd"}

// TestMeasureRealELF prints the structural score of every ELF under the
// measurement roots. It asserts nothing.
func TestMeasureRealELF(t *testing.T) {
	var paths []string
	for _, root := range elfMeasureRoots {
		filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() && info.Size() < 48<<20 {
				paths = append(paths, p)
			}
			if err == nil && info.IsDir() && p != root && root != "/usr/lib/x86_64-linux-gnu" {
				return nil
			}
			if err == nil && info.IsDir() && p != root {
				return filepath.SkipDir
			}
			return nil
		})
	}
	if len(paths) == 0 {
		t.Skip("no ELF population to measure")
	}
	sort.Strings(paths)
	total, elf, detected := 0, 0, 0
	hist := map[string]int{}
	for _, p := range paths {
		r := AnalyzeFile(p, Options{NoFuzzy: true})
		total++
		if r.Error != nil || !r.IsELF {
			continue
		}
		elf++
		var cls []string
		for _, a := range r.Anomalies {
			if a.Score > 0 {
				cls = append(cls, a.Class)
				hist[a.Class]++
			}
		}
		if r.Detected() {
			detected++
		}
		if r.Score > 0 || len(r.ELF.Warnings) > 0 {
			t.Logf("%-60s score=%2d type=%-4s imports=%4d %s", p, r.Score, r.ELF.TypeName, r.ELF.ImportCount, strings.Join(cls, ","))
			for _, w := range r.ELF.Warnings {
				t.Logf("      warn: %s", w)
			}
		}
	}
	t.Logf("files=%d elf=%d detected=%d", total, elf, detected)
	var keys []string
	for k := range hist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  %-40s %d", k, hist[k])
	}
}

// TestMeasureELFContent is the benign sweep for the content classes
// (elf_content.go). It reads a list of files, one path per line, from the file
// named by CAU_MEASURE_ELF_LIST, analyses every ELF among them and prints how
// many carry each scored class, each content class with the files it fired on,
// each marker group, and the detections. It asserts nothing and is skipped
// when the variable is unset: the population is a whole system's binaries and
// takes minutes to read. The list used for the shipped numbers was every
// regular file starting with the ELF magic under /usr/bin, /usr/sbin, /usr/lib
// and /usr/libexec, hard links counted once.
func TestMeasureELFContent(t *testing.T) {
	list := os.Getenv("CAU_MEASURE_ELF_LIST")
	if list == "" {
		t.Skip("CAU_MEASURE_ELF_LIST not set")
	}
	raw, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	// CAU_MEASURE_ELF_OUT names a file that receives one line per ELF
	// ("path\tscore\tdetected\tclasses") so two builds can be diffed.
	var table *os.File
	if out := os.Getenv("CAU_MEASURE_ELF_OUT"); out != "" {
		f, err := os.Create(out)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		table = f
	}
	files, elf, images, linked, detected, skipped := 0, 0, 0, 0, 0, 0
	classes := map[string]int{}
	markers := map[string]int{}
	stubWeights := map[int]int{}
	contentHits := map[string][]string{}
	for _, p := range strings.Split(string(raw), "\n") {
		if p == "" {
			continue
		}
		files++
		r := AnalyzeFile(p, Options{NoFuzzy: true})
		if r.Skipped != "" {
			skipped++
			continue
		}
		if r.Error != nil || !r.IsELF {
			continue
		}
		elf++
		e := r.ELF
		if e.Type == etExec || e.Type == etDyn {
			images++
		}
		if e.Interp != "" || len(e.Needed) > 0 {
			linked++
			if w, strong, names := directSyscallWeight(e.Content); w > 0 {
				stubWeights[w]++
				if w >= 2 {
					t.Logf("stubs weight=%d strong=%v decoded=%d %s: %s", w, strong, e.Content.DecodedSyscalls, p, strings.Join(names, ","))
				}
			}
		}
		if e.Content != nil {
			for _, m := range e.Content.Markers {
				markers[m]++
			}
		}
		for _, a := range r.Anomalies {
			if a.Score == 0 {
				continue
			}
			classes[a.Class]++
			if strings.HasPrefix(a.Class, "content.") {
				contentHits[a.Class] = append(contentHits[a.Class], p)
				t.Logf("%s: %s (static score %d): %s", a.Class, p, r.Score, a.Detail)
			}
		}
		if r.Detected() {
			detected++
			t.Logf("DETECTED %s score=%d %v", p, r.Score, classesOf(r))
		}
		if table != nil {
			var cls []string
			for _, a := range r.Anomalies {
				if a.Score > 0 {
					cls = append(cls, a.Class)
				}
			}
			sort.Strings(cls)
			fmt.Fprintf(table, "%s\t%d\t%v\t%s\n", p, r.Score, r.Detected(), strings.Join(cls, ","))
		}
	}
	t.Logf("files=%d elf=%d images=%d dynamically-linked=%d skipped(size)=%d detected=%d", files, elf, images, linked, skipped, detected)
	for _, k := range sortedKeys(classes) {
		t.Logf("  class  %-40s %d", k, classes[k])
	}
	for _, k := range sortedKeys(markers) {
		t.Logf("  marker %-40s %d", k, markers[k])
	}
	var ws []int
	for w := range stubWeights {
		ws = append(ws, w)
	}
	sort.Ints(ws)
	for _, w := range ws {
		t.Logf("  direct-syscall weight %d (fires at %d): %d dynamically linked image(s)", w, syscallStubWeight, stubWeights[w])
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
