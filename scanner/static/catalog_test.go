package static

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestClassCatalogMatchesSource reads the analysis sources and checks that
// every class literal they emit is in the catalog with the same category,
// technique and (maximum) weight, and that the catalog lists nothing the
// code cannot emit. The catalog is what the coverage matrix publishes, so
// drift here would be a false claim.
func TestClassCatalogMatchesSource(t *testing.T) {
	catalog := map[string]Class{}
	for _, c := range classCatalog {
		if _, dup := catalog[c.Class]; dup {
			t.Fatalf("catalog lists %q twice", c.Class)
		}
		catalog[c.Class] = c
	}

	consts := map[string]string{
		"CatSections": CatSections, "CatEntry": CatEntry, "CatHeaders": CatHeaders, "CatImports": CatImports,
		"CatPacker": CatPacker, "CatSignature": CatSignature, "CatOverlay": CatOverlay, "CatFormat": CatFormat,
		"CatFuzzy": CatFuzzy, "CatInfo": CatInfo, "CatDynamic": CatDynamic, "CatModule": CatModule,
		"techObfuscated": techObfuscated, "techPacking": techPacking, "techDynamicAPI": techDynamicAPI,
		"techEmbeddedPay": techEmbeddedPay, "techTimestomp": techTimestomp, "techInvalidSig": techInvalidSig,
		"techMasquerade": techMasquerade, "techCodeSigning": techCodeSigning, "techHijackFlow": techHijackFlow,
		"techPreload": techPreload, "techRootkit": techRootkit, `""`: "",
		"CatPersist": CatPersist, "techNativeAPI": techNativeAPI, "techSSHKeys": techSSHKeys, "techCron": techCron,
		"techSystemdUnit": techSystemdUnit, "techAutostart": techAutostart,
	}

	// add("class", Cat, score, tech, ...) and Anomaly{Class: "class", Category: Cat, Score: n, ...}.
	addRe := regexp.MustCompile(`add\("([a-z.\-]+)"(?:\+slug\([^)]*\))?,\s*(Cat\w+),\s*(\w+),\s*(tech\w+|""),`)
	litRe := regexp.MustCompile(`Anomaly\{Class:\s*"([a-z.\-]+)",\s*Category:\s*(Cat\w+),\s*Score:\s*(\w+)`)

	seen := map[string]bool{}
	check := func(file, class, cat, weight, tech string) {
		if strings.HasPrefix(class, "packer.") && class != "packer.generic" && class != "packer.installer-stub" {
			class = "packer.*"
		}
		seen[class] = true
		c, ok := catalog[class]
		if !ok {
			t.Errorf("%s emits %q, which is not in the catalog", file, class)
			return
		}
		if want := consts[cat]; c.Category != want {
			t.Errorf("%s: %q category %q, catalog says %q", file, class, want, c.Category)
		}
		if tech != "" {
			if want, ok := consts[tech]; ok && c.Technique != want {
				t.Errorf("%s: %q technique %q, catalog says %q", file, class, want, c.Technique)
			}
		}
		if n, err := strconv.Atoi(weight); err == nil && n > c.Weight {
			t.Errorf("%s: %q scores %d, catalog weight is %d", file, class, n, c.Weight)
		}
	}
	for _, file := range []string{"anomaly.go", "elf_anomaly.go", "elf_content.go", "macho_anomaly.go", "static.go", "signerblock.go"} {
		src, err := os.ReadFile(filepath.Join(".", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range addRe.FindAllStringSubmatch(string(src), -1) {
			check(file, m[1], m[2], m[3], m[4])
		}
		for _, m := range litRe.FindAllStringSubmatch(string(src), -1) {
			check(file, m[1], m[2], m[3], "")
		}
	}
	// Variable-weight classes (imports.minimal) use a local; the regexp
	// still captured the class, which is what matters.
	for class := range catalog {
		if !seen[class] {
			t.Errorf("catalog lists %q but no analysis source emits it", class)
		}
	}
}

func TestClassesSortedAndComplete(t *testing.T) {
	cs := Classes()
	for i := 1; i < len(cs); i++ {
		if cs[i-1].Class >= cs[i].Class {
			t.Fatalf("Classes() not sorted at %q / %q", cs[i-1].Class, cs[i].Class)
		}
	}
	for _, c := range cs {
		if c.Description == "" || c.Category == "" || len(c.Formats) == 0 {
			t.Errorf("%q is missing description, category or formats", c.Class)
		}
		if c.Weight == 0 && c.Category != CatInfo {
			t.Errorf("%q has weight 0 outside the Info category", c.Class)
		}
		if _, ok := categoryCaps[c.Category]; !ok && c.Category != CatInfo {
			t.Errorf("%q names category %q, which has no cap", c.Class, c.Category)
		}
	}
	if Caps()[CatSections] != categoryCaps[CatSections] {
		t.Error("Caps() does not mirror categoryCaps")
	}
}
