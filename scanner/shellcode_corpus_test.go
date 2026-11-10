package scanner

import (
	"bytes"
	"testing"

	"github.com/s-b-repo/cau/scanner/tradecraft"
)

// The shellcode corpus.
//
// The plan's rule for the export-hash atoms asks for "a shellcode corpus to
// measure recall before the atom is changed": the atoms were lengthened to the
// conventional rotate-and-add form, and nobody recorded whether that cost
// recall. This is that corpus.
//
// The fragments are the byte sequences the technique is made of — the PEB
// module walk and the rotate-and-add over an export name — and nothing more:
// they are not working shellcode, they carry no payload, and they are built
// here rather than committed, which is what the corpus policy asks for.
//
// The measurement answers the row's question: the YARA rule is deliberately
// narrow (it matches the two register forms the convention uses, because a
// YARA hit is MALICIOUS), and the Go pass is the one that generalises (any
// rotate). What matters is that the *system* catches every form, and that the
// narrow rule still catches the conventional ones.
func TestTheShellcodeCorpusMeasuresTheHashAtoms(t *testing.T) {
	ys := loadRepoYara(t)

	// The PEB module walk, in the two encodings the rule knows.
	walk32 := []byte{0x64, 0x8B, 0x05, 0x30, 0x8B, 0x45, 0x0C, 0x8B, 0x55, 0x10}
	walk64 := []byte{0x65, 0x48, 0x8B, 0x05, 0x60, 0x48, 0x8B, 0x4D, 0x18, 0x48, 0x8B, 0x55, 0x20}

	cases := []struct {
		name string
		walk []byte
		hash []byte
		// yara is whether the narrow rule is expected to catch it.
		yara bool
	}{
		{"x86 ror edi,13 (the conventional form)", walk32, []byte{0xC1, 0xCF, 0x0D, 0x01, 0xF9}, true},
		{"x86 ror edi,13, add the other way", walk32, []byte{0xC1, 0xCF, 0x0D, 0x03, 0xF9}, true},
		{"x86 ror eax,13 (another register)", walk32, []byte{0xC1, 0xC8, 0x0D, 0x01, 0xF9}, false},
		{"x86 ror edi,7 (another rotation)", walk32, []byte{0xC1, 0xCF, 0x07, 0x01, 0xF9}, false},
		{"x64 ror r9d,13 (the conventional form)", walk64, []byte{0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x03, 0xF9}, true},
		{"x64 ror r8d,13 (another register)", walk64, []byte{0x41, 0xC1, 0xC8, 0x0D, 0x41, 0x03, 0xF9}, false},
	}

	var yaraCaught, goCaught, total int
	// The Go pass looks for the hash loop in a window around the walk and
	// needs the sample to be longer than the pattern it scans, so every
	// fragment carries some trailing bytes.
	padding := bytes.Repeat([]byte{0x90}, 32)
	for _, c := range cases {
		sample := append(append(append([]byte{}, c.walk...), c.hash...), padding...)
		total++

		matches, err := ys.ScanMemYaraStrict(sample)
		if err != nil {
			t.Errorf("%s: the fragment did not scan: %v", c.name, err)
			continue
		}
		yara := hasRule(matches, "highly_sus_shellcode")
		if yara {
			yaraCaught++
		}
		if yara != c.yara {
			t.Errorf("%s: the rule %s it, want %s", c.name, map[bool]string{true: "caught", false: "did not catch"}[yara], map[bool]string{true: "caught", false: "did not catch"}[c.yara])
		}

		// The Go pass is the one that generalises: any rotate, any register.
		res := tradecraft.Analyze(sample, tradecraft.Options{Threshold: tradecraft.Threshold})
		goHit := res.Detected()
		if goHit {
			goCaught++
		}
		if !goHit {
			t.Errorf("%s: the Go pass did not catch the rotate-and-add form; the system recall is not there", c.name)
		}
	}
	t.Logf("shellcode corpus: %d fragment(s); the narrow rule caught %d, the Go pass caught %d", total, yaraCaught, goCaught)
}

// The atoms are the conventional forms, so the rule must catch those: that is
// the recall the plan's row asks to have measured.
func TestTheNarrowRuleCatchesTheConventionalHashForms(t *testing.T) {
	ys := loadRepoYara(t)
	walk32 := []byte{0x64, 0x8B, 0x05, 0x30, 0x8B, 0x45, 0x0C, 0x8B, 0x55, 0x10}
	walk64 := []byte{0x65, 0x48, 0x8B, 0x05, 0x60, 0x48, 0x8B, 0x4D, 0x18, 0x48, 0x8B, 0x55, 0x20}
	for _, c := range []struct {
		name   string
		sample []byte
	}{
		{"x86", append(append(append([]byte{}, walk32...), 0xC1, 0xCF, 0x0D, 0x01, 0xF9), bytes.Repeat([]byte{0x90}, 32)...)},
		{"x64", append(append(append([]byte{}, walk64...), 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x03, 0xF9), bytes.Repeat([]byte{0x90}, 32)...)},
	} {
		matches, err := ys.ScanMemYaraStrict(c.sample)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !hasRule(matches, "highly_sus_shellcode") {
			t.Errorf("%s: the conventional rotate-and-add form is not matched by the rule", c.name)
		}
	}
}

// The atoms are narrow on purpose, so the forms they do not match must not
// match: a YARA hit is MALICIOUS, and a loose atom would fire on ordinary
// binaries.
func TestTheNarrowRuleDoesNotFireOnTheFormsItDeclines(t *testing.T) {
	ys := loadRepoYara(t)
	walk32 := []byte{0x64, 0x8B, 0x05, 0x30, 0x8B, 0x45, 0x0C, 0x8B, 0x55, 0x10}
	sample := append(append([]byte{}, walk32...), 0xC1, 0xC8, 0x0D, 0x01, 0xF9)
	matches, err := ys.ScanMemYaraStrict(sample)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(matches, "highly_sus_shellcode") {
		t.Error("the rule fired on a rotate of a register it does not claim")
	}
}
