package evasion

import (
	"fmt"
	"unicode/utf8"

	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/encchain"
	"github.com/s-b-repo/cau/scanner/static"
	"github.com/s-b-repo/cau/scanner/stego"
)

// The detectors below do not all key on a byte range, and the report says so
// rather than inventing a distance. A detector that keys on a structure — a
// shortcut's arguments, a macro's entry point, a script's line — needs the
// structure dismantled, and "how many bytes is that" is not a number anyone
// can read off a finding.

// staticDetector measures one structural anomaly.
func staticDetector(res *static.Result, class, detail, technique string) Detector {
	d := Detector{Name: "static", Class: class, Detail: detail, Technique: technique}
	switch {
	case class == "overlay.present" || class == "overlay.high-entropy":
		if n := overlaySize(res); n > 0 {
			d.Derivable = true
			d.Distance = n
			d.Edit = fmt.Sprintf("the appended data is %d bytes; removing it removes the overlay", n)
			return d
		}
	}
	d.Edit = "the class describes a property of the structure, not of a byte range, so the distance is not derivable"
	return d
}

// overlaySize is the size of the data appended past the last section, when the
// file is an image the parser understands.
func overlaySize(res *static.Result) int {
	if res == nil {
		return 0
	}
	switch {
	case res.PE != nil:
		return int(res.PE.Overlay.Size)
	case res.ELF != nil:
		return int(res.ELF.Overlay.Size)
	case res.MachO != nil:
		return int(res.MachO.Overlay.Size)
	}
	return 0
}

// stegoDetector measures the invisible-codepoint detection. The distance is
// exact: the scored codepoints are invisible characters, and removing them
// removes the finding.
func stegoDetector(res *stego.Result) (Detector, bool) {
	if res == nil || res.Suspicious == 0 {
		return Detector{}, false
	}
	d := Detector{
		Name:   "stego",
		Class:  "stego.codepoints",
		Detail: fmt.Sprintf("%d invisible codepoint occurrence(s) scored", res.Suspicious),
	}
	bytes := 0
	for _, c := range res.Codepoints {
		scored := c.Count - c.Benign
		if scored <= 0 {
			continue
		}
		n := utf8.RuneLen(c.Rune)
		if n <= 0 {
			n = 1
		}
		bytes += scored * n
	}
	if bytes <= 0 {
		d.Edit = "the scored codepoints are not listed, so the byte count is not derivable"
		return d, true
	}
	d.Derivable = true
	d.Distance = bytes
	d.Edit = fmt.Sprintf("%d byte(s) of invisible codepoints; deleting them removes the finding", bytes)
	return d, true
}

// encchainDetector measures one encoded-executable detection.
func encchainDetector(f encchain.Finding) Detector {
	d := Detector{
		Name:      "encchain",
		Class:     f.Class,
		Detail:    fmt.Sprintf("%d layer(s) of %s decode to an executable header", f.Depth, f.Encoding),
		Technique: f.Technique,
	}
	d.Distance = 1
	d.Derivable = true
	d.Edit = fmt.Sprintf("one byte inside the %d-byte %s run changes what it decodes to, so it no longer decodes to an executable header", f.RunBytes, f.Encoding)
	return d
}

// otherDetectors reports the findings of the detectors whose distance is not
// derived. They are listed, because "the file tripped a tradecraft rule" is
// part of the picture even when the bytes to undo it are not a number.
func otherDetectors(res *scanner.ScanResult) []Detector {
	var out []Detector
	add := func(name, class, detail, technique string) {
		if class == "" {
			return
		}
		out = append(out, Detector{
			Name:      name,
			Class:     class,
			Detail:    detail,
			Technique: technique,
			Edit:      "the detection keys on a structure, so the bytes to dismantle it are not derivable from the finding",
		})
	}

	if res.LNK != nil {
		for _, f := range res.LNK.Findings {
			add("lnk", f.Class, f.Detail, f.Technique)
		}
	}
	if res.OLE != nil {
		for _, f := range res.OLE.Findings {
			add("ole", f.Class, f.Detail, f.Technique)
		}
	}
	if res.PDF != nil {
		for _, f := range res.PDF.Findings {
			add("pdf", f.Class, f.Detail, f.Technique)
		}
	}
	if res.CHM != nil {
		for _, f := range res.CHM.Findings {
			add("chm", f.Class, f.Detail, f.Technique)
		}
	}
	if res.ISO != nil {
		for _, f := range res.ISO.Findings {
			add("iso", f.Class, f.Detail, f.Technique)
		}
	}
	if res.LinuxPkg != nil {
		for _, f := range res.LinuxPkg.Findings {
			add("linuxpkg", f.Class, f.Detail, f.Technique)
		}
	}
	if res.Archive != nil {
		for _, f := range res.Archive.Findings {
			add("archive", f.Class, f.Detail, f.Technique)
		}
	}
	if res.Tradecraft != nil {
		for _, f := range res.Tradecraft.Findings {
			add("tradecraft", f.Class, f.Detail, f.Technique)
		}
	}
	if res.Peel != nil {
		for _, f := range res.Peel.Findings {
			add("peel", f.Class, f.Detail, f.Technique)
		}
	}
	return out
}
