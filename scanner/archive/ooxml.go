package archive

// OOXML (Office Open XML) documents — .docx/.docm, .xlsx/.xlsm, .pptx/.pptm —
// are zip containers. Two things inside them matter to this pass that plain
// container hygiene does not see:
//
//   - the VBA project. A macro-enabled document carries the same [MS-OVBA]
//     compound file the legacy .doc/.xls formats embed, as one member named
//     vbaProject.bin. The engine's OLE pass never sees it (the zip is not a
//     compound file), so this pass decompresses that one member, within its
//     own caps, and runs ole.Analyze over it. The OLE findings are carried
//     into the container's findings under the archive.ooxml.* prefix, with the
//     same weights, so a macro document the OLE pass would flag standalone is
//     flagged inside its zip; the full OLE result (has_vba, the per-module
//     source-state table, the OLE score and threshold) rides along as
//     Result.EmbeddedVBA.
//   - the attached template. A Word document may name the template it was
//     built from in word/_rels/settings.xml.rels (an attachedTemplate
//     relationship). When that target is an http/https/file URL rather than a
//     path, Word fetches it at open and runs whatever macros it carries: the
//     remote-template injection shape (ATT&CK T1221). Only the target's host is
//     reported — the URL itself is attacker text.
//
// The member NAME selects what to inspect; the CONTENT (a compound file with a
// VBA project, an XML relationship with an external target) is what is judged.
// A member named vbaProject.bin that is not a compound file produces nothing.

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/1ungaka/sentinel-edr/scanner/ole"
)

// OOXML inspection caps. Together with the magic peeks (maxMembersPeeked x
// maxMagicPeek = 256 KiB) these keep a zip's total decompression far under
// maxDecompress: at most one VBA project (16 MiB) and one relationship part
// (256 KiB) are expanded per container.
const (
	// maxVBAProjectBytes caps the vbaProject.bin member, declared and actual.
	// A VBA project is small (the largest seen in the wild is a few MiB; the
	// OLE pass's own file cap is 16 MiB); a larger one is refused and reported
	// as not inspected rather than expanded.
	maxVBAProjectBytes = 16 << 20
	// maxRelsBytes caps the settings.xml.rels member. A real one is under a
	// kilobyte.
	maxRelsBytes = 256 << 10
	// maxRelsTokens bounds the XML tokens read out of the relationship part.
	maxRelsTokens = 4096
	// maxHostLen clips the host reported as remote-template evidence.
	maxHostLen = 128
)

// scoreRemoteTemplate weights the remote-template finding. It sits below the
// threshold on its own: a template fetched over https from a corporate
// document-management host is a plausible benign shape, and the benign
// population this was measured on (see ooxml_test.go) is too small to
// justify a verdict from this single tell.
const scoreRemoteTemplate = 6

// techTemplateInjection is ATT&CK T1221, Template Injection.
const techTemplateInjection = "T1221"

// vbaProjectMember is the base name of the embedded VBA project; the
// directory varies (word/, xl/, ppt/, and embedded-document copies).
const vbaProjectMember = "vbaproject.bin"

// settingsRelsMember is where Word records the attachedTemplate relationship.
const settingsRelsMember = "word/_rels/settings.xml.rels"

// contentTypesMember marks an OPC package.
const contentTypesMember = "[content_types].xml"

// ooxmlClassPrefix is prepended, in place of the "ole." prefix, to every OLE
// finding class carried out of an embedded VBA project.
const ooxmlClassPrefix = "archive.ooxml."

// ooxml accumulates what the zip walk saw that bears on OOXML handling. It is
// filled by name only; nothing is decompressed until inspect runs.
type ooxml struct {
	contentTypes bool
	tree         string // "word", "xl" or "ppt": the first Office tree seen
	vba          []*zip.File
	settingsRels *zip.File
}

// note records one member by name. The cost on a non-Office zip is the
// lower-cased base-name comparison and nothing else.
func (o *ooxml) note(f *zip.File) {
	name := strings.ToLower(strings.ReplaceAll(f.Name, "\\", "/"))
	base := path.Base(name)
	switch {
	case base == vbaProjectMember:
		o.vba = append(o.vba, f)
	case name == contentTypesMember:
		o.contentTypes = true
	case name == settingsRelsMember:
		o.settingsRels = f
	}
	if o.tree == "" {
		switch {
		case strings.HasPrefix(name, "word/"):
			o.tree = "word"
		case strings.HasPrefix(name, "xl/"):
			o.tree = "xl"
		case strings.HasPrefix(name, "ppt/"):
			o.tree = "ppt"
		}
	}
}

// format returns the Summary.Format detail for a recognised document, or "".
func (o *ooxml) format() string {
	if !o.contentTypes {
		return ""
	}
	switch o.tree {
	case "word":
		return "ooxml-word"
	case "xl":
		return "ooxml-excel"
	case "ppt":
		return "ooxml-powerpoint"
	}
	return ""
}

// inspect runs the OOXML checks over a recognised document, appending to the
// collector and filling r.EmbeddedVBA.
func (o *ooxml) inspect(r *Result, c *collector, oleThreshold int) {
	o.inspectVBA(r, c, oleThreshold)
	if o.tree == "word" && o.settingsRels != nil {
		o.inspectTemplate(c)
	}
}

// inspectVBA expands the first vbaProject.bin member under the cap and runs
// the OLE pass over it. Members over the cap, and any further copies, are
// reported as not inspected rather than expanded.
func (o *ooxml) inspectVBA(r *Result, c *collector, oleThreshold int) {
	var skipped []string
	for _, f := range o.vba {
		if r.EmbeddedVBA != nil {
			skipped = append(skipped, f.Name+": a VBA project was already inspected")
			continue
		}
		if f.Flags&0x1 != 0 {
			skipped = append(skipped, f.Name+": encrypted")
			continue
		}
		if f.UncompressedSize64 > maxVBAProjectBytes {
			skipped = append(skipped, fmt.Sprintf("%s: declares %d bytes, over the %d byte VBA project cap",
				f.Name, f.UncompressedSize64, maxVBAProjectBytes))
			continue
		}
		data, err := readMember(f, maxVBAProjectBytes)
		if err != nil {
			skipped = append(skipped, f.Name+": "+err.Error())
			continue
		}
		res := ole.Analyze(data, ole.Options{Threshold: oleThreshold})
		res.FilePath = f.Name
		r.EmbeddedVBA = res
		c.vbaMember = f.Name
		for _, fd := range res.Findings {
			c.ooxml = append(c.ooxml, Finding{
				Class:     ooxmlClass(fd.Class),
				Score:     fd.Score,
				Technique: fd.Technique,
				Detail:    fd.Detail,
				Evidence:  fd.Evidence,
				Via:       f.Name,
			})
		}
	}
	if len(skipped) > 0 {
		c.addNotInspected(firstOf(skipped))
	}
}

// ooxmlClass maps an OLE finding class to the archive catalog's name for it:
// ole.vba.autoexec becomes archive.ooxml.vba.autoexec.
func ooxmlClass(oleClass string) string {
	return ooxmlClassPrefix + strings.TrimPrefix(oleClass, "ole.")
}

// errMemberTooLarge reports a member whose stream outgrew its declared size.
var errMemberTooLarge = errors.New("member decompresses past the cap (declared size lies)")

// readMember decompresses one member in full, refusing to read past max
// bytes however large the stream really is.
func readMember(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > max {
		return nil, errMemberTooLarge
	}
	return buf, nil
}

// relationship is the one element type read out of a .rels part. Attributes
// are read by hand (case-insensitively) rather than unmarshalled.
type relationship struct {
	Type   string
	Target string
}

// inspectTemplate reads word/_rels/settings.xml.rels and reports an
// attachedTemplate relationship whose target is a URL. A relative or
// drive-qualified path (the template the document was built from, on the
// author's machine) is not a finding.
func (o *ooxml) inspectTemplate(c *collector) {
	f := o.settingsRels
	if f.Flags&0x1 != 0 || f.UncompressedSize64 > maxRelsBytes {
		c.addNotInspected(f.Name + ": relationship part encrypted or over the cap")
		return
	}
	data, err := readMember(f, maxRelsBytes)
	if err != nil {
		c.addNotInspected(f.Name + ": " + err.Error())
		return
	}
	host, ok := remoteTemplateHost(data)
	if !ok {
		return
	}
	c.ooxml = append(c.ooxml, Finding{
		Class:     "archive.ooxml.remote-template",
		Score:     scoreRemoteTemplate,
		Technique: techTemplateInjection,
		Detail:    "the attached template is fetched from a remote host when the document opens (remote-template injection shape)",
		Evidence:  host,
		Via:       f.Name,
	})
}

// remoteTemplateHost scans a relationships part for an attachedTemplate
// relationship with an http, https or file target and returns the target's
// host. The XML walk is bounded by maxRelsTokens; a malformed part simply
// yields no finding.
func remoteTemplateHost(data []byte) (string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	for n := 0; n < maxRelsTokens; n++ {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		se, ok := tok.(xml.StartElement)
		if !ok || !strings.EqualFold(se.Name.Local, "Relationship") {
			continue
		}
		var rel relationship
		for _, a := range se.Attr {
			switch strings.ToLower(a.Name.Local) {
			case "type":
				rel.Type = a.Value
			case "target":
				rel.Target = a.Value
			}
		}
		if !strings.HasSuffix(strings.ToLower(rel.Type), "/attachedtemplate") {
			continue
		}
		if host, ok := urlHost(rel.Target); ok {
			return host, true
		}
	}
	return "", false
}

// urlHost returns the host of an http://, https:// or file:// target. Anything
// else — a relative path, a drive path, a UNC path, another scheme — is not a
// remote template for this check and returns false. The host is clipped and
// reduced to printable ASCII; it is attacker text.
func urlHost(target string) (string, bool) {
	t := strings.TrimSpace(target)
	lower := strings.ToLower(t)
	var rest string
	switch {
	case strings.HasPrefix(lower, "http://"):
		rest = t[len("http://"):]
	case strings.HasPrefix(lower, "https://"):
		rest = t[len("https://"):]
	case strings.HasPrefix(lower, "file://"):
		rest = t[len("file://"):]
	default:
		return "", false
	}
	// authority ends at the first path, query or fragment delimiter.
	if i := strings.IndexAny(rest, "/\\?#"); i >= 0 {
		rest = rest[:i]
	}
	// drop userinfo and port; a bracketed IPv6 literal keeps its brackets.
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	if strings.HasPrefix(rest, "[") {
		if i := strings.IndexByte(rest, ']'); i >= 0 {
			rest = rest[:i+1]
		}
	} else if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		// file:///C:/templates/x.dotm has an empty authority: a local path.
		return "", false
	}
	out := make([]byte, 0, len(rest))
	for i := 0; i < len(rest) && len(out) < maxHostLen; i++ {
		b := rest[i]
		if b < 0x21 || b > 0x7E {
			b = '?'
		}
		out = append(out, b)
	}
	return string(out), true
}
