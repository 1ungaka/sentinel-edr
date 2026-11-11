// Package eml reads saved emails (.eml, RFC 5322 + MIME) and pulls out the
// parts a phishing check needs: who sent it, the links and the attachments.
//
// This file is only the parser. It does not score anything.
package eml

import (
	"bytes"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Limits. An email is attacker input, so everything is capped.
const (
	DefaultMaxSize     int64 = 64 << 20
	maxHeaderBytes           = 256 << 10
	maxParts                 = 256
	maxDepth                 = 8
	maxLinks                 = 1024
	maxBodyBytes             = 4 << 20
	maxAttachmentBytes       = 32 << 20
)

// ErrNotEML is returned by Parse when the input does not look like an email.
var ErrNotEML = errors.New("eml: not an email message")

// Address is one mailbox from a header, e.g. From or Reply-To.
type Address struct {
	Name string `json:"name,omitempty"` // display name, decoded
	Addr string `json:"addr,omitempty"` // user@example.com, lower case
}

// Domain returns the part after the @, or "" if there is none.
func (a Address) Domain() string {
	i := strings.LastIndexByte(a.Addr, '@')
	if i < 0 {
		return ""
	}
	return a.Addr[i+1:]
}

// Link is a URL found in the body. Text is what the reader sees; for a link
// taken from plain text it is empty.
type Link struct {
	Text string `json:"text,omitempty"`
	URL  string `json:"url"`
}

// Attachment is a decoded file carried by the message.
type Attachment struct {
	Name        string `json:"name,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Data        []byte `json:"-"`
	Truncated   bool   `json:"truncated,omitempty"` // hit maxAttachmentBytes
}

// Message is a parsed email.
type Message struct {
	From       Address
	ReplyTo    Address
	ReturnPath Address
	Subject    string

	Text string // text/plain bodies, joined
	HTML string // text/html bodies, joined

	Links       []Link
	Attachments []Attachment

	Parts     int  // MIME leaf parts seen
	Truncated bool // a limit was hit, so the result is partial
}

var headerLine = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*:`)

// headers that only really show up in mail. From on its own is not enough,
// plenty of text files start with "From:".
var mailHeaders = map[string]bool{
	"received": true, "date": true, "subject": true, "to": true,
	"message-id": true, "mime-version": true, "return-path": true,
	"delivered-to": true, "content-type": true, "reply-to": true,
}

// IsEML reports whether data looks like an email: a header block with a From
// line and at least two other mail headers.
func IsEML(data []byte) bool {
	if len(data) > maxHeaderBytes {
		data = data[:maxHeaderBytes]
	}
	sawFrom := false
	seen := map[string]bool{}
	first := true
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			break // end of headers
		}
		if !utf8.Valid(line) || bytes.IndexByte(line, 0) >= 0 {
			return false
		}
		if line[0] == ' ' || line[0] == '\t' {
			if first {
				return false
			}
			continue // folded header
		}
		first = false
		if !headerLine.Match(line) {
			return false
		}
		name := strings.ToLower(string(line[:bytes.IndexByte(line, ':')]))
		if name == "from" {
			sawFrom = true
		} else if mailHeaders[name] {
			seen[name] = true
		}
	}
	return sawFrom && len(seen) >= 2
}

// Parse reads an email. It returns ErrNotEML if data is not one. A message that
// is too big or too deeply nested is still returned, with Truncated set.
func Parse(data []byte) (*Message, error) {
	if !IsEML(data) {
		return nil, ErrNotEML
	}
	raw, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, ErrNotEML
	}
	m := &Message{
		From:       firstAddress(raw.Header.Get("From")),
		ReplyTo:    firstAddress(raw.Header.Get("Reply-To")),
		ReturnPath: firstAddress(raw.Header.Get("Return-Path")),
		Subject:    decodeHeader(raw.Header.Get("Subject")),
	}
	var text, htm strings.Builder
	m.walk(textproto.MIMEHeader(raw.Header), raw.Body, 0, &text, &htm)
	m.Text, m.HTML = text.String(), htm.String()

	m.addLinks(htmlLinks(m.HTML))
	m.addLinks(textLinks(m.Text))
	return m, nil
}

// walk goes down the MIME tree and sorts each leaf into body or attachment.
func (m *Message) walk(h textproto.MIMEHeader, body io.Reader, depth int, text, htm *strings.Builder) {
	ctype, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || ctype == "" {
		ctype = "text/plain"
	}

	if strings.HasPrefix(ctype, "multipart/") && params["boundary"] != "" {
		if depth >= maxDepth {
			m.Truncated = true
			return
		}
		mr := multipart.NewReader(body, params["boundary"])
		for {
			// NextRawPart so we do the transfer decoding ourselves
			p, err := mr.NextRawPart()
			if err != nil {
				return
			}
			if m.Parts >= maxParts {
				m.Truncated = true
				return
			}
			m.walk(p.Header, p, depth+1, text, htm)
		}
	}

	m.Parts++
	_, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	disp := strings.ToLower(strings.TrimSpace(strings.SplitN(h.Get("Content-Disposition"), ";", 2)[0]))
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	name = decodeHeader(name)

	isBody := disp != "attachment" && name == "" && (ctype == "text/plain" || ctype == "text/html")
	limit := int64(maxAttachmentBytes)
	if isBody {
		limit = maxBodyBytes
	}
	data, truncated := readDecoded(body, h.Get("Content-Transfer-Encoding"), limit)
	if truncated {
		m.Truncated = true
	}

	if !isBody {
		m.Attachments = append(m.Attachments, Attachment{
			Name: name, ContentType: ctype, Data: data, Truncated: truncated,
		})
		return
	}
	s := toUTF8(data, params["charset"])
	if ctype == "text/html" {
		htm.WriteString(s)
		htm.WriteByte('\n')
	} else {
		text.WriteString(s)
		text.WriteByte('\n')
	}
}

// readDecoded undoes base64 / quoted-printable and reads at most limit bytes.
// A decode error keeps whatever came out before it.
func readDecoded(r io.Reader, encoding string, limit int64) (data []byte, truncated bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	}
	data, _ = io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(data)) > limit {
		return data[:limit], true
	}
	return data, false
}

// toUTF8 handles the two charsets that cover nearly all mail. Anything else is
// passed through with bad bytes replaced.
func toUTF8(b []byte, charset string) string {
	switch strings.ToLower(charset) {
	case "iso-8859-1", "latin1", "windows-1252", "cp1252":
		r := make([]rune, len(b))
		for i, c := range b {
			r[i] = rune(c)
		}
		return string(r)
	}
	return strings.ToValidUTF8(string(b), "�")
}

var wordDecoder = new(mime.WordDecoder)

// decodeHeader turns =?UTF-8?B?...?= encoded words into plain text.
func decodeHeader(s string) string {
	if out, err := wordDecoder.DecodeHeader(s); err == nil {
		return strings.TrimSpace(out)
	}
	return strings.TrimSpace(s)
}

var angleAddr = regexp.MustCompile(`<([^<>\s]+@[^<>\s]+)>`)

// firstAddress parses the first mailbox in a header value. Real phishing mail
// often has a sloppy From line, so fall back to grabbing <addr> by hand.
func firstAddress(v string) Address {
	v = strings.TrimSpace(v)
	if v == "" {
		return Address{}
	}
	p := mail.AddressParser{WordDecoder: wordDecoder}
	if list, err := p.ParseList(v); err == nil && len(list) > 0 {
		return Address{Name: strings.TrimSpace(list[0].Name), Addr: strings.ToLower(list[0].Address)}
	}
	if mm := angleAddr.FindStringSubmatchIndex(v); mm != nil {
		name := strings.Trim(strings.TrimSpace(v[:mm[0]]), `"`)
		return Address{Name: decodeHeader(name), Addr: strings.ToLower(v[mm[2]:mm[3]])}
	}
	return Address{Name: decodeHeader(v)}
}

var (
	anchorRe = regexp.MustCompile(`(?is)<a\b[^>]*?\bhref\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)[^>]*>(.*?)</a\s*>`)
	tagRe    = regexp.MustCompile(`(?s)<[^>]*>`)
	urlRe    = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"'\x60]+`)
)

// htmlLinks returns every <a href> with the text shown for it.
func htmlLinks(doc string) []Link {
	var out []Link
	for _, mm := range anchorRe.FindAllStringSubmatch(doc, maxLinks) {
		href := strings.TrimSpace(html.UnescapeString(strings.Trim(mm[1], `"'`)))
		if href == "" {
			continue
		}
		text := html.UnescapeString(tagRe.ReplaceAllString(mm[2], " "))
		out = append(out, Link{Text: strings.Join(strings.Fields(text), " "), URL: href})
	}
	return out
}

// textLinks returns bare URLs from a plain text body.
func textLinks(body string) []Link {
	var out []Link
	for _, u := range urlRe.FindAllString(body, maxLinks) {
		out = append(out, Link{URL: strings.TrimRight(u, ".,;:!?)]}")})
	}
	return out
}

// addLinks appends links, skipping exact repeats and stopping at maxLinks.
func (m *Message) addLinks(links []Link) {
	for _, l := range links {
		if len(m.Links) >= maxLinks {
			m.Truncated = true
			return
		}
		dup := false
		for _, have := range m.Links {
			if have == l {
				dup = true
				break
			}
		}
		if !dup {
			m.Links = append(m.Links, l)
		}
	}
}
