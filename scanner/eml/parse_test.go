package eml

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// crlf turns a readable test email into wire format.
func crlf(s string) []byte {
	return []byte(strings.ReplaceAll(strings.TrimLeft(s, "\n"), "\n", "\r\n"))
}

const plainMail = `
From: Thandi Mokoena <thandi@example.co.za>
To: lunga@example.com
Subject: Lunch on Friday
Date: Mon, 2 Nov 2026 09:15:00 +0200
Message-ID: <abc123@example.co.za>

Hi, are we still on for Friday?
Menu is at https://example.co.za/menu.
`

func TestIsEML(t *testing.T) {
	yes := [][]byte{
		crlf(plainMail),
		[]byte(strings.TrimLeft(plainMail, "\n")), // bare LF
		crlf("Received: from a by b\n\tfor <x@y>; Mon, 2 Nov 2026\nFrom: a@b.c\nSubject: hi\n\nbody"),
	}
	for i, d := range yes {
		if !IsEML(d) {
			t.Errorf("case %d: real email not recognised", i)
		}
	}
	no := map[string][]byte{
		"empty":        nil,
		"prose":        []byte("From: the desk of nobody\n\nJust a note, not an email.\n"),
		"http":         []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"yaml":         []byte("from: a\nto: b\nsubject: c\ndate: d\nkey with space: 1\n"),
		"binary":       {0x7f, 'E', 'L', 'F', 2, 1, 1, 0},
		"no from":      []byte("To: a@b.c\nSubject: x\nDate: y\n\nbody"),
		"leading fold": []byte(" From: a@b.c\nTo: a@b.c\nSubject: x\n\n"),
		"nul byte":     []byte("From: a@b.c\nTo: a\x00@b.c\nSubject: x\n\n"),
	}
	for name, d := range no {
		if IsEML(d) {
			t.Errorf("%s: wrongly recognised as an email", name)
		}
	}
}

func TestParsePlain(t *testing.T) {
	m, err := Parse(crlf(plainMail))
	if err != nil {
		t.Fatal(err)
	}
	if m.From.Name != "Thandi Mokoena" || m.From.Addr != "thandi@example.co.za" {
		t.Errorf("From = %+v", m.From)
	}
	if got := m.From.Domain(); got != "example.co.za" {
		t.Errorf("Domain = %q", got)
	}
	if m.Subject != "Lunch on Friday" {
		t.Errorf("Subject = %q", m.Subject)
	}
	if !strings.Contains(m.Text, "still on for Friday") {
		t.Errorf("Text = %q", m.Text)
	}
	// trailing full stop is not part of the URL
	want := []Link{{URL: "https://example.co.za/menu"}}
	if len(m.Links) != 1 || m.Links[0] != want[0] {
		t.Errorf("Links = %+v, want %+v", m.Links, want)
	}
	if len(m.Attachments) != 0 || m.Parts != 1 || m.Truncated {
		t.Errorf("attachments=%d parts=%d truncated=%v", len(m.Attachments), m.Parts, m.Truncated)
	}
}

func TestParseNotEmail(t *testing.T) {
	if _, err := Parse([]byte("just some text")); !errors.Is(err, ErrNotEML) {
		t.Errorf("err = %v, want ErrNotEML", err)
	}
}

// A typical phish: bank display name on a free mail address, a link whose text
// is the bank and whose target is not, and an attachment.
func TestParsePhish(t *testing.T) {
	payload := []byte("MZ\x90\x00 pretend this is an exe")
	mailText := `
From: =?UTF-8?B?Rk5CIFN1cHBvcnQ=?= <fnb.helpdesk88@gmail.com>
Reply-To: recover@fnb-secure-login.example
Return-Path: <bounce@mailer.example>
To: victim@example.com
Subject: =?UTF-8?Q?Your_account_is_locked_=E2=9A=A0?=
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain; charset=utf-8

Verify at http://198.51.100.7/fnb/login now.
--inner
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<p>Dear client,</p><a class=3D"btn" href=3D"http://198.51.100.7/fnb/login?=
id=3D1&amp;x=3D2"><b>https://www.fnb.co.za</b> </a>
<A HREF=3D'https://www.fnb.co.za/help'>Help</A>
--inner--
--outer
Content-Type: application/octet-stream; name="statement.pdf.exe"
Content-Disposition: attachment; filename="statement.pdf.exe"
Content-Transfer-Encoding: base64

` + base64.StdEncoding.EncodeToString(payload) + `
--outer--
`
	m, err := Parse(crlf(mailText))
	if err != nil {
		t.Fatal(err)
	}
	if m.From.Name != "FNB Support" || m.From.Addr != "fnb.helpdesk88@gmail.com" {
		t.Errorf("From = %+v", m.From)
	}
	if m.ReplyTo.Addr != "recover@fnb-secure-login.example" {
		t.Errorf("ReplyTo = %+v", m.ReplyTo)
	}
	if m.ReturnPath.Addr != "bounce@mailer.example" {
		t.Errorf("ReturnPath = %+v", m.ReturnPath)
	}
	if m.Subject != "Your account is locked ⚠" {
		t.Errorf("Subject = %q", m.Subject)
	}
	if m.Parts != 3 {
		t.Errorf("Parts = %d, want 3", m.Parts)
	}

	want := []Link{
		{Text: "https://www.fnb.co.za", URL: "http://198.51.100.7/fnb/login?id=1&x=2"},
		{Text: "Help", URL: "https://www.fnb.co.za/help"},
		{URL: "http://198.51.100.7/fnb/login"},
	}
	if len(m.Links) != len(want) {
		t.Fatalf("Links = %+v", m.Links)
	}
	for i := range want {
		if m.Links[i] != want[i] {
			t.Errorf("Links[%d] = %+v, want %+v", i, m.Links[i], want[i])
		}
	}

	if len(m.Attachments) != 1 {
		t.Fatalf("Attachments = %+v", m.Attachments)
	}
	a := m.Attachments[0]
	if a.Name != "statement.pdf.exe" || a.ContentType != "application/octet-stream" {
		t.Errorf("attachment = %q %q", a.Name, a.ContentType)
	}
	if !bytes.Equal(a.Data, payload) {
		t.Errorf("attachment data = %q", a.Data)
	}
}

func TestSloppyFrom(t *testing.T) {
	cases := map[string]Address{
		`"SARS eFiling" <refunds@sars-gov.example>`:   {Name: "SARS eFiling", Addr: "refunds@sars-gov.example"},
		`ABSA Bank: Alerts <Alerts@Absa.Example>`:     {Name: "ABSA Bank: Alerts", Addr: "alerts@absa.example"},
		`plain@example.com`:                           {Addr: "plain@example.com"},
		`no address here`:                             {Name: "no address here"},
		`a@example.com, "Second" <b@example.com>`:     {Addr: "a@example.com"},
		`=?ISO-8859-1?Q?Andr=E9?= <andre@example.fr>`: {Name: "André", Addr: "andre@example.fr"},
		``: {},
	}
	for in, want := range cases {
		if got := firstAddress(in); got != want {
			t.Errorf("firstAddress(%q) = %+v, want %+v", in, got, want)
		}
	}
}

// An inline text part with a file name is still a file someone can open.
func TestNamedTextIsAttachment(t *testing.T) {
	m, err := Parse(crlf(`
From: a@example.com
To: b@example.com
Subject: invoice
Content-Type: text/html; name="invoice.html"

<a href="http://evil.example/">open</a>
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Attachments) != 1 || m.Attachments[0].Name != "invoice.html" {
		t.Fatalf("Attachments = %+v", m.Attachments)
	}
	if m.HTML != "" || len(m.Links) != 0 {
		t.Errorf("attachment leaked into body: html=%q links=%+v", m.HTML, m.Links)
	}
}

func TestLatin1Body(t *testing.T) {
	m, err := Parse([]byte("From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n" +
		"Content-Type: text/plain; charset=ISO-8859-1\r\n\r\ncaf\xe9\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Text, "café") {
		t.Errorf("Text = %q", m.Text)
	}
}

// Nesting deeper than maxDepth stops instead of recursing forever.
func TestDepthLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("From: a@example.com\nTo: b@example.com\nSubject: deep\n")
	const levels = maxDepth + 4
	for i := 0; i < levels; i++ {
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"b%d\"\n\n--b%d\n", i, i)
	}
	b.WriteString("Content-Type: text/plain\n\nbottom\n")
	for i := levels - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--b%d--\n", i)
	}
	m, err := Parse(crlf(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Truncated {
		t.Error("Truncated not set")
	}
	if strings.Contains(m.Text, "bottom") {
		t.Error("read past the depth limit")
	}
}

func TestPartLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("From: a@example.com\nTo: b@example.com\nSubject: many\n" +
		"Content-Type: multipart/mixed; boundary=\"x\"\n\n")
	for i := 0; i < maxParts+10; i++ {
		b.WriteString("--x\nContent-Type: text/plain\n\nhi\n")
	}
	b.WriteString("--x--\n")
	m, err := Parse(crlf(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if m.Parts != maxParts || !m.Truncated {
		t.Errorf("Parts = %d, Truncated = %v", m.Parts, m.Truncated)
	}
}

// Broken base64 keeps what decoded and does not fail the whole message.
func TestBadBase64(t *testing.T) {
	m, err := Parse(crlf(`
From: a@example.com
To: b@example.com
Subject: x
Content-Type: application/zip; name="a.zip"
Content-Transfer-Encoding: base64

UEsDBA==!!!!not-base64
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Attachments) != 1 || !bytes.HasPrefix(m.Attachments[0].Data, []byte("PK\x03\x04")) {
		t.Errorf("Attachments = %+v", m.Attachments)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(crlf(plainMail))
	f.Add([]byte("From: a@b.c\nTo: d@e.f\nSubject: s\nContent-Type: multipart/mixed; boundary=x\n\n--x\n\n--x--\n"))
	f.Add([]byte("From: a@b.c\nTo: d@e.f\nSubject: s\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\nPGEgaHJlZj0=\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if (m == nil) == (err == nil) {
			t.Fatalf("m=%v err=%v", m, err)
		}
		if err != nil {
			return
		}
		if len(m.Links) > maxLinks || m.Parts > maxParts {
			t.Fatalf("limits exceeded: links=%d parts=%d", len(m.Links), m.Parts)
		}
		for _, l := range m.Links {
			if l.URL == "" {
				t.Fatal("empty link URL")
			}
		}
	})
}
