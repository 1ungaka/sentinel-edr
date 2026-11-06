package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// One hostile file name, every output format. The name carries each line
// format's separators, a newline followed by a forged syslog frame, a tab, a
// terminal escape sequence and a bidi override (hostilePath, siem_test.go).
// Whatever the format, the name is data: it must not add a result, break the
// document, or reach a terminal as a control sequence.

// walkStrings calls fn for every string value in a decoded JSON tree.
func walkStrings(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case []any:
		for _, e := range x {
			walkStrings(e, fn)
		}
	case map[string]any:
		for _, e := range x {
			walkStrings(e, fn)
		}
	}
}

func TestEveryFormatTreatsAHostileFileNameAsData(t *testing.T) {
	jsonDocument := map[string]bool{"json": true, "sarif": true, "ocsf": true, "otlp": true}
	jsonLines := map[string]bool{"ecs": true, "gelf": true}
	// Formats that carry the path as a plain string a consumer reads back
	// byte for byte. SARIF carries it as a percent-encoded URI instead.
	exact := map[string]bool{"json": true, "ocsf": true, "otlp": true, "ecs": true, "gelf": true}

	for _, format := range Formats {
		t.Run(format, func(t *testing.T) {
			out := renderFormat(t, format, hostileInput())
			if bytes.IndexByte(out, 0x1b) >= 0 {
				t.Errorf("a raw escape byte reached the %s output", format)
			}
			var docs []any
			switch {
			case jsonDocument[format]:
				var doc any
				if err := json.Unmarshal(out, &doc); err != nil {
					t.Fatalf("%s is no longer valid JSON with a hostile name: %v", format, err)
				}
				docs = append(docs, doc)
			case jsonLines[format]:
				lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
				if len(lines) != 1 {
					t.Fatalf("%s: %d lines for one finding", format, len(lines))
				}
				var doc any
				if err := json.Unmarshal([]byte(lines[0]), &doc); err != nil {
					t.Fatalf("%s line is not valid JSON: %v", format, err)
				}
				docs = append(docs, doc)
			case format == "text":
				// The forged frame must not start a line of its own.
				for _, line := range strings.Split(string(out), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "<83>1 ") {
						t.Errorf("text: the name forged a line: %q", line)
					}
				}
				if strings.ContainsRune(string(out), 0x202e) {
					t.Error("text: a raw bidi override reached the output")
				}
			default:
				// The line formats: exactly one event (asserted in detail by
				// TestSinkHostileFilename).
				if n := strings.Count(string(out), "\n"); n != 1 {
					t.Errorf("%s: %d lines for one finding", format, n)
				}
			}
			if exact[format] {
				found := false
				for _, doc := range docs {
					walkStrings(doc, func(s string) {
						if s == hostilePath {
							found = true
						}
					})
				}
				if !found {
					t.Errorf("%s does not carry the file name byte for byte", format)
				}
			}
			if format == "sarif" {
				// One result, and the forged frame is not a value of its own.
				doc := docs[0].(map[string]any)
				results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
				if len(results) != 1 {
					t.Errorf("sarif: %d results for one finding", len(results))
				}
				walkStrings(doc, func(s string) {
					if strings.HasPrefix(s, "<83>1 ") {
						t.Errorf("sarif: the forged frame became its own value: %q", s)
					}
				})
			}
		})
	}
	if len(Formats) < 13 {
		t.Fatalf("only %d formats checked", len(Formats))
	}
}
