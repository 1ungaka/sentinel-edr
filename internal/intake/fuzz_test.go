package intake

import "testing"

// FuzzParse drives every feed parser with arbitrary bytes. The invariant is
// "never panic": a hostile or malformed feed must return an error or an empty
// result, never crash the ingesting process.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"type":"bundle","objects":[{"type":"indicator","pattern":"[file:hashes.'SHA-256'='` +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `']"}]}`))
	f.Add([]byte(`{"Event":{"info":"x","Attribute":[{"type":"sha256","value":"deadbeef"}]}}`))
	f.Add([]byte(`{"query_status":"ok","data":[{"sha256_hash":"x","signature":"y"}]}`))
	f.Add([]byte(`[{"Id":"a","KnownVulnerableSamples":[{"SHA256":"z"}]}]`))
	f.Add([]byte(``))
	f.Add([]byte(`{`))
	f.Add([]byte(`[[[[[[[[[[`))
	f.Add([]byte("\x00\x01\x02 not json"))

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, format := range Formats() {
			// Must not panic; any error or result is acceptable.
			iocs, err := Parse(format, data)
			if err == nil {
				// A successful parse must yield only well-formed, validated IOCs.
				for _, i := range iocs {
					if i.Hash == "" || i.HashType == "" || i.ThreatName == "" {
						t.Fatalf("format %s produced a malformed IOC from fuzz input: %+v", format, i)
					}
				}
			}
		}
		// The CSV path too.
		_, _ = ParseMalwareBazaarCSV(data)
	})
}
