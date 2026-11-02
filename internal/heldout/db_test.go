package heldout

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	sha1 = "67752ad7dbcabbf644510590b078e9649104756f19c0222443641f74cadbca51"
	sha2 = "1bd750ba45cd726c869b19984529bfb50c36b18feee2265faa41d7205505158d"
)

func TestRoundTrip(t *testing.T) {
	db := &DB{}
	if err := db.Add(Record{SHA256: sha1, Family: "wannacry", URL: "https://x/" + sha1}); err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Record{SHA256: strings.ToUpper(sha2), Family: "mimikatz"}); err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery staple")
	blob, err := Encrypt(db, pass)
	if err != nil {
		t.Fatal(err)
	}
	// The ciphertext must not leak a hash in plaintext.
	if bytes.Contains(blob, []byte(sha1)) {
		t.Fatal("hash appears in plaintext in the encrypted blob")
	}
	back, err := Decrypt(blob, pass)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Records) != 2 {
		t.Fatalf("got %d records, want 2", len(back.Records))
	}
	// Records are sorted by hash and the uppercase input was normalised.
	if back.Records[0].SHA256 != sha2 || back.Records[1].SHA256 != sha1 {
		t.Errorf("records not sorted/normalised: %+v", back.Records)
	}
	if back.Records[1].Added == "" {
		t.Error("Add should stamp a timestamp")
	}
}

func TestWrongKeyFails(t *testing.T) {
	db := &DB{}
	_ = db.Add(Record{SHA256: sha1, Family: "wannacry"})
	blob, err := Encrypt(db, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(blob, []byte("wrong")); err != ErrWrongKey {
		t.Errorf("wrong passphrase: err = %v, want ErrWrongKey", err)
	}
}

func TestTamperFails(t *testing.T) {
	db := &DB{}
	_ = db.Add(Record{SHA256: sha1, Family: "wannacry"})
	blob, _ := Encrypt(db, []byte("k"))
	// Flip a byte in the ciphertext body: GCM must reject it.
	blob[len(blob)-1] ^= 0xff
	if _, err := Decrypt(blob, []byte("k")); err != ErrWrongKey {
		t.Errorf("tampered ciphertext: err = %v, want ErrWrongKey", err)
	}
}

func TestHeaderTamperFails(t *testing.T) {
	db := &DB{}
	_ = db.Add(Record{SHA256: sha1, Family: "wannacry"})
	blob, _ := Encrypt(db, []byte("k"))
	// Flip a byte in the salt (inside the authenticated header).
	blob[len(magic)] ^= 0x01
	if _, err := Decrypt(blob, []byte("k")); err != ErrWrongKey {
		t.Errorf("tampered header: err = %v, want ErrWrongKey", err)
	}
}

func TestBadMagic(t *testing.T) {
	if _, err := Decrypt([]byte("not a cau held-out db at all....."), []byte("k")); err == nil {
		t.Error("want an error for a non-database blob")
	}
}

func TestAddValidation(t *testing.T) {
	db := &DB{}
	if err := db.Add(Record{SHA256: "deadbeef", Family: "x"}); err == nil {
		t.Error("want error for a short hash")
	}
	if err := db.Add(Record{SHA256: sha1, Family: ""}); err == nil {
		t.Error("want error for an empty family")
	}
}

func TestAddReplaces(t *testing.T) {
	db := &DB{}
	_ = db.Add(Record{SHA256: sha1, Family: "wannacry"})
	_ = db.Add(Record{SHA256: sha1, Family: "wannacry2"})
	if len(db.Records) != 1 {
		t.Fatalf("duplicate hash should replace, got %d records", len(db.Records))
	}
	if db.Records[0].Family != "wannacry2" {
		t.Errorf("family = %q, want the replacement", db.Records[0].Family)
	}
}

func TestRemove(t *testing.T) {
	db := &DB{}
	_ = db.Add(Record{SHA256: sha1, Family: "wannacry"})
	ok, err := db.Remove(sha1)
	if err != nil || !ok {
		t.Fatalf("remove = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := db.Remove(sha2); ok {
		t.Error("removing an absent hash should report false")
	}
}

func TestManifestShape(t *testing.T) {
	db := &DB{}
	_ = db.Add(Record{SHA256: sha1, Family: "wannacry", URL: "https://x", License: "CC0-1.0"})
	m, err := db.Manifest("corpus/heldout/samples")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		SchemaVersion string `json:"schema_version"`
		Root          string `json:"root"`
		Samples       []struct {
			ID         string `json:"id"`
			Path       string `json:"path"`
			Label      string `json:"label"`
			Family     string `json:"family"`
			SHA256     string `json:"sha256"`
			Provenance struct {
				Source, URL, License string
			} `json:"provenance"`
		} `json:"samples"`
	}
	if err := json.Unmarshal(m, &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != "1" || got.Root != "corpus/heldout/samples" {
		t.Errorf("schema/root = %q/%q", got.SchemaVersion, got.Root)
	}
	if len(got.Samples) != 1 {
		t.Fatalf("got %d samples, want 1", len(got.Samples))
	}
	s := got.Samples[0]
	if s.Path != sha1+".bin" {
		t.Errorf("path = %q, want %s.bin", s.Path, sha1)
	}
	if s.Label != "wannacry" || s.Family != "wannacry" || s.SHA256 != sha1 {
		t.Errorf("label/family/sha = %q/%q/%q", s.Label, s.Family, s.SHA256)
	}
	if s.Provenance.Source != "malwarebazaar" || s.Provenance.License != "CC0-1.0" {
		t.Errorf("provenance = %+v", s.Provenance)
	}
}
