// Package model is the registry of model artifacts: the signed catalogue of
// what the engine may run.
//
// A model is a file an attacker would love to replace — a classifier that
// says "clean" is worse than no classifier at all. So the registry is signed
// (the same trust anchor as the release manifest and the update bundle) over
// its own canonical bytes, every artifact is named by its digest, and every
// artifact carries an SBOM and a model card: what it is, what it was trained
// on, what it is allowed to decide.
//
// The signature carries the registry's own domain ("cau-v1-model-registry"),
// which is what keeps the post-quantum half of a hybrid signature from being
// replayable as an update-manifest signature. With an Ed25519-only key that
// half does not exist and the domain does not enter the signature at all; what
// separates the artifacts there is the bytes, and the registry's canonical
// bytes are its own.
//
// The registry also answers the operational question: which version is
// active, and how to go back. Promoting a version records the previous one in
// the history; rolling back returns to it. Neither operation is a special
// case: both rewrite the document, and the rewritten document has to be
// signed again, so a promotion is an act with a signature on it.
//
// The registry does not run anything. Inference belongs to a sidecar process;
// this package only says what may run and proves the bytes are the ones that
// were signed.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/s-b-repo/cau/internal/release"
)

// SchemaVersion is the registry document format version this package reads
// and writes. A document declaring anything else is refused rather than
// best-effort parsed.
const SchemaVersion = "1"

// Model is one artifact in the registry.
type Model struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Path is the artifact, relative to the registry's directory.
	Path string `json:"path"`
	// SHA256 is the artifact's digest. It is the identity: the file on disk
	// is only the artifact if it hashes to this.
	SHA256 string `json:"sha256"`
	// Size is the artifact's length in bytes, checked with the digest.
	Size int64 `json:"size,omitempty"`
	// Format is the artifact's format ("onnx").
	Format string `json:"format,omitempty"`
	// Runtime names the process that runs it ("onnxruntime-sidecar"). The
	// engine never runs a model itself.
	Runtime string `json:"runtime,omitempty"`
	// SBOM is the artifact's software bill of materials, relative to the
	// registry's directory. A model without one is refused: an artifact
	// nobody can account for is an artifact nobody can trust.
	SBOM string `json:"sbom,omitempty"`
	// SBOMSHA256 is the SBOM's digest.
	SBOMSHA256 string `json:"sbom_sha256,omitempty"`
	// Card is the model card: what the model is, what it was trained on and
	// what it is allowed to decide.
	Card string `json:"card,omitempty"`
	// CardSHA256 is the card's digest.
	CardSHA256 string `json:"card_sha256,omitempty"`
	// Notes is free-form text for the operator.
	Notes string `json:"notes,omitempty"`
}

// ID is the model's identity: name@version.
func (m Model) ID() string { return m.Name + "@" + m.Version }

// Registry is the catalogue.
type Registry struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name,omitempty"`
	// Active is the ID of the version in force.
	Active string `json:"active,omitempty"`
	// History is the IDs of the versions that were active before, most
	// recent first. It is what a rollback returns to.
	History []string `json:"history,omitempty"`
	Models  []Model  `json:"models"`
}

// Parse reads a registry document. Unknown fields are a hard error: a
// misspelt field would otherwise be silently ignored, and a registry that
// silently drops a digest is a registry that cannot be trusted.
func Parse(data []byte) (*Registry, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var r Registry
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("model: parse registry: %w", err)
	}
	if r.SchemaVersion != "" && r.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("model: unsupported schema_version %q (this build understands %q)", r.SchemaVersion, SchemaVersion)
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// validate checks the document's internal consistency.
func (r *Registry) validate() error {
	seen := map[string]bool{}
	for _, m := range r.Models {
		if m.Name == "" || m.Version == "" {
			return fmt.Errorf("model: a model entry has no name or no version")
		}
		if m.Path == "" {
			return fmt.Errorf("model: %s has no path", m.ID())
		}
		// The paths name files inside the registry's own directory. A path
		// that climbs out of it ("../../etc/shadow") or names one
		// absolutely is not a path inside the registry, and a registry that
		// names one is asking the reader to read a file the registry has no
		// business naming.
		for _, p := range []struct{ kind, rel string }{
			{"artifact", m.Path}, {"sbom", m.SBOM}, {"card", m.Card},
		} {
			if err := checkRelative(p.rel); err != nil {
				return fmt.Errorf("model: %s has an unusable %s path %q: %w", m.ID(), p.kind, p.rel, err)
			}
		}
		if !isSHA256(m.SHA256) {
			return fmt.Errorf("model: %s has a malformed sha256 %q", m.ID(), m.SHA256)
		}
		if m.SBOM == "" || m.SBOMSHA256 == "" {
			return fmt.Errorf("model: %s has no SBOM: an artifact nobody can account for is an artifact nobody can trust", m.ID())
		}
		if m.Card == "" || m.CardSHA256 == "" {
			return fmt.Errorf("model: %s has no model card", m.ID())
		}
		if seen[m.ID()] {
			return fmt.Errorf("model: %s is listed twice", m.ID())
		}
		seen[m.ID()] = true
	}
	if r.Active != "" && !seen[r.Active] {
		return fmt.Errorf("model: the active version %q is not in the registry", r.Active)
	}
	return nil
}

// checkRelative refuses a path that does not stay inside the registry's
// directory: an absolute path, or one with a ".." element.
func checkRelative(rel string) error {
	if rel == "" {
		return errors.New("the path is empty")
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") {
		return errors.New("the path is absolute")
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == ".." {
			return errors.New("the path climbs out of the registry directory")
		}
	}
	return nil
}

// Marshal renders the registry in the canonical form: the bytes that are
// signed. The field order is the struct's, and there is no indentation, so
// the same registry always produces the same bytes.
func Marshal(r *Registry) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("model: render registry: %w", err)
	}
	return data, nil
}

// Find returns the model with the given ID.
func (r *Registry) Find(id string) (Model, bool) {
	for _, m := range r.Models {
		if m.ID() == id {
			return m, true
		}
	}
	return Model{}, false
}

// ActiveModel returns the model in force.
func (r *Registry) ActiveModel() (Model, bool) {
	if r.Active == "" {
		return Model{}, false
	}
	return r.Find(r.Active)
}

// Promote makes a version active. The version that was active goes onto the
// history, so a rollback can return to it.
func (r *Registry) Promote(id string) error {
	if _, ok := r.Find(id); !ok {
		return fmt.Errorf("model: %q is not in the registry", id)
	}
	if r.Active == id {
		return nil
	}
	if r.Active != "" {
		r.History = append([]string{r.Active}, r.History...)
	}
	r.Active = id
	return nil
}

// Rollback returns to the version that was active before the current one.
func (r *Registry) Rollback() error {
	if len(r.History) == 0 {
		return fmt.Errorf("model: there is no earlier version to roll back to")
	}
	previous := r.History[0]
	if _, ok := r.Find(previous); !ok {
		return fmt.Errorf("model: the earlier version %q is not in the registry", previous)
	}
	r.History = r.History[1:]
	r.Active = previous
	return nil
}

// Problem is one thing the verification found.
type Problem struct {
	// Model is the model the problem is about ("" for the registry itself).
	Model string `json:"model,omitempty"`
	// Kind is a stable identifier ("digest", "signature", "sbom", "card").
	Kind string `json:"kind"`
	// Message says what is wrong.
	Message string `json:"message"`
}

// Verification is the outcome of verifying a registry against its signature
// and the files on disk.
type Verification struct {
	// Registry is the path the registry was read from.
	Registry string `json:"registry"`
	// Models is how many models the registry lists.
	Models int `json:"models"`
	// Active is the version in force, when there is one.
	Active string `json:"active,omitempty"`
	// Verified says whether the signature and every artifact matched.
	Verified bool `json:"verified"`
	// Problems lists everything that did not match.
	Problems []Problem `json:"problems,omitempty"`
	// Note carries what the verification could not check, such as an
	// unverified post-quantum half.
	Note string `json:"note,omitempty"`
}

// Verify checks a registry: the signature over its canonical bytes, then
// every artifact, SBOM and card against the digests the registry names.
//
// root is the directory the registry's paths are relative to. The signature is
// checked first: an unsigned or badly signed registry is not worth hashing
// anything in.
func Verify(r *Registry, root string, sig []byte, key release.VerifyKey) *Verification {
	v := &Verification{Models: len(r.Models), Active: r.Active}

	canonical, err := Marshal(r)
	if err != nil {
		v.Problems = append(v.Problems, Problem{Kind: "registry", Message: err.Error()})
		return v
	}
	checked, err := release.VerifyDetached(canonical, sig, key, release.DomainModelRegistry)
	if err != nil {
		v.Problems = append(v.Problems, Problem{Kind: "signature", Message: err.Error()})
		return v
	}
	if checked.PQUnchecked {
		v.Note = "the post-quantum half of the signature was not verified (the pinned key is Ed25519-only)"
	}

	for _, m := range r.Models {
		v.Problems = append(v.Problems, checkArtifact(m, root, "artifact", m.Path, m.SHA256, m.Size)...)
		v.Problems = append(v.Problems, checkArtifact(m, root, "sbom", m.SBOM, m.SBOMSHA256, 0)...)
		v.Problems = append(v.Problems, checkArtifact(m, root, "card", m.Card, m.CardSHA256, 0)...)
	}
	v.Verified = len(v.Problems) == 0
	return v
}

// within reports whether path is inside root.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil { // audit:ok the two paths cannot be related at all, so the path is certainly not inside the root
		return false
	}
	return filepath.IsLocal(rel)
}

// ResolveArtifact returns the path of a file the registry names, refusing one
// that is not inside the registry's directory.
//
// The registry's paths are relative to the directory it lives in. A path that
// climbs out of it names a file the registry does not own, and a command that
// opens it would read whatever is there.
func ResolveArtifact(root, rel string) (string, error) {
	if err := checkRelative(rel); err != nil {
		return "", fmt.Errorf("the registry names a path outside its directory (%v): %q", err, rel)
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	if !within(root, path) {
		return "", fmt.Errorf("the registry names a path outside its directory: %q", rel)
	}
	return path, nil
}

// checkArtifact checks one file against the digest the registry names.
func checkArtifact(m Model, root, kind, rel, wantSHA string, wantSize int64) []Problem {
	if rel == "" {
		return nil
	}
	var out []Problem
	if err := checkRelative(rel); err != nil {
		return []Problem{{Model: m.ID(), Kind: kind, Message: fmt.Sprintf("%s names a path outside the registry (%v)", rel, err)}}
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	// The path is inside the registry directory by construction now, but the
	// check is cheap and the consequence of being wrong is reading a file the
	// registry does not name.
	if !within(root, path) {
		return []Problem{{Model: m.ID(), Kind: kind, Message: fmt.Sprintf("%s names a path outside the registry", rel)}}
	}
	info, err := os.Stat(path)
	if err != nil {
		return []Problem{{Model: m.ID(), Kind: kind, Message: fmt.Sprintf("cannot read %s: %v", rel, err)}}
	}
	if info.IsDir() {
		return []Problem{{Model: m.ID(), Kind: kind, Message: fmt.Sprintf("%s is a directory", rel)}}
	}
	if wantSize > 0 && info.Size() != wantSize {
		out = append(out, Problem{Model: m.ID(), Kind: kind,
			Message: fmt.Sprintf("%s is %d bytes, the registry says %d", rel, info.Size(), wantSize)})
	}
	sum, err := release.DigestFile(path)
	if err != nil {
		return append(out, Problem{Model: m.ID(), Kind: kind, Message: err.Error()})
	}
	if !strings.EqualFold(sum, wantSHA) {
		out = append(out, Problem{Model: m.ID(), Kind: kind,
			Message: fmt.Sprintf("%s hashes to %s, the registry says %s", rel, short(sum), short(wantSHA))})
	}
	return out
}

// isSHA256 reports whether s is a 64-character hex digest.
func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// short renders a digest for a message.
func short(d string) string {
	if len(d) <= 16 {
		return d
	}
	return d[:8] + "…" + d[len(d)-8:]
}

// SortedIDs lists the models' IDs in order.
func (r *Registry) SortedIDs() []string {
	out := make([]string, 0, len(r.Models))
	for _, m := range r.Models {
		out = append(out, m.ID())
	}
	sort.Strings(out)
	return out
}
