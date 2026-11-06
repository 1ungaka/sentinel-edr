package trust

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/s-b-repo/cau/internal/selftest"
)

// Guard is the agent's view of its own signed baseline: what its detection
// content and configuration looked like when somebody trusted it.
//
// It is deliberately usable in three states, because a host can be in any of
// them and the agent has to keep defending in all three:
//
//	no baseline      nothing was recorded. Nothing can be verified, and the
//	                 caller is told so once rather than silently believing
//	                 every file it reads.
//	baseline only    digests were recorded but no key was pinned. This catches
//	                 a change made by anyone who did not also rewrite the
//	                 manifest, which is most of them.
//	baseline + key   the manifest is signed and the public key is pinned, so
//	                 rewriting the manifest to match tampered content fails
//	                 too. This is the only state that resists an attacker who
//	                 already has the privileges to edit both files.
type Guard struct {
	path   string
	pub    ed25519.PublicKey
	man    selftest.Manifest
	loaded bool
	signed bool
}

// Refresh re-reads the baseline, so re-recording one after a legitimate content
// update takes effect without restarting the daemon. Without this the guard
// would hold its startup copy for the life of the process, and an operator who
// ran `cau feed update` followed by `cau selftest --record` would still be told
// their feed was tampered with until they restarted.
//
// A refresh that fails leaves the previous baseline in place and returns the
// error. That matters: the new file may be unreadable, unsafe or signed by the
// wrong key, and none of those are reasons to start trusting whatever is on
// disk now — nor to stop defending with what was already known good.
func (g *Guard) Refresh() error {
	if g == nil || g.path == "" {
		return nil
	}
	fresh, err := NewGuard(g.path, g.pub)
	if err != nil {
		return err
	}
	g.man, g.loaded, g.signed = fresh.man, fresh.loaded, fresh.signed
	return nil
}

// NewGuard reads the baseline manifest and, when a key is given, verifies its
// signature. A missing manifest is not an error: it leaves a Guard that
// verifies nothing and says so. A manifest that is present but unsafe on disk,
// or whose signature does not verify against a pinned key, is an error — at
// that point the baseline is not evidence of anything.
func NewGuard(manifestPath string, pub ed25519.PublicKey) (*Guard, error) {
	g := &Guard{path: manifestPath, pub: pub}
	if manifestPath == "" {
		return g, nil
	}
	if _, err := os.Lstat(manifestPath); errors.Is(err, os.ErrNotExist) {
		return g, nil
	}
	// The manifest is the thing every other check is measured against, so it
	// gets the same scrutiny as the files it describes.
	if err := CheckFile(manifestPath); err != nil {
		return g, err
	}
	man, err := selftest.ReadManifest(manifestPath)
	if err != nil {
		return g, fmt.Errorf("trust: baseline %s: %w", manifestPath, err)
	}
	g.man, g.loaded = man, true
	if len(pub) > 0 {
		if err := man.VerifySignature(pub); err != nil {
			return g, fmt.Errorf("trust: baseline %s: %w", manifestPath, err)
		}
		g.signed = true
	}
	return g, nil
}

// Loaded reports whether a baseline was found.
func (g *Guard) Loaded() bool { return g != nil && g.loaded }

// Signed reports whether the baseline's signature was verified against a
// pinned key.
func (g *Guard) Signed() bool { return g != nil && g.signed }

// Path is where the baseline was read from.
func (g *Guard) Path() string {
	if g == nil {
		return ""
	}
	return g.path
}

// Manifest is the baseline as read.
func (g *Guard) Manifest() selftest.Manifest {
	if g == nil {
		return selftest.Manifest{}
	}
	return g.man
}

// Pin returns a signed configuration value.
func (g *Guard) Pin(name string) (string, bool) {
	if !g.Loaded() {
		return "", false
	}
	return g.man.Pin(name)
}

// Covers reports whether the baseline recorded this resource.
func (g *Guard) Covers(name string) bool {
	if !g.Loaded() {
		return false
	}
	_, ok := g.man.Lookup(name)
	return ok
}

// VerifyResource checks one named resource against the baseline. It returns a
// reason when the resource no longer matches, and "" when it does, was never
// recorded, or there is no baseline to compare against. Those last two are not
// failures: a host with nothing recorded is unverified, not compromised, and
// saying otherwise would make the alert worthless.
func (g *Guard) VerifyResource(name string) (reason string, err error) {
	if !g.Loaded() {
		return "", nil
	}
	drift, covered, err := selftest.VerifyOne(g.man, name)
	if err != nil || !covered {
		return "", err
	}
	return drift.Reason, nil
}

// VerifyFile checks the file the caller is about to read: that it is safe where
// it sits, that the baseline actually covers it, and that its contents still
// match. The returned reason is empty when the file is trustworthy.
//
// It digests path rather than the path recorded in the baseline, and that
// distinction is the whole point. Hashing the recorded path would answer a
// question nobody asked: an attacker who edits `feed =` in the configuration,
// or passes --feed, leaves the baselined file untouched, so its digest still
// matches while the agent reads a different file entirely. A redirected path is
// therefore reported, not verified — the baseline describes one file, and a
// digest of it says nothing about any other.
func (g *Guard) VerifyFile(name, path string) (reason string, err error) {
	if path != "" {
		if err := CheckFile(path); err != nil {
			return err.Error(), nil
		}
	}
	if !g.Loaded() {
		return "", nil
	}
	if path == "" {
		return g.VerifyResource(name)
	}
	want, ok := g.man.Lookup(name)
	if !ok {
		return "", nil
	}
	if want.Path != path {
		return "the agent is reading " + path + " but the baseline covers " + want.Path +
			": a redirected path is not vouched for by the digest of the file it no longer reads", nil
	}
	got, _, _, err := selftest.Digest(path)
	if errors.Is(err, os.ErrNotExist) {
		return "resource missing on disk: " + path, nil
	}
	if err != nil {
		return "", err
	}
	if got != want.SHA256 {
		return "content changed since the baseline", nil
	}
	return "", nil
}
