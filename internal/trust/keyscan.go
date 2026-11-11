package trust

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/safefs"
)

// maxKeyFileSize bounds what is even considered. A hex Ed25519 private key is
// 64 or 128 characters, so anything larger is not one, and this keeps the scan
// from reading a log or a database by accident.
const maxKeyFileSize = 512

// SigningKeysNearby reports files in the given directories that look like
// Ed25519 private keys.
//
// It exists because a signed baseline is only worth more than an unsigned one
// while the private key is somewhere the attacker is not. A key left in
// /etc/cau next to the manifest it signed reduces the signed case to the
// unsigned one exactly: whoever rewrites the content signs their own baseline
// over it and every check still passes. That is the single most likely way for
// this feature to be worth nothing in practice, it is invisible from the
// outside, and an operator who did it was usually trying to be helpful. So the
// agent looks, once, and says so, rather than leaving the strongest guarantee
// it offers silently hollow.
//
// It reports rather than refuses: the key may be a decoy, a test fixture or a
// public key with a confusing name, and a security tool that will not start
// because of a file it found is its own kind of outage.
func SigningKeysNearby(dirs ...string) []string {
	seen := map[string]bool{}
	var found []string
	for _, dir := range dirs {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		// A directory that is absent or unreadable holds no key we could find,
		// and saying so for every host without an /etc/cau would be noise.
		if err != nil { // audit:ok an absent or unreadable dir holds no key to find; reporting it on every host would be noise
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil || info.Size() == 0 || info.Size() > maxKeyFileSize {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if looksLikePrivateKey(path) {
				found = append(found, path)
			}
		}
	}
	return found
}

// looksLikePrivateKey reports whether a file's whole contents are hex of an
// Ed25519 seed or private key length. A public key is 32 bytes too, so a seed
// and a public key are indistinguishable by length alone; the private-key
// length (64 bytes) is unambiguous, and for 32 bytes this can only say "looks
// like" rather than "is".
//
// It reads through safefs rather than os.ReadFile, bounded and refusing to
// follow a symlink, because this walks a directory an attacker may be able to
// write to. The earlier size check is not protection: it is a stat before an
// open, so the file can change in between, and a FIFO reports a size of zero
// and would sail through it — after which an unbounded read blocks forever on a
// writer that never comes. A named pipe called priv.hex in /etc/cau would
// otherwise hang the daemon at startup, which is a denial of service dressed
// as a hardening check.
//
// Non-regular files are refused outright here, which is deliberately stricter
// than safefs.ReadOperatorFile, where a pipe is allowed so that
// `--sign-key <(pass show cau/key)` can keep a key off disk entirely. The
// difference is who named the path: there the operator did, and a pipe is a
// reasonable thing for them to mean; here the agent is walking a directory and
// reading whatever it finds, so anything that is not an ordinary file is
// something nobody asked it to read.
func looksLikePrivateKey(path string) bool {
	b, fi, err := safefs.ReadFileNoFollow(path, maxKeyFileSize)
	// An unreadable or non-regular file is simply not a key we can identify,
	// which is the same answer as "no key here" and needs no record of its own:
	// this function's whole contract is a yes-or-no guess. audit:ok
	if err != nil || fi == nil || !fi.Mode().IsRegular() {
		return false
	}
	s := strings.TrimSpace(string(b))
	if len(s) != 64 && len(s) != 128 {
		return false
	}
	_, err = hex.DecodeString(s)
	return err == nil
}
