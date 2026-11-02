// Package resources resolves the engine's on-disk resources (signature
// database, YARA rules, fuzzy database) across the locations a `cau` binary
// may be invoked from: a dev checkout, an FHS install under /usr, or an
// explicit flag or environment override.
//
// The search order is:
//
//  1. an explicit value (a --db / --rules flag)
//  2. the environment (CAU_SIGNATURES / CAU_RULES / CAU_FUZZY)
//  3. next to the binary                      (<exe dir>/signatures/hashes.txt)
//  4. the FHS share dir relative to the binary (<exe dir>/../share/cau/...)
//  5. /usr/local/share/cau and /usr/share/cau
//  6. the current working directory
//
// The first existing path wins; when nothing is found the full search list is
// returned so the caller can report an actionable error.
//
// Both the `cau` CLI and the `cau-mcp` server resolve resources through this
// package so their discovery behaviour stays identical.
package resources

import (
	"os"
	"path/filepath"
)

// Environment variables that override resource discovery.
const (
	EnvSignatures = "CAU_SIGNATURES"
	EnvRules      = "CAU_RULES"
	EnvFuzzy      = "CAU_FUZZY"
)

// Relative paths, resolved against each search root.
const (
	RelSignatures = "signatures/hashes.txt"
	RelRules      = "rules"
	RelFuzzy      = "signatures/fuzzy.txt"
)

// Roots returns the directories searched for a resource, in priority order,
// with duplicates and empty entries removed.
func Roots() []string {
	var roots []string
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		dir := filepath.Dir(exe)
		roots = append(roots, dir, filepath.Join(dir, "..", "share", "cau"))
	}
	roots = append(roots, "/usr/local/share/cau", "/usr/share/cau")
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}

	seen := make(map[string]bool, len(roots))
	out := roots[:0]
	for _, r := range roots {
		r = filepath.Clean(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// Find resolves a resource. explicit is the flag value ("" when the flag was
// not given), env is the environment variable to consult, and rel is the
// relative path to look for under each root. It returns the chosen path and,
// when nothing was found, the list of locations that were tried.
func Find(explicit, env, rel string) (path string, searched []string) {
	if explicit != "" {
		return explicit, nil
	}
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	for _, root := range Roots() {
		candidate := filepath.Join(root, filepath.FromSlash(rel))
		searched = append(searched, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", searched
}
