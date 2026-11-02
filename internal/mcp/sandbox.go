package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Sandbox confines the file-touching tools. An MCP client is, sooner or later,
// an autonomous agent that will point a scanner at `/`; the sandbox is the
// line between "scan this directory" and "read every file on the host".
//
// It enforces three of the Phase 3 non-negotiables:
//
//   - Path confinement: every path a tool touches must resolve, with all
//     symlinks followed, to a location inside one of the configured roots. A
//     symlink inside a root that points outside it is rejected, not followed.
//   - Size caps: files larger than MaxBytes are refused before being read.
//   - Bounded enumeration: a directory with more than MaxDirFiles regular
//     files is refused rather than walked, so one tool call cannot fan out
//     across an entire filesystem.
//
// Resolve follows every symlink with EvalSymlinks and re-checks containment on
// the real path, so a component swapped for an out-of-root symlink after the
// check cannot widen access: the resolved path is what callers open.
type Sandbox struct {
	roots       []string // absolute, symlink-resolved, cleaned
	maxBytes    int64
	maxDirFiles int
}

// SandboxConfig configures a Sandbox. Roots that do not exist or cannot be
// resolved are dropped with a note in the returned warnings.
type SandboxConfig struct {
	Roots       []string
	MaxBytes    int64
	MaxDirFiles int
}

// Defaults for a sandbox when the caller passes zero values.
const (
	DefaultMaxBytes    int64 = 256 << 20 // 256 MiB
	DefaultMaxDirFiles       = 10000
)

// NewSandbox builds a sandbox from the config. It returns the sandbox, any
// per-root warnings (a root that could not be resolved), and an error only
// when no usable root remains while roots were requested.
func NewSandbox(cfg SandboxConfig) (*Sandbox, []string, error) {
	s := &Sandbox{
		maxBytes:    cfg.MaxBytes,
		maxDirFiles: cfg.MaxDirFiles,
	}
	if s.maxBytes <= 0 {
		s.maxBytes = DefaultMaxBytes
	}
	if s.maxDirFiles <= 0 {
		s.maxDirFiles = DefaultMaxDirFiles
	}

	var warnings []string
	seen := make(map[string]bool)
	for _, r := range cfg.Roots {
		if strings.TrimSpace(r) == "" {
			continue
		}
		abs, err := filepath.Abs(r)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("root %q: %v", r, err))
			continue
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("root %q: %v", r, err))
			continue
		}
		real = filepath.Clean(real)
		if seen[real] {
			continue
		}
		seen[real] = true
		s.roots = append(s.roots, real)
	}

	if len(cfg.Roots) > 0 && len(s.roots) == 0 {
		return nil, warnings, fmt.Errorf("no usable scan root (all %d requested roots failed to resolve)", len(cfg.Roots))
	}
	return s, warnings, nil
}

// MaxBytes is the per-file size cap.
func (s *Sandbox) MaxBytes() int64 { return s.maxBytes }

// Roots returns the resolved roots (a copy), for diagnostics.
func (s *Sandbox) Roots() []string {
	out := make([]string, len(s.roots))
	copy(out, s.roots)
	return out
}

// contains reports whether real (already an absolute, cleaned, symlink-free
// path) is inside one of the roots. A path equal to a root, or under it with a
// separator boundary, is contained; "/a/bc" is not inside root "/a/b".
func (s *Sandbox) contains(real string) bool {
	for _, root := range s.roots {
		if real == root {
			return true
		}
		if strings.HasPrefix(real, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// Resolve validates path and returns its real (symlink-resolved) location
// inside a root. It is the single choke point for file access: it rejects
// anything that resolves outside the allowlist. When no roots are configured
// every path is rejected, so the hash/rule tools still work while the
// file-reading tools are effectively disabled.
func (s *Sandbox) Resolve(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("empty path")
	}
	if len(s.roots) == 0 {
		return "", fmt.Errorf("file access is disabled: no scan root is configured")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	real = filepath.Clean(real)
	if !s.contains(real) {
		return "", fmt.Errorf("path %q is outside the allowed scan roots", path)
	}
	return real, nil
}

// ResolveFile resolves path, requires it to be a regular file, and enforces
// the size cap. It returns the real path and its size.
func (s *Sandbox) ResolveFile(path string) (real string, size int64, err error) {
	real, err = s.Resolve(path)
	if err != nil {
		return "", 0, err
	}
	info, err := os.Lstat(real)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("not a regular file: %q", path)
	}
	if info.Size() > s.maxBytes {
		return "", 0, fmt.Errorf("file is %d bytes, over the %d-byte sandbox cap", info.Size(), s.maxBytes)
	}
	return real, info.Size(), nil
}

// ResolveDir resolves path, requires it to be a directory, and refuses it if
// it holds more than MaxDirFiles regular files. The count walk is bounded: it
// stops the moment the cap is exceeded and never follows directory symlinks.
func (s *Sandbox) ResolveDir(path string) (real string, files int, err error) {
	real, err = s.Resolve(path)
	if err != nil {
		return "", 0, err
	}
	info, err := os.Lstat(real)
	if err != nil {
		return "", 0, err
	}
	if !info.IsDir() {
		return "", 0, fmt.Errorf("not a directory: %q", path)
	}
	count := 0
	over := false
	walkErr := filepath.WalkDir(real, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries; the scan reports them per-file
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil // symlinks are never followed
		}
		if d.Type().IsRegular() {
			count++
			if count > s.maxDirFiles {
				over = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	if walkErr != nil {
		return "", 0, walkErr
	}
	if over {
		return "", 0, fmt.Errorf("directory holds more than %d files; narrow the scan or raise the sandbox cap", s.maxDirFiles)
	}
	return real, count, nil
}
