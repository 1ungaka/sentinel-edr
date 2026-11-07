// Package trust holds the agent's configuration and the rules that decide
// whether a file on disk is worth believing.
//
// The agent is meant to be installed once and left running, which means its
// behaviour is decided by files, not by someone at a terminal. That makes those
// files a target: an attacker who can rewrite one line of configuration can
// redirect the incident stream to themselves, or point the agent at an empty
// threat feed, and nothing about the running daemon would look wrong. So a file
// this package loads has to earn it twice:
//
//   - Before it is read, by how it sits on disk. A configuration or feed file
//     that is a symlink, or writable by a group or by everyone, or owned by
//     somebody who is not the owner of the agent, is refused outright. Those
//     are not style preferences; each one is a way to change the file's
//     contents later without ever touching the file the agent checked.
//   - After it is read, by matching the signed baseline. That part lives in
//     internal/selftest, which records a digest per resource and an Ed25519
//     signature over the lot, plus pins for the settings that are not files.
//
// What this package deliberately does not do is let a failed check disable the
// agent. Refusing to run because a rules file changed would hand an attacker a
// one-file kill switch for the defence, which is a worse outcome than running
// on content that is one revision stale. Every caller here keeps the last known
// good value and raises the tamper as an incident instead.
package trust

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultConfigPath is where the packages install the agent's configuration.
const DefaultConfigPath = "/etc/cau/cau.conf"

// DefaultSIEMPort is the Wazuh Manager API port, so an operator can write an
// address with no port and mean the obvious thing.
const DefaultSIEMPort = "55000"

// Errors a caller can branch on.
var (
	// ErrUnsafePath means the file cannot be trusted as it sits on disk,
	// regardless of its contents.
	ErrUnsafePath = errors.New("trust: file is not safe to read")
)

// Config is the agent's configuration. A zero value is valid and means "no
// configuration file", which is how the agent runs on a host where nobody has
// written one.
type Config struct {
	// Path is where this came from, or "" for defaults only.
	Path string

	// SIEM is the address incidents are forwarded to: an IP, a host, either
	// with a port, or a full URL. Empty means forwarding is off.
	SIEM            string
	SIEMUser        string
	SIEMPasswordEnv string
	SIEMCA          string
	SIEMInsecure    bool
	// SIEMCertPins are SHA-256 public-key pins for the manager. Several may be
	// listed, comma-separated, so a key can be rotated without an outage.
	SIEMCertPins []string

	// Response policy. Respond is "", "stop", "kill" or "none".
	Respond    string
	Quarantine *bool
	BlockExe   *bool
	Netblock   *bool
	ReportOnly *bool

	// Feed is the threat-intel feed path, when it is not the default.
	Feed string

	// Unknown keys, kept so the caller can warn rather than silently ignore a
	// typo in a file nobody is watching.
	Unknown []string
}

// LoadConfig reads a configuration file. A missing file is not an error: it
// returns a zero Config, because running without one is normal. A file that
// exists but cannot be trusted is an error, because quietly falling back to
// defaults is exactly what an attacker who made it unreadable would want.
func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err := CheckFile(path); err != nil {
		return Config{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("trust: open %s: %w", path, err)
	}
	defer f.Close()
	cfg, err := parseConfig(f)
	if err != nil {
		return Config{}, fmt.Errorf("trust: %s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// parseConfig reads key = value lines. '#' starts a comment.
func parseConfig(r io.Reader) (Config, error) {
	var cfg Config
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return cfg, fmt.Errorf("line %d: expected key = value", line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if err := cfg.set(key, value); err != nil {
			return cfg, fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) set(key, value string) error {
	boolean := func(dst **bool) error {
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s: %q is not a boolean", key, value)
		}
		*dst = &b
		return nil
	}
	switch key {
	case "siem":
		c.SIEM = value
	case "siem-user":
		c.SIEMUser = value
	case "siem-password-env":
		c.SIEMPasswordEnv = value
	case "siem-ca":
		c.SIEMCA = value
	case "siem-cert-pin":
		for _, p := range strings.Split(value, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.SIEMCertPins = append(c.SIEMCertPins, p)
			}
		}
	case "siem-insecure":
		var b *bool
		if err := boolean(&b); err != nil {
			return err
		}
		c.SIEMInsecure = *b
	case "respond":
		switch value {
		case "stop", "kill", "none", "":
			c.Respond = value
		default:
			return fmt.Errorf("respond: %q is not stop, kill or none", value)
		}
	case "quarantine":
		return boolean(&c.Quarantine)
	case "block-exe":
		return boolean(&c.BlockExe)
	case "netblock":
		return boolean(&c.Netblock)
	case "report-only":
		return boolean(&c.ReportOnly)
	case "feed":
		c.Feed = value
	default:
		c.Unknown = append(c.Unknown, key)
	}
	return nil
}

// SIEMURL turns a configured address into the API base URL the forwarder wants.
// An address with a scheme is taken as given; anything else becomes https with
// the manager's default port, so "10.0.0.5" is enough to configure forwarding.
func SIEMURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.Contains(addr, "://") {
		return strings.TrimRight(addr, "/")
	}
	if !hasPort(addr) {
		addr = joinHostPort(addr, DefaultSIEMPort)
	}
	return "https://" + addr
}

// hasPort reports whether addr already carries a port, handling the bracketed
// IPv6 form. A bare IPv6 address has colons but no port, which is why this is
// not just a check for ':'.
func hasPort(addr string) bool {
	if strings.HasPrefix(addr, "[") {
		return strings.Contains(addr[strings.LastIndexByte(addr, ']')+1:], ":")
	}
	return strings.Count(addr, ":") == 1
}

// joinHostPort brackets a bare IPv6 address. net.JoinHostPort is not used so
// this package pulls in no networking.
func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// CheckFile reports whether a file is safe for the agent to believe.
//
// Each rule closes a way to change what the agent reads without changing the
// file it checked:
//
//   - A symlink is refused because the target can be repointed afterwards, and
//     because the link may lead somewhere the agent would not have looked.
//   - A non-regular file is refused: a fifo or device hands back whatever its
//     writer chooses, and can block the reader for as long as it likes.
//   - Group- or world-writable is refused, since that is a standing invitation
//     to rewrite the contents later.
//   - An owner other than root or the agent's own user is refused, because that
//     user can rewrite it at will.
//
// The directory holding the file is checked for the same write bits: being able
// to replace a file is as good as being able to edit it.
func CheckFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnsafePath, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink, whose target can be repointed after this check", ErrUnsafePath, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, path)
	}
	if err := checkWritable(path, info); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	dinfo, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnsafePath, dir, err)
	}
	// A sticky directory (/tmp) lets only the owner replace their own file, so
	// the write bits there do not mean what they mean elsewhere.
	if dinfo.Mode()&os.ModeSticky == 0 {
		if err := checkWritable(dir, dinfo); err != nil {
			return err
		}
	}
	return nil
}

// checkWritable refuses a path that someone other than the agent's own identity
// could rewrite.
//
// World-writable is always wrong. Group-writable is only refused when the agent
// is running as root, which is how it runs in production: a group-writable file
// under /etc is a way for a non-root group member to change what root believes.
// Run as an ordinary user — a developer, a test, a per-user install — the
// agent's own files routinely sit in a 0775 home or temp directory whose group
// is that user's private group, and on a distribution with a umask of 002 that
// is simply what a directory looks like. Refusing those would make the check
// unusable without making a single host safer, so the strict rule is applied
// exactly where it buys something.
func checkWritable(path string, info os.FileInfo) error {
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return fmt.Errorf("%w: %s is world-writable (mode %04o)", ErrUnsafePath, path, perm)
	}
	root := os.Geteuid() == 0
	if root && perm&0o020 != 0 {
		return fmt.Errorf("%w: %s is group-writable (mode %04o), so a non-root group member can change what the agent reads", ErrUnsafePath, path, perm)
	}
	uid, ok := ownerUID(info)
	if !ok {
		return nil // an OS that does not report an owner; the mode checks stand
	}
	if uid != 0 && uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%w: %s is owned by uid %d, which is neither root nor this process", ErrUnsafePath, path, uid)
	}
	return nil
}
