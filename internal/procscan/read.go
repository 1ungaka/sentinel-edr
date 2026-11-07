package procscan

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readProc reads the public /proc fields for one pid into a rawProc. It is
// best-effort: any field this user may not read (another user's process without
// root) is simply left empty. It returns ok=false only when the process has
// vanished entirely (its directory is gone), so a live-but-restricted process is
// still scored on whatever is readable (comm, cmdline are world-readable).
//
// A field longer than its cap is read up to the cap and recorded as truncated
// in rp.partial, so the scan can say which processes were only partly read.
func readProc(root string, pid int) (rawProc, bool) {
	base := filepath.Join(root, strconv.Itoa(pid))
	if _, err := os.Stat(base); err != nil {
		return rawProc{}, false
	}
	rp := rawProc{pid: pid}

	rp.comm = strings.TrimRight(readSmall(filepath.Join(base, "comm"), 256), "\n")

	if target, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		rp.exeTarget = target
	} else {
		rp.exeErr = true
	}

	raw, hit := readSmall2(filepath.Join(base, "cmdline"), maxCmdlineByte)
	if hit {
		// The command line was cut, whether or not the bytes kept parsed: the
		// argv past the cap was never read.
		rp.truncated("cmdline")
	}
	if raw != "" {
		args := splitNUL(raw)
		if len(args) > 0 {
			rp.argv0 = args[0]
		}
		rp.cmdline = strings.Join(args, " ")
	}

	var mapsTruncated bool
	rp.libs, rp.anonRWX, mapsTruncated = mappedFiles(filepath.Join(base, "maps"))
	if mapsTruncated {
		rp.truncated("maps")
	}
	if isInterpreter(rp.comm) {
		// One peer on both descriptors is a shell; two different ones is
		// reported as the split it is and never as the shell it is not.
		if peer, in, out := stdioWiring(base); peer != "" {
			rp.stdioPeer = peer
		} else if in != "" && out != "" {
			rp.stdioSplit = in + " -> " + out
		}
	}
	if isInterpreter(rp.comm) || isRelayTool(rp.comm) {
		rp.stdin, _ = readlink(filepath.Join(base, "fd", "0"))
		rp.stdout, _ = readlink(filepath.Join(base, "fd", "1"))
		if fi, err := os.Stat(filepath.Join(base, "fd", "0")); err == nil {
			rp.stdinFIFO = fi.Mode()&os.ModeNamedPipe != 0
		}
	}

	envRaw, envHit := readSmall2(filepath.Join(base, "environ"), maxEnvironByte)
	for _, kv := range splitNUL(envRaw) {
		if v, ok := strings.CutPrefix(kv, "LD_PRELOAD="); ok {
			rp.preload = v
		} else if v, ok := strings.CutPrefix(kv, "LD_LIBRARY_PATH="); ok {
			rp.libpath = v
		}
	}
	if envHit {
		rp.truncated("environ")
	}

	parseStatus(filepath.Join(base, "status"), &rp)
	rp.startTicks = parseStartTicks(readSmall(filepath.Join(base, "stat"), 4096))
	return rp, true
}

// parseStartTicks returns the starttime field of a /proc/<pid>/stat line, or 0
// when there is none. The count starts after the last ')': comm comes before it
// and a program chooses its own, spaces and parentheses included.
func parseStartTicks(stat string) uint64 {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0
	}
	const startTimeField = 19 // field 22 of the line; state, field 3, is index 0 here
	f := strings.Fields(stat[i+1:])
	if len(f) <= startTimeField {
		return 0
	}
	n, err := strconv.ParseUint(f[startTimeField], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// readSmall reads at most max bytes from a /proc file, returning "" when nothing
// could be read (the file may be restricted or the process may have exited). It
// reads to EOF because maps and net/tcp are seq_files, which hand back a page per
// read: one read saw 27 of 40 sockets on the development host. A process exiting
// partway through keeps what was already read.
func readSmall(path string, max int) string {
	b, _ := readSmall2(path, max)
	return b
}

// readSmall2 is readSmall plus whether the byte limit was reached. A /proc file
// longer than max is cut there, so exactly max bytes read means the rest is
// still unread: argv past the command-line cap, an LD_PRELOAD past the
// environment cap, or a mapping past the maps cap are all in that rest.
func readSmall2(path string, max int) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, int64(max)))
	return string(b), len(b) == max
}

// truncated records one field of one process that was cut at a cap, so the
// scan can say what it did not see instead of reporting the process whole.
func (rp *rawProc) truncated(field string) {
	if rp.partial == nil {
		rp.partial = map[string]bool{}
	}
	rp.partial[field] = true
}

func splitNUL(s string) []string {
	s = strings.TrimRight(s, "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// mappedFiles returns the distinct file-backed pathnames from a maps file, the
// number of anonymous writable-and-executable mappings, and whether the caps
// (maxMapsBytes of read, maxMappedEntries of pathnames) were reached. A mapping
// past either cap is not inspected, and a caller that does not say so reports a
// process as fully mapped that was not.
func mappedFiles(path string) (libs []string, anonRWX int, truncated bool) {
	raw, hit := readSmall2(path, maxMapsBytes)
	if raw == "" {
		return nil, 0, false
	}
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		// address perms offset dev inode pathname — the pathname is after the
		// 5th field and may contain spaces (e.g. " (deleted)").
		fields := strings.Fields(line)
		if len(fields) == 5 && strings.HasPrefix(fields[1], "rwx") {
			anonRWX++
		}
		if len(fields) < 6 {
			continue
		}
		idx := strings.Index(line, fields[4])
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len(fields[4]):])
		if rest == "" || strings.HasPrefix(rest, "[") {
			continue // anonymous or special ([heap], [stack], [vdso]…)
		}
		if !seen[rest] {
			seen[rest] = true
			out = append(out, rest)
		}
		if len(out) >= maxMappedEntries {
			truncated = true
			break
		}
	}
	return out, anonRWX, truncated || hit
}

func readlink(path string) (string, error) { return os.Readlink(path) }

func parseStatus(path string, rp *rawProc) {
	for _, line := range strings.Split(readSmall(path, 64<<10), "\n") {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			rp.ppid, _ = strconv.Atoi(strings.TrimSpace(v))
		} else if v, ok := strings.CutPrefix(line, "TracerPid:"); ok {
			rp.tracerPID, _ = strconv.Atoi(strings.TrimSpace(v))
		} else if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) >= 2 {
				r, rerr := strconv.Atoi(f[0])
				e, eerr := strconv.Atoi(f[1])
				if rerr == nil && eerr == nil {
					rp.ruid, rp.euid, rp.hasUID = r, e, true
				}
			}
		}
	}
}
