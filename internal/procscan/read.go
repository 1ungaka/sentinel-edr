package procscan

import (
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

	if raw := readSmall(filepath.Join(base, "cmdline"), maxCmdlineByte); raw != "" {
		args := splitNUL(raw)
		if len(args) > 0 {
			rp.argv0 = args[0]
		}
		rp.cmdline = strings.Join(args, " ")
	}

	rp.libs = mappedFiles(filepath.Join(base, "maps"))

	for _, kv := range splitNUL(readSmall(filepath.Join(base, "environ"), maxEnvironByte)) {
		if v, ok := strings.CutPrefix(kv, "LD_PRELOAD="); ok {
			rp.preload = v
		} else if v, ok := strings.CutPrefix(kv, "LD_LIBRARY_PATH="); ok {
			rp.libpath = v
		}
	}

	parseStatus(filepath.Join(base, "status"), &rp)
	return rp, true
}

// readSmall reads at most max bytes from a /proc file, returning "" on any error
// (the file may be restricted or the process may have exited).
func readSmall(path string, max int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

func splitNUL(s string) []string {
	s = strings.TrimRight(s, "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// mappedFiles returns the distinct file-backed pathnames from a maps file,
// bounded by maxMapsBytes.
func mappedFiles(path string) []string {
	raw := readSmall(path, maxMapsBytes)
	if raw == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		// address perms offset dev inode pathname — the pathname is after the
		// 5th field and may contain spaces (e.g. " (deleted)").
		fields := strings.Fields(line)
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
		if len(out) >= 4096 {
			break
		}
	}
	return out
}

func parseStatus(path string, rp *rawProc) {
	for _, line := range strings.Split(readSmall(path, 64<<10), "\n") {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			rp.ppid, _ = strconv.Atoi(strings.TrimSpace(v))
		} else if v, ok := strings.CutPrefix(line, "TracerPid:"); ok {
			rp.tracerPID, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
}
