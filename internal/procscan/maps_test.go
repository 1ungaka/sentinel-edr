package procscan

import (
	"os"
	"path/filepath"
	"testing"
)

// A maps line is: address perms offset dev inode pathname, and the pathname
// may contain spaces (" (deleted)"). The pathname must be taken as the sixth
// field, not found by searching for the inode number: the hexadecimal address
// range in front of it routinely contains the inode's decimal digits (a tmpfs
// inode is 1, 2, 3…), and a search finds the wrong place.
//
// The consequence of getting it wrong is a detection that does not fire: a
// shared object mapped from a world-writable directory stops looking like one,
// so the library-injection check is defeated by the file's location alone.
func TestMappedFilesReadsThePathname(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "maps")
	body := "" +
		"7f8a4c001000-7f8a4c003000 r-xp 00000000 08:01 3       /dev/shm/evil.so\n" +
		"7f8a4c004000-7f8a4c006000 r-xp 00000000 08:01 12      /tmp/other.so\n" +
		"55d1b2c00000-55d1b2c21000 r-xp 00000000 fd:00 1442929    /usr/lib/x86_64-linux-gnu/libc.so.6\n" +
		"55d1b2c22000-55d1b2c41000 r-xp 00000000 fd:00 1442930    /tmp/has space.so (deleted)\n" +
		"7ffd1c000000-7ffd1c021000 rw-p 00000000 00:00 0 \n" +
		"7ffd1c400000-7ffd1c421000 rwxp 00000000 00:00 0 \n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	libs, anonRWX, _ := mappedFiles(path)
	want := []string{
		"/dev/shm/evil.so",
		"/tmp/other.so",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/tmp/has space.so (deleted)",
	}
	if len(libs) != len(want) {
		t.Fatalf("got %d pathnames %q, want %d", len(libs), libs, len(want))
	}
	for i := range want {
		if libs[i] != want[i] {
			t.Errorf("pathname %d = %q, want %q", i, libs[i], want[i])
		}
	}
	if anonRWX != 1 {
		t.Errorf("anonymous writable-executable mappings = %d, want 1", anonRWX)
	}
	// The whole point: a library out of a world-writable directory still looks
	// like one.
	if !suspiciousLibPath("/dev/shm/evil.so") {
		t.Error("a library mapped from /dev/shm is not suspicious")
	}
}
