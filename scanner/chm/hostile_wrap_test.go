package chm

import (
	"encoding/binary"
	"testing"
)

// A directory offset near 2^64 makes dirOff+0x54 wrap to a small number, so the
// bounds check passed and data[dirOff:] panicked, aborting the file's scan.
func TestDirectoryOffsetThatWrapsIsRejected(t *testing.T) {
	data := buildCHM(t, []string{"/index.html"})
	binary.LittleEndian.PutUint64(data[0x48:], ^uint64(0)-0x10)

	names, truncated := enumerate(data)
	if len(names) != 0 || !truncated {
		t.Fatalf("enumerate = %d names, truncated=%v; want none, truncated", len(names), truncated)
	}
}
