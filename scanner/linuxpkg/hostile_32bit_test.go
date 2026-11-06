package linuxpkg

import (
	"bytes"
	"fmt"
	"testing"
)

// A ten-digit ar size overflows a 32-bit int, which debian/control's
// "Architecture: any" allows.
func TestArMemberSizeOverflowingInt(t *testing.T) {
	hdr := fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10s`\n", "control.tar.gz", "0", "0", "0", "100644", "4294967000")
	members, note := readAr(append(append(append([]byte(nil), magicDeb...), hdr...), bytes.Repeat([]byte("x"), 64)...))
	if len(members) != 0 || note == "" {
		t.Fatalf("members %d, note %q", len(members), note)
	}
}

func TestRPMEntryOffsetOverflowingInt(t *testing.T) {
	store := bytes.Repeat([]byte("x"), 16)
	if got := rpmString(store, rpmEntry{typ: rpmTypeString, offset: 0x90000000}); got != "" {
		t.Fatalf("got %q", got)
	}
}
