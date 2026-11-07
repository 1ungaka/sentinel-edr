package lzma

import "testing"

func TestTmpDebug(t *testing.T) {
	stream := fixture(t, "text.crc32.xz")
	hdrLen := (int(stream[12]) + 1) * 4
	t.Logf("hdr % x", stream[12:12+hdrLen])
	idx := findIndex(stream)
	t.Logf("index % x", stream[idx:len(stream)-12])
	sized := withSizes(t, stream, 3, uint64(len(fixture(t, "text.raw"))))
	h2 := (int(sized[12]) + 1) * 4
	t.Logf("new hdr % x", sized[12:12+h2])
	t.Logf("new index % x", sized[findIndex(sized):len(sized)-12])
	_, rep, err := DecodeReport(sized, 1<<20)
	t.Logf("%v %+v", err, rep)
}
