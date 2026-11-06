package uefi

import (
	"encoding/binary"
	"testing"
)

// A volume length that survives int() as a huge positive value sent findFV past
// the end of the buffer, where its own off+0x2c check wrapped and the read at a
// negative offset panicked, aborting the file's scan.
func TestVolumeLengthNearMaxIntDoesNotPanic(t *testing.T) {
	for _, fvLen := range []uint64{1<<63 - 16, 1<<63 - 1, 1 << 63, ^uint64(0)} {
		fw := buildFirmware(ffsFile(guid16(0x11), 0x07, section(0x10, []byte("MZ"))))
		binary.LittleEndian.PutUint64(fw[0x20:], fvLen)
		if r := Analyze(fw, Options{}); r == nil || r.Parsed == nil {
			t.Fatalf("fvLen %#x: firmware image not parsed", fvLen)
		}
	}
}
