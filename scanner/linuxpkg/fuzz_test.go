package linuxpkg

import "testing"

// FuzzAnalyze drives the package parsers (ar, RPM headers, tar, compressed
// members) from their magics. The input is a package an attacker built, so the
// invariant is the same as every other format's: no panic, whatever the bytes.
func FuzzAnalyze(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("!<arch>\ndebian-binary   0           0     0     100644  4         `\n2.0\n"))
	f.Add([]byte("!<arch>\ncontrol.tar.gz  0           0     0     100644  9999999999`\n"))
	f.Add(append([]byte{0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0}, make([]byte, 200)...))
	f.Add(append(append(make([]byte, 96), 0x8e, 0xad, 0xe8, 1), make([]byte, 64)...))
	f.Add([]byte("#!/bin/sh\npkgname=x\nsource=(http://x)\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		Analyze(data, Options{})
	})
}
