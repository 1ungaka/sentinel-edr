package tradecraft

import (
	"bytes"
	"fmt"
	"math/bits"
	"strings"
)

// pattern is a byte sequence with wildcards: -1 matches any byte.
type pattern []int16

func hexPattern(s string) pattern {
	f := strings.Fields(s)
	out := make(pattern, len(f))
	for i, tok := range f {
		if tok == "??" {
			out[i] = -1
			continue
		}
		var v int16
		if _, err := fmt.Sscanf(tok, "%x", &v); err != nil {
			panic("tradecraft: bad byte pattern " + s)
		}
		out[i] = v
	}
	return out
}

// find returns the offsets of p in data. The leading literal run is the anchor,
// so a wildcard costs nothing until the literal prefix has matched.
func (p pattern) find(data []byte, limit int) []int {
	n := 0
	for n < len(p) && p[n] >= 0 {
		n++
	}
	anchor := make([]byte, n)
	for i := 0; i < n; i++ {
		anchor[i] = byte(p[i])
	}
	var out []int
	for off := 0; off+len(p) <= len(data); {
		i := bytes.Index(data[off:], anchor)
		if i < 0 {
			break
		}
		at := off + i
		off = at + 1
		if at+len(p) > len(data) {
			break
		}
		ok := true
		for j := n; j < len(p); j++ {
			if p[j] >= 0 && byte(p[j]) != data[at+j] {
				ok = false
				break
			}
		}
		if ok {
			if out = append(out, at); len(out) >= limit {
				break
			}
		}
	}
	return out
}

// pebWalks are the instruction sequences that follow PEB -> Ldr -> module list:
// how code with no import table finds kernel32. x86 reads fs:[30h], x64 gs:[60h].
var pebWalks = []pattern{
	hexPattern("64 8B ?? 30 8B ?? 0C 8B ?? ??"),
	hexPattern("64 8B ?? 30 00 00 00 8B ?? 0C 8B ?? ??"),
	hexPattern("64 A1 30 00 00 00 8B ?? 0C 8B ?? ??"),
	hexPattern("65 48 8B ?? 60 48 8B ?? 18 48 8B ?? ??"),
	hexPattern("65 48 8B ?? 25 60 00 00 00 48 8B ?? 18 48 8B ?? ??"),
}

// hashLoopNear reports a rotate-and-add over a name, which is how an export is
// looked up without its string appearing in the file: `ror r32, imm8` followed
// by `add r32, r32`, with or without REX prefixes.
func hashLoopNear(data []byte, at, reach int) bool {
	lo, hi := at-reach, at+reach
	if lo < 0 {
		lo = 0
	}
	if hi > len(data)-5 {
		hi = len(data) - 5
	}
	for i := lo; i < hi; i++ {
		if data[i] != 0xC1 || data[i+1] < 0xC8 || data[i+1] > 0xCF {
			continue
		}
		if imm := data[i+2]; imm == 0 || imm > 31 {
			continue
		}
		next := data[i+3]
		if next == 0x41 || next == 0x44 || next == 0x45 {
			next = data[i+4]
		}
		if next == 0x01 || next == 0x03 {
			return true
		}
	}
	return false
}

// apiImports are the functions stagers resolve by hash. Listing names and
// computing the constants keeps this a statement about the hashing convention,
// not a list of opaque numbers from one tool.
var apiImports = map[string][]string{
	"kernel32.dll": {"LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect", "ExitProcess", "CreateProcessA",
		"WaitForSingleObject", "CreateThread", "WinExec", "GetVersion", "CreateFileA", "WriteFile", "Sleep"},
	"ws2_32.dll": {"WSAStartup", "WSASocketA", "connect", "bind", "listen", "accept", "recv", "send", "closesocket"},
	"wininet.dll": {"InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA", "InternetReadFile",
		"InternetSetOptionA", "InternetErrorDlg"},
	"winhttp.dll": {"WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData"},
	"ntdll.dll":   {"RtlExitUserThread"},
	"urlmon.dll":  {"URLDownloadToFileA"},
	"user32.dll":  {"MessageBoxA"},
}

// ror13 is the rolling hash Windows shellcode conventionally uses.
func ror13(h uint32, b byte) uint32 { return bits.RotateLeft32(h, -13) + uint32(b) }

// apiHash combines a module hash (upper-cased UTF-16 with its terminator) and a
// function hash (ASCII with its terminator), as stagers walking the export
// tables of every loaded module do.
func apiHash(module, function string) uint32 {
	var m uint32
	for _, c := range []byte(strings.ToUpper(module) + "\x00") {
		m = ror13(ror13(m, c), 0)
	}
	var f uint32
	for _, c := range []byte(function + "\x00") {
		f = ror13(f, c)
	}
	return m + f
}

var apiHashes = func() map[uint32]string {
	out := map[uint32]string{}
	for mod, fns := range apiImports {
		for _, fn := range fns {
			out[apiHash(mod, fn)] = fn
		}
	}
	return out
}()

// hashedCalls returns the distinct known API hashes loaded as an immediate:
// `push imm32` on x86, `mov r10d, imm32` on x64.
func hashedCalls(data []byte) []string {
	seen := map[uint32]bool{}
	var names []string
	check := func(off int) {
		if off+4 > len(data) {
			return
		}
		v := uint32(data[off]) | uint32(data[off+1])<<8 | uint32(data[off+2])<<16 | uint32(data[off+3])<<24
		if name, ok := apiHashes[v]; ok && !seen[v] {
			seen[v] = true
			names = append(names, name)
		}
	}
	for i := 0; i+5 <= len(data); i++ {
		switch {
		case data[i] == 0x68:
			check(i + 1)
		case data[i] == 0x41 && i+6 <= len(data) && data[i+1] == 0xBA:
			check(i + 2)
		}
	}
	return names
}

// fpuGetPC finds the x87 trick for learning the instruction pointer (fnstenv
// saves it to the stack) followed by a pop and an xor through that pointer: a
// self-decoding stub. Compilers never emit this sequence.
func fpuGetPC(data []byte) int {
	for off := 0; ; {
		i := bytes.Index(data[off:], []byte{0xD9, 0x74, 0x24, 0xF4})
		if i < 0 {
			return -1
		}
		at := off + i
		off = at + 1
		end := at + 40
		if end > len(data) {
			end = len(data)
		}
		body := data[at+4 : end]
		pop := false
		for _, b := range body[:min(len(body), 8)] {
			if b >= 0x58 && b <= 0x5F {
				pop = true
				break
			}
		}
		if pop && hasMemXor(body) {
			return at
		}
	}
}

// hasMemXor reports `xor [reg+disp8], reg`, the write that decodes in place.
func hasMemXor(b []byte) bool {
	for i := 0; i+2 < len(b); i++ {
		if (b[i] == 0x30 || b[i] == 0x31) && b[i+1]&0xC0 == 0x40 {
			return true
		}
	}
	return false
}

// jmpCallPop finds the other way to learn the instruction pointer: jump forward
// to a call that lands back on a pop. Following the branches instead of
// matching bytes makes this about control flow, so reordered registers and
// different decoders still match. The body between them must xor.
func jmpCallPop(data []byte) int {
	for i := 0; i+8 < len(data); i++ {
		if data[i] != 0xEB || data[i+1] >= 0x80 {
			continue
		}
		target := i + 2 + int(data[i+1])
		if target+5 > len(data) || data[target] != 0xE8 {
			continue
		}
		rel := int32(uint32(data[target+1]) | uint32(data[target+2])<<8 | uint32(data[target+3])<<16 | uint32(data[target+4])<<24)
		if int(rel)+target+5 != i+2 {
			continue
		}
		if p := data[i+2]; p < 0x58 || p > 0x5F {
			continue
		}
		for _, b := range data[i+2 : target] {
			if b == 0x30 || b == 0x31 {
				return i
			}
		}
	}
	return -1
}

// Linux syscall numbers, x86-64.
const (
	sysExecve  = 0x3B
	sysSocket  = 0x29
	sysConnect = 0x2A
	sysBind    = 0x31
)

// pushSyscall reports `push nr; pop rax` reaching a `syscall` shortly after,
// the size-optimised form no compiler emits.
func pushSyscall(data []byte, nr byte) bool {
	for off := 0; ; {
		i := bytes.Index(data[off:], []byte{0x6A, nr, 0x58})
		if i < 0 {
			return false
		}
		at := off + i
		off = at + 1
		end := at + 32
		if end > len(data) {
			end = len(data)
		}
		if bytes.Contains(data[at:end], []byte{0x0F, 0x05}) {
			return true
		}
	}
}

// socketcall reports the x86 multiplexed socket syscall reached with eax loaded
// by hand: `mov al, 0x66` or `push 0x66; pop eax` shortly before `int 0x80`.
func socketcall(data []byte) bool {
	for _, lead := range [][]byte{{0xB0, 0x66}, {0x6A, 0x66, 0x58}} {
		for off := 0; ; {
			i := bytes.Index(data[off:], lead)
			if i < 0 {
				break
			}
			at := off + i
			off = at + 1
			end := at + 16
			if end > len(data) {
				end = len(data)
			}
			if bytes.Contains(data[at:end], []byte{0xCD, 0x80}) {
				return true
			}
		}
	}
	return false
}

var shellStrings = [][]byte{
	{0x68, 0x2F, 0x2F, 0x73, 0x68, 0x68, 0x2F, 0x62, 0x69, 0x6E}, // push "//sh"; push "/bin"
	{0x68, 0x6E, 0x2F, 0x73, 0x68, 0x68, 0x2F, 0x2F, 0x62, 0x69}, // push "n/sh"; push "//bi"
}

// movabsShell matches `movabs r64, "/bin/sh\0"`. The instruction is the evidence:
// the string alone is in every program that honours $SHELL (measured: flock's
// rodata reads "/bin/sh\0SHELL").
var movabsShell = hexPattern("48 ?? 2F 62 69 6E 2F 73 68 00")

// maxSyscallBlob bounds the checks that only mean anything in a small blob: a
// large static binary legitimately contains syscall instructions and strings.
const maxSyscallBlob = 64 << 10

func (w *walker) scanBytes(data []byte, origin string) {
	for _, p := range pebWalks {
		for _, at := range p.find(data, 16) {
			if hashLoopNear(data, at, 512) {
				w.add(classPEBHash, catalog[classPEBHash], origin, fmt.Sprintf("PEB walk at 0x%x", at))
				break
			}
		}
	}
	if names := hashedCalls(data); len(names) >= 2 {
		w.add(classAPIHash, catalog[classAPIHash], origin, strings.Join(names, ", "))
	}
	if at := fpuGetPC(data); at >= 0 {
		w.add(classGetPC, catalog[classGetPC], origin, fmt.Sprintf("fnstenv at 0x%x", at))
	}
	if at := jmpCallPop(data); at >= 0 {
		w.add(classJmpCall, catalog[classJmpCall], origin, fmt.Sprintf("jmp at 0x%x", at))
	}
	if len(data) > maxSyscallBlob {
		return
	}
	x64 := pushSyscall(data, sysSocket) && (pushSyscall(data, sysConnect) || pushSyscall(data, sysBind))
	if x64 || socketcall(data) {
		w.add(classLinuxNet, catalog[classLinuxNet], origin, "")
	}
	for _, s := range shellStrings {
		if bytes.Contains(data, s) {
			w.add(classLinuxExec, catalog[classLinuxExec], origin, "")
			break
		}
	}
	for _, at := range movabsShell.find(data, 16) {
		if data[at+1] >= 0xB8 && data[at+1] <= 0xBF {
			w.add(classLinuxExec, catalog[classLinuxExec], origin, "")
			break
		}
	}
	if pushSyscall(data, sysExecve) {
		w.add(classLinuxExec, catalog[classLinuxExec], origin, "")
	}
}
