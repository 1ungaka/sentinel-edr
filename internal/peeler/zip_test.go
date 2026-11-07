package peeler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// zipEntry is one member of a synthetic archive. Fixtures are built at run time
// from inert content; nothing here is a real payload.
type zipEntry struct {
	name   string
	body   []byte
	stored bool
	flags  uint16
}

func zipOf(entries ...zipEntry) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Flags: e.flags}
		if e.stored {
			h.Method = zip.Store
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			panic(err)
		}
		f.Write(e.body)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// harmlessScript is the leaf the synthetic chains hide: it echoes a fixed word.
var harmlessScript = []byte("#!/bin/sh\n" + strings.Repeat("echo canary\n", 12))

var prose = []byte(strings.Repeat("Ordinary documentation with nothing hidden in it at all.\n", 20))

func init() {
	encoders[zipStep] = func(b []byte) []byte {
		return zipOf(zipEntry{name: "readme.txt", body: prose}, zipEntry{name: "data.bin", body: b})
	}
}

func TestAMemberIsPeeledLikeAFile(t *testing.T) {
	chain := compose(fakeELF, "base64", "gzip")
	r := peelDefault(zipOf(
		zipEntry{name: "notes.txt", body: prose},
		zipEntry{name: "blob", body: chain},
		zipEntry{name: "stored", body: compose(harmlessScript, "hex", "zlib"), stored: true},
	))
	if r.Outcome != OutcomeRevealedExecutable {
		t.Fatalf("outcome %s, chains %v, exhausted %q", r.Outcome, r.Chains, r.ExhaustReason)
	}
	for _, sig := range []string{"zip>base64>gzip", "zip>hex>zlib"} {
		if !hasChain(r, sig) {
			t.Errorf("no chain %s in %v", sig, r.Chains)
		}
	}
	// The archive is packaging: the member scores what it would score on disk.
	if want := peelDefault(chain); r.MaxDepth != want.MaxDepth || r.Score != want.Score {
		t.Errorf("in a zip: depth %d score %d; on disk: depth %d score %d", r.MaxDepth, r.Score, want.MaxDepth, want.Score)
	}
	if a := r.Archive; a == nil || a.Archives != 1 || a.Members != 3 || a.Peeled != 2 || a.Screened != 1 {
		t.Errorf("archive stats %+v", r.Archive)
	}
}

// An archive of programs, a jar in a war, one base64 file in a zip: all packaging.
func TestAnArchiveIsNotALayer(t *testing.T) {
	inner := zipOf(zipEntry{name: "lib.so", body: largeELF()}, zipEntry{name: "run.sh", body: harmlessScript})
	for name, blob := range map[string][]byte{
		"programs":       inner,
		"nested archive": zipOf(zipEntry{name: "inner.jar", body: inner, stored: true}, zipEntry{name: "b.zip", body: inner}),
		"one encoding":   zipOf(zipEntry{name: "elf.b64", body: compose(fakeELF, "base64")}),
		"prose":          zipOf(zipEntry{name: "a.txt", body: prose}, zipEntry{name: "b.txt", body: prose[:300]}),
	} {
		t.Run(name, func(t *testing.T) {
			r := peelDefault(blob)
			if r.Outcome != OutcomeClean || r.Score != 0 || len(r.Findings) != 0 || r.Exhausted {
				t.Fatalf("outcome %s, score %d, depth %d, chains %v, reason %q", r.Outcome, r.Score, r.MaxDepth, r.Chains, r.ExhaustReason)
			}
		})
	}
}

// A zip under an encoding was hidden, so it counts, and so does what it holds.
func TestAHiddenArchiveIsALayer(t *testing.T) {
	archive := zipOf(zipEntry{name: "readme.txt", body: prose}, zipEntry{name: "tool", body: largeELF()})
	for _, outer := range []string{"base64", "hex", "base85", "base32>base64", "base64>gzip"} {
		t.Run(outer, func(t *testing.T) {
			steps := strings.Split(outer, ">")
			r := peelDefault(composeAny(archive, steps...))
			if r.Outcome != OutcomeRevealedExecutable || !hasChain(r, outer+">zip") || r.MaxDepth != len(steps)+1 {
				t.Fatalf("outcome %s, depth %d, chains %v", r.Outcome, r.MaxDepth, r.Chains)
			}
		})
	}
}

// A gzipped document is a compressed archive, which is still only packaging:
// what Debian does to every OpenDocument file under /usr/share/doc.
func TestACompressedArchiveIsStillPackaging(t *testing.T) {
	archive := zipOf(zipEntry{name: "content.xml", body: prose}, zipEntry{name: "tool", body: largeELF()},
		zipEntry{name: "run.sh", body: harmlessScript}, zipEntry{name: "one.b64", body: compose(fakeELF, "base64")})
	for _, outer := range []string{"gzip", "zlib", "gzip>gzip"} {
		t.Run(outer, func(t *testing.T) {
			r := peelDefault(composeAny(archive, strings.Split(outer, ">")...))
			if r.Outcome != OutcomeClean || len(r.Findings) != 0 || r.Archive == nil {
				t.Fatalf("outcome %s, depth %d, chains %v, archive %+v", r.Outcome, r.MaxDepth, r.Chains, r.Archive)
			}
		})
	}
	// The members are still peeled, each as the file it is.
	chained := zipOf(zipEntry{name: "blob", body: compose(fakeELF, "base64", "gzip")})
	if r := peelDefault(compose(chained, "gzip")); !hasChain(r, "gzip>zip>base64>gzip") || r.Outcome != OutcomeRevealedExecutable {
		t.Fatalf("outcome %s, chains %v", r.Outcome, r.Chains)
	}
}

func TestNestedArchivesShareTheTree(t *testing.T) {
	blob := compose(fakeELF, "base64", "gzip")
	for i := 0; i < 5; i++ {
		blob = zipOf(zipEntry{name: "inner.zip", body: blob})
	}
	r := peelDefault(blob)
	if !hasChain(r, "zip>zip>zip>zip>zip>base64>gzip") || r.MaxDepth != 2 {
		t.Fatalf("depth %d, chains %v, reason %q", r.MaxDepth, r.Chains, r.ExhaustReason)
	}
	if r.Archive == nil || r.Archive.Archives != 5 {
		t.Fatalf("archive stats %+v", r.Archive)
	}

	// Nesting spends depth like any other step: past the wall it is exhausted.
	for i := 0; i < 40; i++ {
		blob = zipOf(zipEntry{name: "inner.zip", body: blob, stored: true})
	}
	r = peelDefault(blob)
	if r.Outcome != OutcomePeelExhausted || r.ExhaustReason != "depth ceiling" {
		t.Fatalf("outcome %s, reason %q", r.Outcome, r.ExhaustReason)
	}
}

// A jar: thousands of members, none of them a layer. It must cost neither the
// node wall nor a verdict.
func TestOrdinaryMembersAreScreenedNotWalked(t *testing.T) {
	var entries []zipEntry
	for i := 0; i < 3000; i++ {
		body := append([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, byte(i)}, bytes.Repeat([]byte{byte(i), 0x01, 0xb7}, 60)...)
		if i%3 == 0 {
			body = []byte(fmt.Sprintf("name=%d\nvalue=some ordinary property text, number %d\n", i, i))
		}
		entries = append(entries, zipEntry{name: fmt.Sprint("m", i), body: body})
	}
	r := peelDefault(zipOf(entries...))
	if r.Outcome != OutcomeClean || r.Exhausted || r.MaxDepth != 0 {
		t.Fatalf("outcome %s, reason %q, depth %d", r.Outcome, r.ExhaustReason, r.MaxDepth)
	}
	if r.NodesVisited != 1 {
		t.Errorf("%d nodes for an archive with no layer in it", r.NodesVisited)
	}
	if a := r.Archive; a == nil || a.Members != 3000 || a.Screened != 3000 || a.Peeled != 0 {
		t.Errorf("archive stats %+v", r.Archive)
	}
	// What was decompressed to screen them is charged, though none was kept.
	if r.OutputBytes == 0 {
		t.Error("screening was not charged to the output wall")
	}
}

// More layered members than there are nodes: the wall, said out loud.
func TestTooManyLayeredMembersExhaust(t *testing.T) {
	var entries []zipEntry
	for i := 0; i < 80; i++ {
		entries = append(entries, zipEntry{name: fmt.Sprint(i), body: compose([]byte(fmt.Sprintf("member %d %s", i, prose)), "gzip")})
	}
	r := New(WithLimits(BudgetLimits{MaxNodes: 40})).Peel(context.Background(), zipOf(entries...))
	if r.Outcome != OutcomePeelExhausted || r.ExhaustReason != "node ceiling" {
		t.Fatalf("outcome %s, reason %q", r.Outcome, r.ExhaustReason)
	}
	if r.NodesVisited > 40 {
		t.Fatalf("%d nodes over a wall of 40", r.NodesVisited)
	}
}

func TestEncryptedMembersAreSkippedAndReported(t *testing.T) {
	r := peelDefault(zipOf(
		zipEntry{name: "locked", body: compose(fakeELF, "base64", "gzip"), flags: 0x1},
		zipEntry{name: "open.txt", body: prose},
	))
	if r.Archive == nil || r.Archive.Encrypted != 1 || r.Archive.Peeled != 0 {
		t.Fatalf("archive stats %+v", r.Archive)
	}
	if len(r.Chains) != 0 {
		t.Fatalf("an encrypted member was read: %v", r.Chains)
	}
}

func TestUnsupportedMethodIsReported(t *testing.T) {
	blob := zipOf(zipEntry{name: "a", body: compose(fakeELF, "base64", "gzip"), stored: true})
	dir, _, ok := zipDirectory(blob)
	if !ok {
		t.Fatal("no directory")
	}
	// Method 14 (LZMA) in the central record, which is the one this layer reads.
	at := bytes.Index(blob, dir)
	binary.LittleEndian.PutUint16(blob[at+10:], 14)
	r := peelDefault(blob)
	if r.Archive == nil || r.Archive.Unsupported != 1 || len(r.Chains) != 0 {
		t.Fatalf("archive stats %+v, chains %v", r.Archive, r.Chains)
	}
}

func TestZipBombIsRefusedByItsProfile(t *testing.T) {
	blob := zipOf(zipEntry{name: "zeros", body: make([]byte, 56<<20)})
	start := time.Now()
	r := peelDefault(blob)
	if r.Outcome != OutcomePeelExhausted || !strings.HasPrefix(r.ExhaustReason, "zip decompression-bomb profile") {
		t.Fatalf("outcome %s, reason %q", r.Outcome, r.ExhaustReason)
	}
	// Refused on what the directory declares, before a member is opened.
	if r.OutputBytes != 0 {
		t.Errorf("%d bytes decompressed from a refused archive", r.OutputBytes)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("refusal took %s", d)
	}
}

// A directory that declares a small size cannot buy more than the wall either.
// Past it, a plain archive is reported as not read through, with no score: the
// members before the wall were ordinary. The same wall under an encoding cut a
// chain short, and that keeps the exhausted floor.
func TestZipMemberCannotOutrunTheOutputWall(t *testing.T) {
	text := bytes.Repeat([]byte("all work and no play makes a dull archive member\n"), 40000)
	blob := zipOf(zipEntry{name: "first.txt", body: prose}, zipEntry{name: "big.txt", body: text}, zipEntry{name: "last.txt", body: prose[:200]})
	dir, _, _ := zipDirectory(blob)
	at := bytes.Index(blob, dir)
	binary.LittleEndian.PutUint32(blob[at+zipDirLen+len("first.txt")+24:], 64) // declared uncompressed size: a lie
	p := New(WithLimits(BudgetLimits{MaxOutputBytes: 64 << 10}))
	r, st := p.inspect(context.Background(), blob, nil)
	if r.Outcome != OutcomePeelExhausted || !strings.HasPrefix(r.ExhaustReason, "archive read past the output wall (1 of 3 members read)") {
		t.Fatalf("outcome %s, reason %q", r.Outcome, r.ExhaustReason)
	}
	if !r.ExhaustSoft || r.Score != 0 || r.Archive.Unscreened != 2 || r.Archive.Screened != 1 {
		t.Fatalf("soft %v, score %d, archive %+v", r.ExhaustSoft, r.Score, r.Archive)
	}
	if r.OutputBytes > 64<<10 || st.budget.peakHeld.Load() > st.budget.maxHeld {
		t.Fatalf("kept %d, held %d", r.OutputBytes, st.budget.peakHeld.Load())
	}

	r = p.Peel(context.Background(), compose(blob, "base64"))
	if r.Outcome != OutcomePeelExhausted || !strings.HasPrefix(r.ExhaustReason, "output ceiling") || r.ExhaustSoft || r.Score != 30 {
		t.Fatalf("hidden: outcome %s, reason %q, soft %v, score %d", r.Outcome, r.ExhaustReason, r.ExhaustSoft, r.Score)
	}
}

// The wall clock striking inside a plain archive is the same: said, not scored,
// unless a chain was being followed when it struck. The deadline is produced by
// construction: the budget's clock jumps past it once the walk is inside the
// archive, so the outcome does not depend on how loaded the machine is.
func TestWallClockInsideAPlainArchiveIsSoft(t *testing.T) {
	var entries []zipEntry
	for i := 0; i < 2000; i++ {
		entries = append(entries, zipEntry{name: fmt.Sprint(i), body: []byte(fmt.Sprintf("member %d\n%s", i, prose))})
	}
	blob := zipOf(entries...)

	// At the layer: the member loop asks stop every zipStopEvery members. Text
	// members are only settled on the second pass, so a stop during the first
	// leaves every one of them unread.
	asked := 0
	stop := func() bool { asked++; return asked > 1 }
	outs, rep, err := (zipLayer{}).UnwrapContainer(blob, containerEnv{limit: 1 << 30, stop: stop})
	if err != nil || len(outs) != 0 || !rep.soft || rep.wall != "archive read past the wall clock (0 of 2000 members read)" {
		t.Fatalf("outs %d, err %v, soft %v, wall %q", len(outs), err, rep.soft, rep.wall)
	}
	if rep.stats.Unscreened != 2000 || rep.stats.Screened != 0 {
		t.Fatalf("stats %+v", rep.stats)
	}
	// Stopped during the second pass, the members read so far are counted.
	asked = 0
	stop = func() bool { asked++; return asked > 9 } // 8 asks in the first pass, one more in the second
	if _, rep, _ := (zipLayer{}).UnwrapContainer(blob, containerEnv{limit: 1 << 30, stop: stop}); rep.wall != "archive read past the wall clock (256 of 2000 members read)" || rep.stats.Screened != 256 {
		t.Fatalf("second pass: wall %q, stats %+v", rep.wall, rep.stats)
	}
	asked = 0
	if _, rep, _ := (zipLayer{}).UnwrapContainer(blob, containerEnv{limit: 1 << 30, stop: stop, hidden: true}); rep.soft || rep.wall != deadlineReason {
		t.Fatalf("hidden: soft %v, wall %q", rep.soft, rep.wall)
	}

	// Through the walk: the clock is read once when the budget is built, once
	// by the root node, once by each of the root's decoders before it starts,
	// and then by the archive's member loop. From the seventh read on it is an
	// hour later: the archive's own decode has started by then, and its loop
	// is what finds the deadline, with up to eight reads of its own to find it.
	clock := func() func() time.Time {
		start := time.Now()
		var reads atomic.Int64
		return func() time.Time {
			if reads.Add(1) >= 7 {
				return start.Add(time.Hour)
			}
			return start
		}
	}
	r := New(withClock(clock())).Peel(context.Background(), blob)
	if r.Outcome != OutcomePeelExhausted || !r.ExhaustSoft || r.Score != 0 || !strings.HasPrefix(r.ExhaustReason, "archive read past the wall clock") {
		t.Fatalf("outcome %s, soft %v, score %d, reason %q", r.Outcome, r.ExhaustSoft, r.Score, r.ExhaustReason)
	}
	if r.Archive == nil || r.Archive.Unscreened == 0 || r.Archive.Unscreened+r.Archive.Screened != 2000 {
		t.Fatalf("archive %+v", r.Archive)
	}
	// The same archive under an encoding was hidden: whenever the deadline
	// strikes, the result is not soft, and it scores as an exhausted chain.
	r = New(withClock(clock())).Peel(context.Background(), compose(blob, "base64"))
	if !r.Exhausted || r.ExhaustSoft || r.Score < 30 {
		t.Fatalf("hidden: exhausted %v, soft %v, score %d, reason %q", r.Exhausted, r.ExhaustSoft, r.Score, r.ExhaustReason)
	}
}

func TestZipMemberCap(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := 0; i < maxZipMembers+5; i++ {
		if _, err := w.CreateHeader(&zip.FileHeader{Name: "e", Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	r := peelDefault(buf.Bytes())
	if r.Outcome != OutcomePeelExhausted || !strings.HasPrefix(r.ExhaustReason, "zip member cap") {
		t.Fatalf("outcome %s, reason %q", r.Outcome, r.ExhaustReason)
	}
	if r.Archive == nil || r.Archive.Members != maxZipMembers {
		t.Fatalf("archive stats %+v", r.Archive)
	}
}

func TestZip64Directory(t *testing.T) {
	// 65,536 members forces the zip64 end record and its locator.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := 0; i < 0x10000-1; i++ {
		w.CreateHeader(&zip.FileHeader{Name: "e", Method: zip.Store})
	}
	f, _ := w.CreateHeader(&zip.FileHeader{Name: "last", Method: zip.Deflate})
	f.Write(prose)
	w.Close()
	dir, base, ok := zipDirectory(buf.Bytes())
	if !ok || base != 0 {
		t.Fatalf("ok %v, base %d", ok, base)
	}
	n := 0
	for p := 0; p+zipDirLen <= len(dir) && zipSig(dir, uint64(p), 1, 2); n++ {
		p += zipDirLen + int(binary.LittleEndian.Uint16(dir[p+28:])) + int(binary.LittleEndian.Uint16(dir[p+30:])) + int(binary.LittleEndian.Uint16(dir[p+32:]))
	}
	if n != 0x10000 {
		t.Fatalf("%d records in the zip64 directory", n)
	}
}

// Data in front of an archive shifts every offset in it.
func TestZipDirectoryWithPrependedData(t *testing.T) {
	inner := zipOf(zipEntry{name: "blob", body: compose(fakeELF, "base64", "gzip")})
	shifted := append(bytes.Repeat([]byte("stub"), 100), inner...)
	dir, base, ok := zipDirectory(shifted)
	if !ok || base != 400 {
		t.Fatalf("ok %v, base %d", ok, base)
	}
	found := false
	zipMembers(dir, func(m zipMember) bool {
		data, ok := zipData(shifted, base, m)
		found = ok && len(data) > 0
		return true
	})
	if !found {
		t.Fatal("member data not located behind the stub")
	}
}

func TestZipThatIsNotOne(t *testing.T) {
	for name, blob := range map[string][]byte{
		"magic only":   append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0}, 80)...),
		"no directory": zipOf(zipEntry{name: "a", body: prose})[:60],
	} {
		if _, _, err := (zipLayer{}).UnwrapContainer(blob, containerEnv{limit: 1 << 20}); err != ErrNotThisLayer {
			t.Errorf("%s: err = %v", name, err)
		}
		if r := peelDefault(blob); r.Exhausted || r.Archive != nil {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// xz is recognised and cannot be decoded here. The result says so.
func TestXZIsReportedOpaque(t *testing.T) {
	xz := append([]byte{0xfd, '7', 'z', 'X', 'Z', 0, 0, 4}, bytes.Repeat([]byte{0x5a, 0xa5, 0x13}, 40)...)
	r := peelDefault(compose(xz, "base64"))
	if len(r.Opaque) != 1 || r.Opaque[0] != "base64>xz" {
		t.Fatalf("opaque = %v", r.Opaque)
	}
	r = peelDefault(zipOf(zipEntry{name: "a.xz", body: xz, stored: true}))
	if len(r.Opaque) != 1 || r.Opaque[0] != "zip>xz" {
		t.Fatalf("opaque = %v", r.Opaque)
	}
	if r.Outcome != OutcomeClean {
		t.Fatalf("an opaque layer is reported, not scored: %s", r.Outcome)
	}
}

// FuzzZipLayer drives the archive reader with arbitrary bytes. It must never
// panic, never yield more members than the cap, and never decompress more than
// it was allowed, kept and discarded together.
func FuzzZipLayer(f *testing.F) {
	f.Add(zipOf(zipEntry{name: "a", body: compose(fakeELF, "base64", "gzip")}, zipEntry{name: "b", body: prose}))
	f.Add(zipOf(zipEntry{name: "s", body: harmlessScript, stored: true}, zipEntry{name: "e", body: prose, flags: 1}))
	f.Add(zipOf(zipEntry{name: "in", body: zipOf(zipEntry{name: "x", body: compose(harmlessScript, "hex")}), stored: true}))
	f.Add(zipOf())
	f.Add([]byte("PK\x03\x04"))
	f.Add(append([]byte("PK\x03\x04"), bytes.Repeat([]byte("PK\x01\x02PK\x05\x06PK\x06\x06PK\x06\x07"), 8)...))

	const limit = 256 << 10
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, hidden := range []bool{false, true} {
			outs, rep, err := (zipLayer{}).UnwrapContainer(data, containerEnv{limit: limit, hidden: hidden})
			if err != nil && len(outs) != 0 {
				t.Fatalf("outputs returned beside %v", err)
			}
			if len(outs) > maxZipMembers || rep.stats.Members > maxZipMembers {
				t.Fatalf("%d outputs from %d members", len(outs), rep.stats.Members)
			}
			total := rep.screenedBytes
			for _, d := range outs {
				total += int64(len(d.Data))
			}
			if total > limit || rep.screenedBytes < 0 {
				t.Fatalf("%d bytes decompressed (%d discarded) over a limit of %d", total, rep.screenedBytes, limit)
			}
		}
		// And through the walk, where nested archives meet the shared budget.
		r, st := New(WithLimits(BudgetLimits{MaxNodes: 64, MaxOutputBytes: limit, MaxDepth: 6, MaxWallClock: 2 * time.Second})).
			inspect(context.Background(), data, nil)
		if v := st.gauges.violation.Load(); v != nil {
			t.Fatal(*v)
		}
		if r.OutputBytes > limit || r.NodesVisited > 64 {
			t.Fatalf("%d bytes, %d nodes", r.OutputBytes, r.NodesVisited)
		}
	})
}
