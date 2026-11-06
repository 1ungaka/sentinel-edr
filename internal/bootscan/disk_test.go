package bootscan

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
)

// ── synthetic disks ──────────────────────────────────────────────────────────
//
// Every fixture is generated here, at test time: a blank image with real
// structures written into it. No fixture is taken from a real disk.

const testSectors = 4096 // a 2 MiB disk at 512 bytes per sector

var (
	espTypeGUID   = guidBytes(0xc12a7328, 0xf81f, 0x11d2, [8]byte{0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b})
	linuxTypeGUID = guidBytes(0x0fc63daf, 0x8483, 0x4772, [8]byte{0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4})
	diskGUID      = guidBytes(0x11111111, 0x2222, 0x3333, [8]byte{0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55})
)

func guidBytes(a uint32, b, c uint16, d [8]byte) []byte {
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint16(out[4:], b)
	binary.LittleEndian.PutUint16(out[6:], c)
	copy(out[8:], d[:])
	return out
}

type gptPart struct {
	typ         []byte
	first, last uint64
	name        string
}

func utf16le(s string) []byte {
	var out []byte
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// writeGPTHeader writes a header at lba with a correct CRC.
func writeGPTHeader(img []byte, ss int, lba, alt, entriesLBA uint64, entriesCRC uint32, total uint64) {
	h := make([]byte, 92)
	copy(h, "EFI PART")
	binary.LittleEndian.PutUint32(h[8:], 0x00010000)
	binary.LittleEndian.PutUint32(h[12:], 92)
	binary.LittleEndian.PutUint64(h[24:], lba)
	binary.LittleEndian.PutUint64(h[32:], alt)
	binary.LittleEndian.PutUint64(h[40:], 34)
	binary.LittleEndian.PutUint64(h[48:], total-34)
	copy(h[56:], diskGUID)
	binary.LittleEndian.PutUint64(h[72:], entriesLBA)
	binary.LittleEndian.PutUint32(h[80:], 128)
	binary.LittleEndian.PutUint32(h[84:], 128)
	binary.LittleEndian.PutUint32(h[88:], entriesCRC)
	binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
	copy(img[int(lba)*ss:], h)
}

// fixHeaderCRC recomputes the CRC of the header at lba after a field edit.
func fixHeaderCRC(img []byte, ss int, lba uint64) {
	h := img[int(lba)*ss : int(lba)*ss+92]
	binary.LittleEndian.PutUint32(h[16:], 0)
	binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
}

func writeFAT(img []byte, off int) {
	s := img[off : off+512]
	s[0], s[1], s[2] = 0xEB, 0x58, 0x90
	copy(s[3:], "MSDOS5.0")
	binary.LittleEndian.PutUint16(s[11:], 512)
	s[16] = 2
	copy(s[82:], "FAT32   ")
	s[510], s[511] = 0x55, 0xAA
}

func writeExt(img []byte, off int) {
	img[off+1024+56], img[off+1024+57] = 0x53, 0xEF
}

// gptDisk builds a valid GPT disk: protective MBR, primary and backup
// headers, and the given partitions, the first formatted FAT and the rest ext.
func gptDisk(ss int, parts ...gptPart) []byte {
	total := uint64(testSectors)
	img := make([]byte, int(total)*ss)

	// Protective MBR.
	e := img[446:462]
	e[4] = 0xEE
	binary.LittleEndian.PutUint32(e[8:], 1)
	binary.LittleEndian.PutUint32(e[12:], uint32(total-1))
	img[510], img[511] = 0x55, 0xAA

	entries := make([]byte, 128*128)
	for i, p := range parts {
		ent := entries[i*128:]
		copy(ent, p.typ)
		copy(ent[16:], guidBytes(uint32(i+1), 0, 0, [8]byte{}))
		binary.LittleEndian.PutUint64(ent[32:], p.first)
		binary.LittleEndian.PutUint64(ent[40:], p.last)
		copy(ent[56:], utf16le(p.name))
		if i == 0 {
			writeFAT(img, int(p.first)*ss)
		} else {
			writeExt(img, int(p.first)*ss)
		}
	}
	crc := crc32.ChecksumIEEE(entries)
	entrySectors := uint64((len(entries) + ss - 1) / ss)
	copy(img[2*ss:], entries)
	backupEntries := total - 1 - entrySectors
	copy(img[int(backupEntries)*ss:], entries)
	writeGPTHeader(img, ss, 1, total-1, 2, crc, total)
	writeGPTHeader(img, ss, total-1, 1, backupEntries, crc, total)
	return img
}

func standardGPT() []byte {
	return gptDisk(512,
		gptPart{espTypeGUID, 64, 1087, "EFI System Partition"},
		gptPart{linuxTypeGUID, 1088, 3000, "root"})
}

func analyze(img []byte) (*DiskReport, []Finding) {
	return AnalyzeDisk(bytes.NewReader(img), int64(len(img)))
}

func classes(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Class)
	}
	return out
}

func hasClass(fs []Finding, class string) bool {
	for _, f := range fs {
		if f.Class == class {
			return true
		}
	}
	return false
}

func total(fs []Finding) int {
	n := 0
	for _, f := range fs {
		n += f.Score
	}
	return n
}

// ── GPT ──────────────────────────────────────────────────────────────────────

func TestCleanGPTDiskHasNoFindings(t *testing.T) {
	rep, fs := analyze(standardGPT())
	if len(fs) != 0 {
		t.Fatalf("a well-formed GPT disk produced findings: %v", classes(fs))
	}
	if rep.SectorSize != 512 || rep.MBR == nil || !rep.MBR.Protective || !rep.MBR.SignatureValid || rep.MBR.BootCodePresent {
		t.Errorf("mbr: %+v", rep.MBR)
	}
	g := rep.GPT
	if g == nil || !g.HeaderCRCValid || !g.EntriesCRCValid || !g.BackupChecked || !g.BackupValid || !g.BackupConsistent {
		t.Fatalf("gpt: %+v", g)
	}
	if g.DiskGUID != "11111111-2222-3333-4444-555555555555" || g.Entries != 2 {
		t.Errorf("gpt identity: %+v", g)
	}
	if len(rep.Partitions) != 2 {
		t.Fatalf("partitions: %+v", rep.Partitions)
	}
	esp, root := rep.Partitions[0], rep.Partitions[1]
	if !esp.ESP || esp.Type != gptESPType || esp.Name != "EFI System Partition" || esp.BootSector != "fat" || esp.StartLBA != 64 || esp.Sectors != 1024 {
		t.Errorf("esp: %+v", esp)
	}
	if root.ESP || root.BootSector != "ext" || root.Name != "root" {
		t.Errorf("root: %+v", root)
	}
}

func TestGPT4KnSectorSize(t *testing.T) {
	img := gptDisk(4096,
		gptPart{espTypeGUID, 64, 200, "esp"},
		gptPart{linuxTypeGUID, 201, 900, "root"})
	rep, fs := analyze(img)
	if rep.SectorSize != 4096 || rep.GPT == nil || len(rep.Partitions) != 2 || rep.Partitions[0].BootSector != "fat" {
		t.Fatalf("4Kn disk: sector %d gpt %+v parts %+v", rep.SectorSize, rep.GPT, rep.Partitions)
	}
	if len(fs) != 0 {
		t.Errorf("findings on a clean 4Kn disk: %v", classes(fs))
	}
}

func TestGPTHeaderCRC(t *testing.T) {
	img := standardGPT()
	img[512+40]++ // first usable LBA, without fixing the CRC
	_, fs := analyze(img)
	if !hasClass(fs, "gpt.header-crc-invalid") {
		t.Errorf("want gpt.header-crc-invalid, got %v", classes(fs))
	}
}

func TestGPTEntriesCRC(t *testing.T) {
	img := standardGPT()
	// Repoint the second partition without updating the entries CRC: what a
	// raw edit of the table looks like.
	binary.LittleEndian.PutUint64(img[2*512+128+32:], 2000)
	_, fs := analyze(img)
	if !hasClass(fs, "gpt.entries-crc-invalid") || hasClass(fs, "gpt.header-crc-invalid") {
		t.Errorf("want only the entries CRC finding, got %v", classes(fs))
	}
}

func TestGPTPrimaryDestroyed(t *testing.T) {
	img := standardGPT()
	clear(img[:34*512]) // the start of the disk overwritten: MBR, header, entries
	rep, fs := analyze(img)
	if !hasClass(fs, "gpt.primary-destroyed") {
		t.Fatalf("want gpt.primary-destroyed, got %v", classes(fs))
	}
	if rep.GPT == nil || !rep.GPT.RecoveredFromBackup || len(rep.Partitions) != 2 || rep.Partitions[0].Name != "EFI System Partition" {
		t.Errorf("the table should be recovered from the backup: %+v %+v", rep.GPT, rep.Partitions)
	}
	// The backup alone must not also produce a protective-MBR complaint.
	if hasClass(fs, "gpt.no-protective-mbr") {
		t.Errorf("redundant finding: %v", classes(fs))
	}
}

func TestGPTBackupMismatch(t *testing.T) {
	img := standardGPT()
	last := uint64(testSectors - 1)
	img[int(last)*512+56] ^= 0xFF // backup disk GUID
	fixHeaderCRC(img, 512, last)
	rep, fs := analyze(img)
	if !hasClass(fs, "gpt.backup-mismatch") || rep.GPT.BackupConsistent || !rep.GPT.BackupValid {
		t.Errorf("want gpt.backup-mismatch, got %v (%+v)", classes(fs), rep.GPT)
	}
}

// A truncated image has no backup header. That is one low-weight finding and
// nowhere near the threshold: it is also what copying a disk image looks like.
func TestGPTTruncatedImage(t *testing.T) {
	img := standardGPT()[:3500*512]
	_, fs := analyze(img)
	if !hasClass(fs, "gpt.backup-missing") || total(fs) >= DefaultThreshold {
		t.Errorf("truncated image: %v score %d", classes(fs), total(fs))
	}
}

// With no size, the end-of-disk checks are skipped rather than failed.
func TestGPTUnknownSizeSkipsBackupCheck(t *testing.T) {
	img := standardGPT()
	rep, fs := AnalyzeDisk(bytes.NewReader(img), 0)
	if rep.GPT == nil || rep.GPT.BackupChecked || hasClass(fs, "gpt.backup-missing") {
		t.Errorf("unknown size: %+v %v", rep.GPT, classes(fs))
	}
}

func TestGPTOverlapAndRange(t *testing.T) {
	img := gptDisk(512,
		gptPart{espTypeGUID, 64, 1087, "esp"},
		gptPart{linuxTypeGUID, 1000, 3000, "overlaps"})
	_, fs := analyze(img)
	if !hasClass(fs, "gpt.partition-overlap") {
		t.Errorf("want overlap, got %v", classes(fs))
	}
	img = gptDisk(512,
		gptPart{espTypeGUID, 64, 1087, "esp"},
		gptPart{linuxTypeGUID, 1088, 5000, "past the end"})
	_, fs = analyze(img)
	if !hasClass(fs, "gpt.partition-out-of-range") {
		t.Errorf("want out-of-range, got %v", classes(fs))
	}
}

func TestGPTNoProtectiveMBR(t *testing.T) {
	img := standardGPT()
	img[446+4] = 0x83
	_, fs := analyze(img)
	if !hasClass(fs, "gpt.no-protective-mbr") {
		t.Errorf("want gpt.no-protective-mbr, got %v", classes(fs))
	}
}

func TestESPMustBeFAT(t *testing.T) {
	img := standardGPT()
	clear(img[64*512 : 65*512])
	copy(img[64*512+3:], "NTFS    ")
	_, fs := analyze(img)
	if !hasClass(fs, "vbr.esp-not-fat") {
		t.Errorf("want vbr.esp-not-fat, got %v", classes(fs))
	}
}

// ── MBR ──────────────────────────────────────────────────────────────────────

type mbrPart struct {
	status, typ  byte
	start, count uint32
}

func mbrDisk(code string, parts ...mbrPart) []byte {
	img := make([]byte, testSectors*512)
	copy(img, code)
	for i, p := range parts {
		e := img[446+16*i:]
		e[0], e[4] = p.status, p.typ
		binary.LittleEndian.PutUint32(e[8:], p.start)
		binary.LittleEndian.PutUint32(e[12:], p.count)
		if p.count > 0 && int(p.start) < testSectors {
			writeFAT(img, int(p.start)*512)
		}
	}
	img[510], img[511] = 0x55, 0xAA
	return img
}

func TestCleanMBRDisk(t *testing.T) {
	img := mbrDisk("\xeb\x63\x90GRUB \x00Geom\x00Hard Disk\x00Read\x00 Error",
		mbrPart{0x80, 0x0c, 2048, 1000}, mbrPart{0, 0x83, 3048, 1000})
	rep, fs := analyze(img)
	if len(fs) != 0 {
		t.Fatalf("clean MBR disk: %v", classes(fs))
	}
	if rep.GPT != nil || rep.MBR.Loader != "grub" || !rep.MBR.BootCodePresent || len(rep.MBR.BootCodeSHA256) != 64 {
		t.Errorf("mbr: %+v", rep.MBR)
	}
	if len(rep.Partitions) != 2 || !rep.Partitions[0].Active || rep.Partitions[0].Type != "0x0c" || rep.Partitions[0].BootSector != "fat" {
		t.Errorf("partitions: %+v", rep.Partitions)
	}
}

func TestMBRAnomalies(t *testing.T) {
	img := mbrDisk("\xfa\x31\xc0\x8e\xd0 some code with no known message",
		mbrPart{0x80, 0x07, 2048, 1500}, // overlaps the next
		mbrPart{0x80, 0x83, 3000, 500},  // second active
		mbrPart{0, 0x83, 3900, 9000})    // runs past the end
	_, fs := analyze(img)
	for _, want := range []string{"mbr.bootcode-unrecognized", "mbr.multiple-active", "mbr.partition-overlap", "mbr.partition-beyond-disk"} {
		if !hasClass(fs, want) {
			t.Errorf("missing %s in %v", want, classes(fs))
		}
	}
}

func TestMBRExtendedContainerIsNotAnOverlap(t *testing.T) {
	img := mbrDisk("GRUB ",
		mbrPart{0x80, 0x83, 2048, 500},
		mbrPart{0, 0x05, 2548, 1400}, // extended container
	)
	_, fs := analyze(img)
	if hasClass(fs, "mbr.partition-overlap") {
		t.Errorf("an extended container holds its logical partitions; that is not an overlap: %v", classes(fs))
	}
}

func TestActivePartitionWithoutBootSignature(t *testing.T) {
	img := mbrDisk("GRUB ", mbrPart{0x80, 0x83, 2048, 1000})
	img[2048*512+510], img[2048*512+511] = 0, 0
	_, fs := analyze(img)
	if !hasClass(fs, "vbr.active-not-bootable") {
		t.Errorf("want vbr.active-not-bootable, got %v", classes(fs))
	}
}

// ── boot-area text ───────────────────────────────────────────────────────────

func TestRansomTextCrossesAlone(t *testing.T) {
	img := mbrDisk("GRUB ", mbrPart{0x80, 0x83, 2048, 1000})
	note := "YOUR HARD DISK has been ENCRYPTED. To decrypt it, send payment."
	copy(img[5*512:], note)
	_, fs := analyze(img)
	if !hasClass(fs, "boot.ransom-text") || total(fs) < DefaultThreshold {
		t.Fatalf("want boot.ransom-text crossing the threshold, got %v score %d", classes(fs), total(fs))
	}
	for _, f := range fs {
		if f.Class == "boot.ransom-text" && strings.Contains(f.Evidence, "YOUR HARD") {
			t.Errorf("the evidence must be the matched terms, not the note text: %q", f.Evidence)
		}
	}
}

// A disk-encryption loader says "decrypt" and "encrypted" in its prompts.
func TestTwoTermsAreNotANote(t *testing.T) {
	img := mbrDisk("GRUB ", mbrPart{0x80, 0x83, 2048, 1000})
	copy(img[3*512:], "Enter passphrase to decrypt the encrypted volume")
	if _, fs := analyze(img); hasClass(fs, "boot.ransom-text") {
		t.Errorf("two terms must not be a note: %v", classes(fs))
	}
}

// The same words inside a partition are file content, not boot-area text.
func TestRansomTextInsideAPartitionIsIgnored(t *testing.T) {
	img := mbrDisk("GRUB ", mbrPart{0x80, 0x83, 8, 3000})
	copy(img[20*512:], "your files are encrypted, decrypt them with bitcoin payment")
	if _, fs := analyze(img); hasClass(fs, "boot.ransom-text") {
		t.Errorf("text past the first partition's start is not boot-area text: %v", classes(fs))
	}
}

// ── hostile input ────────────────────────────────────────────────────────────

func TestHostileGPTFieldsAreBounded(t *testing.T) {
	mutations := map[string]func(h []byte){
		"huge entry count":  func(h []byte) { binary.LittleEndian.PutUint32(h[80:], 0xFFFFFFFF) },
		"zero entry size":   func(h []byte) { binary.LittleEndian.PutUint32(h[84:], 0) },
		"huge entry size":   func(h []byte) { binary.LittleEndian.PutUint32(h[84:], 0xFFFFFFFF) },
		"entries past disk": func(h []byte) { binary.LittleEndian.PutUint64(h[72:], 1<<60) },
		"entries LBA wraps": func(h []byte) { binary.LittleEndian.PutUint64(h[72:], ^uint64(0)) },
		"backup LBA wraps":  func(h []byte) { binary.LittleEndian.PutUint64(h[32:], ^uint64(0)) },
		"header too small":  func(h []byte) { binary.LittleEndian.PutUint32(h[12:], 8) },
		"header too large":  func(h []byte) { binary.LittleEndian.PutUint32(h[12:], 0xFFFFFFFF) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			img := standardGPT()
			mutate(img[512 : 512+92])
			fixHeaderCRC(img, 512, 1)
			analyze(img) // must not panic or allocate without bound
		})
	}
	// Partition LBAs that overflow a byte offset.
	img := standardGPT()
	binary.LittleEndian.PutUint64(img[2*512+32:], ^uint64(0)-5)
	binary.LittleEndian.PutUint64(img[2*512+40:], ^uint64(0))
	rep, _ := analyze(img)
	if len(rep.Partitions) > 0 && rep.Partitions[0].BootSector != "unread" {
		t.Errorf("an unaddressable partition must be unread, got %q", rep.Partitions[0].BootSector)
	}
}

func TestShortAndEmptyInputs(t *testing.T) {
	if rep, fs := AnalyzeDisk(bytes.NewReader(nil), 0); rep.Error == "" || len(fs) != 0 {
		t.Errorf("empty input: %+v %v", rep, fs)
	}
	if rep, _ := AnalyzeDisk(bytes.NewReader(make([]byte, 100)), 100); rep.Error == "" {
		t.Errorf("sub-sector input must be an error: %+v", rep)
	}
	// An all-zero disk is unpartitioned: nothing to report.
	rep, fs := analyze(make([]byte, 64*512))
	if rep.Error != "" || len(fs) != 0 || rep.MBR.SignatureValid {
		t.Errorf("blank disk: %+v %v", rep, classes(fs))
	}
}

func FuzzAnalyzeDisk(f *testing.F) {
	f.Add(standardGPT()[:40*512])
	f.Add(mbrDisk("GRUB ", mbrPart{0x80, 0x83, 8, 16})[:40*512])
	f.Add(make([]byte, 512))
	f.Add([]byte("EFI PART"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, fs := AnalyzeDisk(bytes.NewReader(data), int64(len(data)))
		if rep == nil {
			t.Fatal("nil report")
		}
		for _, x := range fs {
			if _, ok := classIndex[x.Class]; !ok {
				t.Fatalf("class %q is not in the catalog", x.Class)
			}
		}
		AnalyzeDisk(bytes.NewReader(data), 0) // and with the size unknown
	})
}
