package bootscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf16"
)

// Bounds. A hostile image controls every length field in these structures.
const (
	maxSectorSize    = 4096
	maxGPTEntries    = 1024
	maxGPTEntrySize  = 4096
	maxVBRPartitions = 128
	// bootAreaSectors is how much of the disk start is searched for boot-area
	// text: the classic 63-sector pre-partition gap, rounded up.
	bootAreaSectors = 64
)

// DiskReport is what was read from one disk or image.
type DiskReport struct {
	Path       string      `json:"path"`
	Size       int64       `json:"size,omitempty"` // 0 when the size could not be determined
	SectorSize int         `json:"sector_size,omitempty"`
	MBR        *MBRInfo    `json:"mbr,omitempty"`
	GPT        *GPTInfo    `json:"gpt,omitempty"`
	Partitions []Partition `json:"partitions,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// MBRInfo describes sector 0.
type MBRInfo struct {
	SignatureValid bool `json:"signature_valid"`
	// Protective is set when a 0xEE entry marks the disk as GPT.
	Protective      bool   `json:"protective"`
	BootCodePresent bool   `json:"boot_code_present"`
	BootCodeSHA256  string `json:"boot_code_sha256,omitempty"`
	// Loader is the boot-loader family the boot code was recognised as, by
	// the message strings it carries. Empty when unrecognised or absent.
	// Recognition only ever withholds a low-weight "unrecognised" finding;
	// it is never evidence that the code is benign.
	Loader        string `json:"loader,omitempty"`
	DiskSignature string `json:"disk_signature,omitempty"`
}

// GPTInfo describes the GUID partition table.
type GPTInfo struct {
	HeaderCRCValid   bool   `json:"header_crc_valid"`
	EntriesCRCValid  bool   `json:"entries_crc_valid"`
	DiskGUID         string `json:"disk_guid"`
	Entries          int    `json:"entries"`
	FirstUsableLBA   uint64 `json:"first_usable_lba"`
	LastUsableLBA    uint64 `json:"last_usable_lba"`
	BackupLBA        uint64 `json:"backup_lba"`
	BackupChecked    bool   `json:"backup_checked"`
	BackupValid      bool   `json:"backup_valid"`
	BackupConsistent bool   `json:"backup_consistent"`
	// RecoveredFromBackup is set when the primary header was unusable and
	// the table below was read from the backup header.
	RecoveredFromBackup bool `json:"recovered_from_backup,omitempty"`
}

// Partition is one partition from either table.
type Partition struct {
	Index    int    `json:"index"`
	Scheme   string `json:"scheme"` // "mbr" or "gpt"
	Type     string `json:"type"`   // MBR type byte (0x..) or GPT type GUID
	Name     string `json:"name,omitempty"`
	StartLBA uint64 `json:"start_lba"`
	Sectors  uint64 `json:"sectors"`
	Active   bool   `json:"active,omitempty"`
	ESP      bool   `json:"esp,omitempty"`
	// BootSector is what the partition's first sector was identified as:
	// fat, ntfs, exfat, ext, xfs, luks, empty, unknown, or unread.
	BootSector string `json:"boot_sector,omitempty"`
}

const (
	gptESPType     = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
	mbrTypeGPT     = 0xEE
	mbrTypeESP     = 0xEF
	mbrBootCodeLen = 440
)

// ScanDisk opens a disk image or block device read-only and analyses its
// boot structures.
func ScanDisk(path string) (*DiskReport, []Finding) {
	f, err := os.Open(path) // read-only by construction
	if err != nil {
		return &DiskReport{Path: path, Error: err.Error()}, nil
	}
	defer f.Close()
	var size int64
	// Seeking to the end gives the size of a regular file and of a block
	// device alike; Stat reports 0 for the latter.
	if end, serr := f.Seek(0, io.SeekEnd); serr == nil {
		size = end
	}
	rep, fs := AnalyzeDisk(f, size)
	rep.Path = path
	for i := range fs {
		if fs[i].Target == "" {
			fs[i].Target = path
		}
	}
	return rep, fs
}

// lbaOffset converts an LBA to a byte offset, refusing one that would
// overflow: a hostile table can name any 64-bit sector.
func lbaOffset(lba uint64, ss int64) (int64, bool) {
	if lba > uint64(1<<62)/uint64(ss) {
		return 0, false
	}
	return int64(lba) * ss, true
}

// readAt reads exactly n bytes at off, or returns nil. It never reads past a
// known size and never allocates more than the caller's bounded n.
func readAt(r io.ReaderAt, size, off int64, n int) []byte {
	if off < 0 || n <= 0 || (size > 0 && off+int64(n) > size) {
		return nil
	}
	buf := make([]byte, n)
	if got, err := r.ReadAt(buf, off); got != n || (err != nil && err != io.EOF) {
		return nil
	}
	return buf
}

// AnalyzeDisk analyses the boot structures of a disk presented as a reader.
// size is the disk size in bytes, or 0 when unknown (backup-header and
// end-of-disk checks are then skipped and said to be).
func AnalyzeDisk(r io.ReaderAt, size int64) (*DiskReport, []Finding) {
	rep := &DiskReport{Size: size}
	var out []Finding

	sector0 := readAt(r, size, 0, 512)
	if sector0 == nil {
		rep.Error = "the first sector could not be read"
		return rep, nil
	}

	// Sector size: GPT's header sits at LBA 1, so its signature is at byte
	// 512 on a 512-byte-sector disk and at 4096 on a 4Kn disk.
	rep.SectorSize = 512
	if hdr := readAt(r, size, 512, 8); hdr == nil || string(hdr) != "EFI PART" {
		if hdr4k := readAt(r, size, 4096, 8); hdr4k != nil && string(hdr4k) == "EFI PART" {
			rep.SectorSize = 4096
		}
	}
	ss := int64(rep.SectorSize)
	var totalSectors uint64
	if size > 0 {
		totalSectors = uint64(size / ss)
	}

	// ── MBR ──
	mbr, mbrParts := parseMBR(sector0)
	rep.MBR = mbr

	// ── GPT ──
	gpt, gptParts, gptFindings := parseGPT(r, size, ss, totalSectors)
	rep.GPT = gpt
	out = append(out, gptFindings...)

	switch {
	case gpt != nil:
		rep.Partitions = gptParts
		if !mbr.Protective && !gpt.RecoveredFromBackup {
			out = append(out, finding("gpt.no-protective-mbr", "",
				"the disk has a GPT but its MBR carries no protective 0xEE entry", ""))
		}
	default:
		rep.Partitions = mbrParts
		out = append(out, mbrFindings(mbr, mbrParts, totalSectors)...)
	}

	// Boot code that matches no known loader. On a GPT disk the MBR boot
	// code is only used by BIOS-compatibility boot, but it is still code at
	// the one place a BIOS will execute unconditionally.
	if mbr.BootCodePresent && mbr.Loader == "" {
		out = append(out, finding("mbr.bootcode-unrecognized", "",
			"the MBR holds boot code that matches no boot loader the scan recognises",
			"boot code sha256 "+mbr.BootCodeSHA256))
	}

	// ── boot-area text ──
	gap := uint64(bootAreaSectors)
	for _, p := range rep.Partitions {
		if p.StartLBA > 0 && p.StartLBA < gap {
			gap = p.StartLBA
		}
	}
	area := readAt(r, size, 0, int(gap)*int(ss))
	if area == nil {
		area = sector0
	}
	if terms := ransomTerms(area); len(terms) >= ransomMinTerms {
		out = append(out, finding("boot.ransom-text", "",
			"the boot sector or the gap before the first partition contains ransom-note vocabulary",
			"terms: "+strings.Join(terms, ", ")))
	}

	// ── partition boot sectors ──
	for i := range rep.Partitions {
		p := &rep.Partitions[i]
		if i >= maxVBRPartitions {
			p.BootSector = "unread"
			continue
		}
		off, ok := lbaOffset(p.StartLBA, ss)
		if !ok {
			p.BootSector = "unread"
			continue
		}
		p.BootSector = classifyBootSector(r, size, off)
		if p.ESP && p.BootSector != "fat" && p.BootSector != "unread" {
			out = append(out, finding("vbr.esp-not-fat", "",
				fmt.Sprintf("partition %d is typed as the EFI System Partition but begins with %s, not a FAT boot sector", p.Index, describeBootSector(p.BootSector)), ""))
		}
		if p.Scheme == "mbr" && p.Active && p.BootSector != "unread" {
			if vbr := readAt(r, size, off, 512); vbr != nil && !(vbr[510] == 0x55 && vbr[511] == 0xAA) {
				out = append(out, finding("vbr.active-not-bootable", "",
					fmt.Sprintf("active partition %d has no boot signature in its first sector", p.Index), ""))
			}
		}
	}
	return rep, out
}

// ── MBR ──────────────────────────────────────────────────────────────────────

func parseMBR(s []byte) (*MBRInfo, []Partition) {
	m := &MBRInfo{SignatureValid: s[510] == 0x55 && s[511] == 0xAA}
	code := s[:mbrBootCodeLen]
	for _, b := range code {
		if b != 0 {
			m.BootCodePresent = true
			break
		}
	}
	if m.BootCodePresent {
		sum := sha256.Sum256(code)
		m.BootCodeSHA256 = hex.EncodeToString(sum[:])
		m.Loader = recogniseLoader(s)
	}
	if sig := binary.LittleEndian.Uint32(s[440:444]); sig != 0 {
		m.DiskSignature = fmt.Sprintf("0x%08x", sig)
	}
	var parts []Partition
	if !m.SignatureValid {
		return m, nil
	}
	for i := 0; i < 4; i++ {
		e := s[446+16*i : 446+16*i+16]
		typ := e[4]
		start := uint64(binary.LittleEndian.Uint32(e[8:12]))
		count := uint64(binary.LittleEndian.Uint32(e[12:16]))
		if typ == 0 {
			continue
		}
		if typ == mbrTypeGPT {
			m.Protective = true
		}
		parts = append(parts, Partition{
			Index: i + 1, Scheme: "mbr", Type: fmt.Sprintf("0x%02x", typ),
			StartLBA: start, Sectors: count, Active: e[0] == 0x80, ESP: typ == mbrTypeESP,
		})
	}
	return m, parts
}

// loaderMarkers are message strings standard boot loaders carry in sector 0.
var loaderMarkers = []struct{ marker, family string }{
	{"GRUB ", "grub"},
	{"Missing operating system", "generic-mbr"},
	{"Invalid partition table", "generic-mbr"},
	{"Error loading operating system", "generic-mbr"},
	{"Operating system not found", "generic-mbr"},
	{"isolinux", "syslinux"},
	{"SYSLINUX", "syslinux"},
	{"LILO", "lilo"},
	{"BOOTMGR", "windows"},
	{"NTLDR", "windows"},
	{"FreeBSD", "freebsd"},
}

func recogniseLoader(sector []byte) string {
	for _, m := range loaderMarkers {
		if bytes.Contains(sector, []byte(m.marker)) {
			return m.family
		}
	}
	return ""
}

func mbrFindings(m *MBRInfo, parts []Partition, totalSectors uint64) []Finding {
	var out []Finding
	active := 0
	for _, p := range parts {
		if p.Active {
			active++
		}
		if totalSectors > 0 && p.StartLBA+p.Sectors > totalSectors {
			out = append(out, finding("mbr.partition-beyond-disk", "",
				fmt.Sprintf("partition %d ends at sector %d on a %d-sector disk", p.Index, p.StartLBA+p.Sectors, totalSectors), ""))
		}
	}
	if active > 1 {
		out = append(out, finding("mbr.multiple-active", "",
			fmt.Sprintf("%d partitions are marked active; a BIOS boots exactly one", active), ""))
	}
	if a, b, ok := firstOverlap(parts); ok {
		out = append(out, finding("mbr.partition-overlap", "",
			fmt.Sprintf("partitions %d and %d overlap", a, b), ""))
	}
	return out
}

// firstOverlap reports the first pair of partitions sharing a sector.
// Zero-length partitions and an MBR extended container are not compared.
func firstOverlap(parts []Partition) (a, b int, found bool) {
	var ps []Partition
	for _, p := range parts {
		if p.Sectors == 0 || p.Type == "0x05" || p.Type == "0x0f" || p.Type == "0x85" || p.Type == fmt.Sprintf("0x%02x", mbrTypeGPT) {
			continue
		}
		ps = append(ps, p)
	}
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].StartLBA < ps[j].StartLBA })
	for i := 1; i < len(ps); i++ {
		prevEnd := ps[i-1].StartLBA + ps[i-1].Sectors // exclusive; cannot overflow meaningfully for 32-bit MBR, guarded for GPT by the caller
		if prevEnd < ps[i-1].StartLBA {
			prevEnd = ^uint64(0)
		}
		if ps[i].StartLBA < prevEnd {
			return ps[i-1].Index, ps[i].Index, true
		}
	}
	return 0, 0, false
}

// ── boot-area text ───────────────────────────────────────────────────────────

// ransomMinTerms is how many distinct terms must appear. One or two can
// occur in a legitimate loader's messages (a disk-encryption prompt says
// "decrypt"); three together in the boot area is a note.
const ransomMinTerms = 3

var ransomVocabulary = []string{
	"encrypt", "decrypt", "bitcoin", "ransom", ".onion",
	"your files", "your disk", "your hard", "your data", "payment", "purchase",
}

// ransomTerms returns the distinct ransom-note terms present in the boot
// area, case-folded. The evidence is the matched terms, never the text.
func ransomTerms(area []byte) []string {
	lower := bytes.ToLower(area)
	var hit []string
	for _, t := range ransomVocabulary {
		if bytes.Contains(lower, []byte(t)) {
			hit = append(hit, t)
		}
	}
	return hit
}

// ── GPT ──────────────────────────────────────────────────────────────────────

type gptHeader struct {
	headerSize  uint32
	headerCRC   uint32
	myLBA       uint64
	altLBA      uint64
	firstUsable uint64
	lastUsable  uint64
	diskGUID    string
	entriesLBA  uint64
	numEntries  uint32
	entrySize   uint32
	entriesCRC  uint32
	crcValid    bool
}

// readGPTHeader reads and checks a GPT header at the given LBA. ok is false
// when there is no GPT signature there or the header is structurally unusable.
func readGPTHeader(r io.ReaderAt, size, ss int64, lba uint64) (h gptHeader, ok bool) {
	off, inRange := lbaOffset(lba, ss)
	if !inRange {
		return h, false
	}
	raw := readAt(r, size, off, int(ss))
	if raw == nil || string(raw[:8]) != "EFI PART" {
		return h, false
	}
	h.headerSize = binary.LittleEndian.Uint32(raw[12:16])
	if h.headerSize < 92 || int64(h.headerSize) > ss {
		return h, false
	}
	h.headerCRC = binary.LittleEndian.Uint32(raw[16:20])
	h.myLBA = binary.LittleEndian.Uint64(raw[24:32])
	h.altLBA = binary.LittleEndian.Uint64(raw[32:40])
	h.firstUsable = binary.LittleEndian.Uint64(raw[40:48])
	h.lastUsable = binary.LittleEndian.Uint64(raw[48:56])
	h.diskGUID = formatGUID(raw[56:72])
	h.entriesLBA = binary.LittleEndian.Uint64(raw[72:80])
	h.numEntries = binary.LittleEndian.Uint32(raw[80:84])
	h.entrySize = binary.LittleEndian.Uint32(raw[84:88])
	h.entriesCRC = binary.LittleEndian.Uint32(raw[88:92])

	check := make([]byte, h.headerSize)
	copy(check, raw[:h.headerSize])
	check[16], check[17], check[18], check[19] = 0, 0, 0, 0
	h.crcValid = crc32.ChecksumIEEE(check) == h.headerCRC
	return h, true
}

// readGPTEntries reads the partition entry array a header points at. It
// returns nil when the array is out of bounds or out of range.
func readGPTEntries(r io.ReaderAt, size, ss int64, h gptHeader) []byte {
	if h.numEntries == 0 || h.numEntries > maxGPTEntries || h.entrySize < 128 || h.entrySize > maxGPTEntrySize {
		return nil
	}
	off, ok := lbaOffset(h.entriesLBA, ss)
	if !ok {
		return nil
	}
	return readAt(r, size, off, int(h.numEntries)*int(h.entrySize))
}

func parseGPT(r io.ReaderAt, size, ss int64, totalSectors uint64) (*GPTInfo, []Partition, []Finding) {
	var out []Finding
	primary, havePrimary := readGPTHeader(r, size, ss, 1)

	if !havePrimary {
		// No primary. If an intact backup sits at the last sector, the disk
		// was GPT and its start has been overwritten.
		if totalSectors < 3 {
			return nil, nil, nil
		}
		backup, ok := readGPTHeader(r, size, ss, totalSectors-1)
		if !ok || !backup.crcValid || backup.altLBA != 1 {
			return nil, nil, nil
		}
		out = append(out, finding("gpt.primary-destroyed", "",
			"there is no primary GPT header, but an intact backup header sits at the end of the disk",
			"backup header at LBA "+fmt.Sprint(totalSectors-1)+", disk GUID "+backup.diskGUID))
		info := &GPTInfo{
			DiskGUID: backup.diskGUID, FirstUsableLBA: backup.firstUsable, LastUsableLBA: backup.lastUsable,
			BackupLBA: totalSectors - 1, BackupChecked: true, BackupValid: true, RecoveredFromBackup: true,
		}
		entries := readGPTEntries(r, size, ss, backup)
		if entries != nil {
			info.EntriesCRCValid = crc32.ChecksumIEEE(entries) == backup.entriesCRC
		}
		parts := gptPartitions(entries, backup)
		info.Entries = len(parts)
		return info, parts, out
	}

	info := &GPTInfo{
		HeaderCRCValid: primary.crcValid, DiskGUID: primary.diskGUID,
		FirstUsableLBA: primary.firstUsable, LastUsableLBA: primary.lastUsable, BackupLBA: primary.altLBA,
	}
	if !primary.crcValid {
		out = append(out, finding("gpt.header-crc-invalid", "",
			"the primary GPT header does not match its own CRC32", ""))
	}
	entries := readGPTEntries(r, size, ss, primary)
	if entries != nil {
		info.EntriesCRCValid = crc32.ChecksumIEEE(entries) == primary.entriesCRC
	}
	if !info.EntriesCRCValid {
		detail := "the partition entry array does not match the CRC32 in the GPT header"
		if entries == nil {
			detail = "the partition entry array the GPT header points at is out of range or could not be read"
		}
		out = append(out, finding("gpt.entries-crc-invalid", "", detail, ""))
	}
	parts := gptPartitions(entries, primary)
	info.Entries = len(parts)

	// Backup header. Only checkable when the disk size is known.
	if totalSectors > 0 {
		info.BackupChecked = true
		backup, ok := readGPTHeader(r, size, ss, primary.altLBA)
		switch {
		case !ok || !backup.crcValid:
			out = append(out, finding("gpt.backup-missing", "",
				fmt.Sprintf("no valid backup GPT header at LBA %d, where the primary header says it is", primary.altLBA), ""))
		default:
			info.BackupValid = true
			info.BackupConsistent = backup.diskGUID == primary.diskGUID && backup.entriesCRC == primary.entriesCRC &&
				backup.altLBA == primary.myLBA
			// Only meaningful when the primary itself is internally valid:
			// otherwise the CRC findings above already say what is wrong.
			if !info.BackupConsistent && primary.crcValid && info.EntriesCRCValid {
				out = append(out, finding("gpt.backup-mismatch", "",
					"the primary and backup GPT headers are each valid but describe different tables",
					fmt.Sprintf("primary disk GUID %s entries CRC %08x; backup disk GUID %s entries CRC %08x",
						primary.diskGUID, primary.entriesCRC, backup.diskGUID, backup.entriesCRC)))
			}
		}
	}

	for _, p := range parts {
		last := p.StartLBA + p.Sectors - 1
		if p.StartLBA < primary.firstUsable || last > primary.lastUsable || last < p.StartLBA {
			out = append(out, finding("gpt.partition-out-of-range", "",
				fmt.Sprintf("partition %d spans LBA %d-%d outside the usable range %d-%d", p.Index, p.StartLBA, last, primary.firstUsable, primary.lastUsable), ""))
			break // one finding per table; the report lists every partition
		}
	}
	if a, b, ok := firstOverlap(parts); ok {
		out = append(out, finding("gpt.partition-overlap", "",
			fmt.Sprintf("partitions %d and %d overlap", a, b), ""))
	}
	return info, parts, out
}

func gptPartitions(entries []byte, h gptHeader) []Partition {
	var parts []Partition
	if entries == nil {
		return nil
	}
	es := int(h.entrySize)
	for i := 0; i+es <= len(entries); i += es {
		e := entries[i : i+es]
		if allZero(e[:16]) {
			continue
		}
		first := binary.LittleEndian.Uint64(e[32:40])
		last := binary.LittleEndian.Uint64(e[40:48])
		var sectors uint64
		if last >= first && last-first < ^uint64(0) {
			sectors = last - first + 1
		}
		typ := formatGUID(e[:16])
		parts = append(parts, Partition{
			Index: i/es + 1, Scheme: "gpt", Type: typ, Name: utf16Name(e[56:128]),
			StartLBA: first, Sectors: sectors, ESP: typ == gptESPType,
		})
	}
	return parts
}

// ── partition boot sectors ───────────────────────────────────────────────────

// classifyBootSector identifies what a partition begins with. It reads at
// most 2048 bytes.
func classifyBootSector(r io.ReaderAt, size, off int64) string {
	head := readAt(r, size, off, 512)
	if head == nil {
		return "unread"
	}
	switch {
	case string(head[3:11]) == "NTFS    ":
		return "ntfs"
	case string(head[3:11]) == "EXFAT   ":
		return "exfat"
	case string(head[82:87]) == "FAT32" || string(head[54:58]) == "FAT1":
		return "fat"
	case string(head[:6]) == "LUKS\xba\xbe":
		return "luks"
	case string(head[:4]) == "XFSB":
		return "xfs"
	}
	// A FAT boot sector whose type label was blanked still has the BIOS
	// parameter block: a jump, a power-of-two sector size and a FAT count.
	if (head[0] == 0xEB || head[0] == 0xE9) && head[510] == 0x55 && head[511] == 0xAA {
		bps := binary.LittleEndian.Uint16(head[11:13])
		if (bps == 512 || bps == 1024 || bps == 2048 || bps == 4096) && (head[16] == 1 || head[16] == 2) {
			return "fat"
		}
	}
	// ext2/3/4: superblock at byte 1024, magic 0xEF53 at offset 56 within it.
	if sb := readAt(r, size, off+1024, 64); sb != nil && sb[56] == 0x53 && sb[57] == 0xEF {
		return "ext"
	}
	if allZero(head) {
		return "empty"
	}
	return "unknown"
}

func describeBootSector(kind string) string {
	switch kind {
	case "empty":
		return "an all-zero sector"
	case "unknown":
		return "data the scan does not recognise as a filesystem"
	default:
		return "a " + kind + " volume"
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// formatGUID renders a 16-byte mixed-endian EFI GUID in its canonical
// lower-case text form.
func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// utf16Name decodes a NUL-terminated UTF-16LE string.
func utf16Name(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
