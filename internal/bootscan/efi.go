package bootscan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/s-b-repo/cau/internal/safefs"
)

// Firmware variables, read from efivarfs. Each file is named <Name>-<GUID>
// and holds a 4-byte attribute word followed by the variable's data. Nothing
// here writes: efivarfs is the one place where a careless write can brick a
// machine, and this package never opens a variable for anything but reading.

const (
	guidGlobal   = "8be4df61-93ca-11d2-aa0d-00e098032b8c" // EFI_GLOBAL_VARIABLE
	guidSecurity = "d719b2cb-3d3a-4596-a3bc-dad00e67656f" // EFI_IMAGE_SECURITY_DATABASE_GUID
	guidShim     = "605dab50-e046-4300-abb6-3dd810dd8b23" // SHIM_LOCK_GUID

	guidCertSHA256 = "c1c41626-504c-4092-aca9-41f936934328" // EFI_CERT_SHA256_GUID
	guidCertX509   = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072" // EFI_CERT_X509_GUID

	maxEFIVars     = 4096
	maxEFIVarBytes = 4 << 20
	maxBootEntries = 256
	maxSBATEntries = 64
	maxSBATLine    = 256
)

// EFIReport is the firmware-variable inventory.
type EFIReport struct {
	Path      string `json:"path"`
	Variables int    `json:"variables"`
	// SecureBoot and SetupMode are nil when the variable is absent or
	// unreadable: unknown is a state, and it is not reported as "off".
	SecureBoot  *bool       `json:"secure_boot,omitempty"`
	SetupMode   *bool       `json:"setup_mode,omitempty"`
	BootCurrent string      `json:"boot_current,omitempty"`
	BootOrder   []string    `json:"boot_order,omitempty"`
	BootEntries []BootEntry `json:"boot_entries,omitempty"`

	// BootEntriesPartial is set when the variable listing or the boot-entry
	// list hit a bound: an entry missing from BootEntries may still exist.
	BootEntriesPartial bool `json:"boot_entries_partial,omitempty"`

	PlatformKey bool `json:"platform_key_enrolled"`
	// PK and KEK summarise the platform key and the key-exchange keys: who
	// may change the databases below.
	PK  *SignatureDB `json:"pk,omitempty"`
	KEK *SignatureDB `json:"kek,omitempty"`
	// DB and DBX summarise the allow and revocation signature databases.
	DB  *SignatureDB `json:"db,omitempty"`
	DBX *SignatureDB `json:"dbx,omitempty"`
	// MOK summarises the shim machine-owner-key list, when shim publishes it.
	MOK       *SignatureDB `json:"mok,omitempty"`
	SBATLevel string       `json:"sbat_level,omitempty"`
	// SBAT is the whole shim revocation level, parsed, where SBATLevel is
	// its first two lines for display.
	SBAT *SBATInfo `json:"sbat,omitempty"`

	// Unreadable names the variables above that exist and could not be read
	// (permissions, an oversized or truncated file). A variable listed here is
	// unknown, where one that is simply missing from the report is absent.
	Unreadable []string `json:"unreadable_variables,omitempty"`

	// DBXReference describes the comparison against a reference revocation
	// list, when one was supplied.
	DBXReference *DBXComparison `json:"dbx_reference,omitempty"`
}

// BootEntry is one Boot#### load option.
type BootEntry struct {
	ID          string `json:"id"` // four hex digits
	Description string `json:"description,omitempty"`
	// FilePath is the first file-path node of the entry's device path, with
	// forward slashes: the loader the firmware will start.
	FilePath string `json:"file_path,omitempty"`
	Active   bool   `json:"active"`
	InOrder  bool   `json:"in_boot_order"`
	// SHA256 is the digest of the whole load option as the firmware stores
	// it. TargetSHA256 covers everything in it except the description and
	// the active bit: the remaining attribute bits, the full device-path
	// list (which disk and partition, not only which file) and the optional
	// data handed to the loader. It is empty when the option is malformed.
	SHA256       string `json:"sha256,omitempty"`
	TargetSHA256 string `json:"target_sha256,omitempty"`
}

// SignatureDB summarises an EFI signature database variable.
type SignatureDB struct {
	Hashes       int `json:"sha256_hashes"`
	Certificates int `json:"x509_certificates"`
	Other        int `json:"other_entries,omitempty"`
	// SHA256 is the digest of the variable's data (the attribute word
	// removed) and Bytes its length: the counts say how large the database
	// is, the digest says whether it is the same database.
	SHA256 string `json:"sha256,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
	// Unparsed is set when the data is not a well-formed sequence of
	// signature lists: either it could not be walked at all, in which case
	// the counts are zero and only the digest speaks, or a list ended in a
	// partial signature entry, in which case the counted entries are the
	// whole ones and the trailing bytes are missing from them.
	Unparsed bool `json:"unparsed,omitempty"`
	// hashes holds the SHA-256 entries for comparison; not serialised.
	hashes map[string]bool
}

// DBXComparison is the host revocation list measured against a reference.
type DBXComparison struct {
	Path            string `json:"path"`
	ReferenceHashes int    `json:"reference_hashes"`
	Missing         int    `json:"missing_on_host"`
}

// SBATInfo is the shim revocation level (SbatLevelRT), parsed.
type SBATInfo struct {
	SHA256  string      `json:"sha256"`
	Entries []SBATEntry `json:"entries,omitempty"`
	// Unparsed is set when the variable is not the CSV shim writes.
	Unparsed bool `json:"unparsed,omitempty"`
}

// SBATEntry is one line of the SBAT level: a component and the lowest
// generation of it that shim still accepts.
type SBATEntry struct {
	Component  string `json:"component"`
	Generation uint64 `json:"generation"`
	// Date is the datestamp the "sbat" line carries after its generation.
	Date string `json:"date,omitempty"`
}

// readVarState reads one variable's data (attribute word removed). ok is
// false when the variable is absent, unreadable or oversized; unreadable
// tells the last two from the first, because "it is not there" is a fact and
// "it could not be read" is not.
//
// The read opens first and asks the open descriptor what it is: a stat
// followed by a read would block forever on a FIFO, which reports size zero.
func readVarState(dir, name, guid string) (data []byte, ok, unreadable bool) {
	raw, err := safefs.ReadFile(filepath.Join(dir, name+"-"+guid), maxEFIVarBytes)
	if err != nil {
		return nil, false, !errors.Is(err, os.ErrNotExist)
	}
	if len(raw) < 4 {
		return nil, false, true
	}
	return raw[4:], true, false
}

// readVar is readVarState for a caller that does not need the distinction.
func readVar(dir, name, guid string) ([]byte, bool) {
	data, ok, _ := readVarState(dir, name, guid)
	return data, ok
}

// signatureVar summarises a signature-database variable. Unlike
// parseSignatureLists it never returns nil: a variable that is present and
// malformed still has a digest, and that is still comparable.
func signatureVar(data []byte) *SignatureDB {
	db := parseSignatureLists(data)
	if db == nil {
		db = &SignatureDB{Unparsed: true}
	}
	sum := sha256.Sum256(data)
	db.SHA256, db.Bytes = hex.EncodeToString(sum[:]), len(data)
	return db
}

// parseSBATLevel decodes SbatLevelRT: lines of component,generation[,date].
// Anything else leaves Unparsed set and no entries; it never fails.
func parseSBATLevel(data []byte) *SBATInfo {
	sum := sha256.Sum256(data)
	info := &SBATInfo{SHA256: hex.EncodeToString(sum[:])}
	text := strings.TrimRight(string(data), "\x00\r\n")
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		f := strings.Split(line, ",")
		gen, err := uint64(0), error(nil)
		if len(f) >= 2 {
			gen, err = strconv.ParseUint(f[1], 10, 64)
		}
		if len(info.Entries) >= maxSBATEntries || len(line) > maxSBATLine || len(f) < 2 || len(f) > 3 ||
			err != nil || !sbatName(f[0]) || seen[f[0]] || (len(f) == 3 && !sbatName(f[2])) {
			info.Entries, info.Unparsed = nil, true
			return info
		}
		seen[f[0]] = true
		e := SBATEntry{Component: f[0], Generation: gen}
		if len(f) == 3 {
			e.Date = f[2]
		}
		info.Entries = append(info.Entries, e)
	}
	return info
}

// sbatName reports a non-empty field of printable ASCII without a space.
func sbatName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// ScanEFIVars reads the firmware-variable state from an efivarfs mount.
func ScanEFIVars(dir, dbxReference string) (*EFIReport, []Finding, []string) {
	var notes []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, []string{"no firmware variables at " + dir + ": the host did not boot through UEFI, or efivarfs is not mounted"}
		}
		return nil, nil, []string{"firmware variables at " + dir + " could not be listed: " + err.Error()}
	}
	rep := &EFIReport{Path: dir}
	var out []Finding

	// get reads a variable and records one that exists but cannot be read.
	get := func(name, guid string) ([]byte, bool) {
		data, ok, unreadable := readVarState(dir, name, guid)
		if unreadable {
			rep.Unreadable = append(rep.Unreadable, name)
		}
		return data, ok
	}
	boolVar := func(name string) *bool {
		data, ok := get(name, guidGlobal)
		if !ok {
			return nil
		}
		if len(data) < 1 {
			rep.Unreadable = append(rep.Unreadable, name)
			return nil
		}
		v := data[0] == 1
		return &v
	}

	bootIDs := map[string]bool{}
	for _, e := range entries {
		if rep.Variables >= maxEFIVars {
			notes = append(notes, fmt.Sprintf("more than %d firmware variables; the rest were not listed", maxEFIVars))
			rep.BootEntriesPartial = true
			break
		}
		rep.Variables++
		name := e.Name()
		if strings.HasSuffix(name, "-"+guidGlobal) && len(name) == len("Boot0000-")+len(guidGlobal) && strings.HasPrefix(name, "Boot") {
			id := strings.ToUpper(name[4:8])
			if _, err := hex.DecodeString(id); err == nil {
				bootIDs[id] = true
			}
		}
	}

	rep.SecureBoot = boolVar("SecureBoot")
	rep.SetupMode = boolVar("SetupMode")
	if data, ok := get("PK", guidGlobal); ok {
		rep.PlatformKey = true
		rep.PK = signatureVar(data)
	}
	if data, ok := get("KEK", guidGlobal); ok {
		rep.KEK = signatureVar(data)
	}
	if data, ok := readVar(dir, "BootCurrent", guidGlobal); ok && len(data) >= 2 {
		rep.BootCurrent = fmt.Sprintf("%04X", binary.LittleEndian.Uint16(data))
	}
	inOrder := map[string]bool{}
	if data, ok := get("BootOrder", guidGlobal); ok {
		for i := 0; i+1 < len(data) && len(rep.BootOrder) < maxBootEntries; i += 2 {
			id := fmt.Sprintf("%04X", binary.LittleEndian.Uint16(data[i:]))
			rep.BootOrder = append(rep.BootOrder, id)
			inOrder[id] = true
		}
		// The order list is bounded like the entry list: an ID past the cap
		// may still exist, and a report that does not say so presents a
		// shorter order as the whole of it.
		if len(rep.BootOrder) == maxBootEntries && len(data) > 2*maxBootEntries {
			rep.BootEntriesPartial = true
			notes = append(notes, fmt.Sprintf("BootOrder holds more than %d entries; the rest were not read", maxBootEntries))
		}
	}

	ids := make([]string, 0, len(bootIDs))
	for id := range bootIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > maxBootEntries {
		ids = ids[:maxBootEntries]
		notes = append(notes, fmt.Sprintf("more than %d boot entries; the rest were not read", maxBootEntries))
		rep.BootEntriesPartial = true
	}
	for _, id := range ids {
		// efivarfs names keep the firmware's case; try both spellings.
		data, ok := readVar(dir, "Boot"+id, guidGlobal)
		if !ok {
			data, ok = readVar(dir, "Boot"+strings.ToLower(id), guidGlobal)
		}
		if !ok {
			// Listed and not readable: the entry exists, its content is
			// unknown. It is not dropped as if it were absent.
			rep.Unreadable = append(rep.Unreadable, "Boot"+id)
			continue
		}
		entry := parseLoadOption(data)
		entry.ID, entry.InOrder = id, inOrder[id]
		sum := sha256.Sum256(data)
		entry.SHA256 = hex.EncodeToString(sum[:])
		rep.BootEntries = append(rep.BootEntries, entry)
	}
	for _, id := range rep.BootOrder {
		if !bootIDs[id] {
			out = append(out, finding("efi.bootorder-dangling", "BootOrder",
				"BootOrder names Boot"+id+", which does not exist", ""))
		}
	}

	if data, ok := get("db", guidSecurity); ok {
		rep.DB = signatureVar(data)
	}
	if data, ok := get("dbx", guidSecurity); ok {
		rep.DBX = signatureVar(data)
		if rep.DBX.Unparsed {
			note := "the revocation list (dbx) is present but is not a well-formed signature list"
			if rep.DBX.Hashes+rep.DBX.Certificates+rep.DBX.Other == 0 {
				note += "; its entries could not be counted"
			} else {
				note += "; a trailing signature entry is incomplete, so its counts are short"
			}
			notes = append(notes, note)
		}
	}
	if data, ok := get("MokListRT", guidShim); ok {
		rep.MOK = signatureVar(data)
	}
	if data, ok := get("SbatLevelRT", guidShim); ok {
		rep.SBATLevel = firstLines(string(data), 2)
		rep.SBAT = parseSBATLevel(data)
	}
	sort.Strings(rep.Unreadable)

	// ── posture and findings ──
	if rep.SetupMode != nil && *rep.SetupMode {
		out = append(out, finding("efi.setup-mode", "SetupMode",
			"the platform is in setup mode: no platform key is enrolled, so Secure Boot keys can be replaced without authorisation", ""))
	}
	switch {
	case rep.SecureBoot == nil:
		notes = append(notes, "Secure Boot state is unknown: the SecureBoot variable is absent or unreadable")
	case !*rep.SecureBoot:
		out = append(out, finding("efi.secure-boot-disabled", "SecureBoot",
			"Secure Boot is disabled: the firmware starts any boot loader, signed or not", ""))
	default:
		if rep.DBX == nil || rep.DBX.Hashes+rep.DBX.Certificates+rep.DBX.Other == 0 {
			out = append(out, finding("efi.dbx-empty", "dbx",
				"Secure Boot is enabled but the revocation list (dbx) is empty or absent, so every boot loader ever revoked is still trusted", ""))
		}
	}

	if dbxReference != "" {
		cmp, err := compareDBX(rep.DBX, dbxReference)
		if err != nil {
			notes = append(notes, "the dbx reference could not be used: "+err.Error())
		} else {
			rep.DBXReference = cmp
			if cmp.Missing > 0 {
				out = append(out, finding("efi.dbx-behind-reference", "dbx",
					fmt.Sprintf("%d of the %d SHA-256 revocations in the reference list are missing from this host's dbx", cmp.Missing, cmp.ReferenceHashes),
					"reference: "+dbxReference))
			}
		}
	}
	return rep, out, notes
}

// parseLoadOption decodes an EFI_LOAD_OPTION: a 4-byte attribute word, a
// 2-byte device-path length, a NUL-terminated UCS-2 description and a list of
// device-path nodes. Malformed input yields a partial entry, never a panic.
func parseLoadOption(data []byte) BootEntry {
	var e BootEntry
	if len(data) < 6 {
		return e
	}
	e.Active = binary.LittleEndian.Uint32(data)&1 != 0
	pathLen := int(binary.LittleEndian.Uint16(data[4:6]))
	i := 6
	descStart := i
	for i+1 < len(data) {
		if data[i] == 0 && data[i+1] == 0 {
			break
		}
		i += 2
	}
	if i+1 >= len(data) {
		return e
	}
	e.Description = utf16Name(data[descStart : i+2])
	i += 2
	// What is started and how: the attribute bits other than "active", the
	// declared path length, the device-path list and the optional data.
	h := sha256.New()
	var attrs [4]byte
	binary.LittleEndian.PutUint32(attrs[:], binary.LittleEndian.Uint32(data)&^1)
	h.Write(attrs[:])
	h.Write(data[4:6])
	h.Write(data[i:])
	e.TargetSHA256 = hex.EncodeToString(h.Sum(nil))
	end := i + pathLen
	if end > len(data) {
		end = len(data)
	}
	// Walk the device-path nodes: type, subtype, 2-byte length.
	for i+4 <= end {
		typ, sub := data[i], data[i+1]
		n := int(binary.LittleEndian.Uint16(data[i+2 : i+4]))
		if n < 4 || i+n > end {
			break
		}
		if typ == 0x7f { // end of device path
			break
		}
		if typ == 0x04 && sub == 0x04 && e.FilePath == "" { // media / file path
			e.FilePath = strings.ReplaceAll(utf16Name(data[i+4:i+n]), `\`, "/")
		}
		i += n
	}
	return e
}

// parseSignatureLists walks a sequence of EFI_SIGNATURE_LIST structures.
// It returns nil when the data is not a well-formed sequence, and a database
// marked Unparsed when a list ends in a partial signature entry: the entries
// that did parse are counted and the digest still speaks, but the list is not
// the whole of what the variable holds.
func parseSignatureLists(data []byte) *SignatureDB {
	db := &SignatureDB{hashes: map[string]bool{}}
	for off := 0; off < len(data); {
		if len(data)-off < 28 {
			return nil
		}
		typ := formatGUID(data[off : off+16])
		listSize := int(binary.LittleEndian.Uint32(data[off+16:]))
		hdrSize := int(binary.LittleEndian.Uint32(data[off+20:]))
		sigSize := int(binary.LittleEndian.Uint32(data[off+24:]))
		if listSize < 28 || listSize > len(data)-off || hdrSize < 0 || hdrSize > listSize-28 || sigSize < 16 {
			return nil
		}
		body := data[off+28+hdrSize : off+listSize]
		count := len(body) / sigSize
		if len(body)%sigSize != 0 {
			// A trailing partial entry: the declared list does not divide into
			// whole signatures. The bytes left over are not counted, and the
			// database is marked incomplete instead of returned as if every
			// entry in it had been read.
			db.Unparsed = true
		}
		switch typ {
		case guidCertSHA256:
			if sigSize != 48 {
				return nil
			}
			for i := 0; i < count; i++ {
				db.hashes[hex.EncodeToString(body[i*48+16:i*48+48])] = true
			}
			db.Hashes = len(db.hashes)
		case guidCertX509:
			db.Certificates += count
		default:
			db.Other += count
		}
		off += listSize
	}
	return db
}

// compareDBX measures the host revocation list against a reference file: the
// dbx update the UEFI Forum publishes, either as a bare signature-list
// sequence or wrapped in the authenticated-variable header it is signed with.
func compareDBX(host *SignatureDB, path string) (*DBXComparison, error) {
	// The path is the operator's, and it may be anything: a FIFO here must
	// be refused, not read until a writer that never comes.
	raw, err := safefs.ReadFile(path, maxEFIVarBytes)
	switch {
	case errors.Is(err, safefs.ErrNotRegular):
		return nil, fmt.Errorf("%s is not a regular file", path)
	case errors.Is(err, safefs.ErrTooLarge):
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxEFIVarBytes)
	case err != nil:
		return nil, err
	}
	ref := parseSignatureLists(raw)
	if ref == nil || len(ref.hashes) == 0 {
		// EFI_VARIABLE_AUTHENTICATION_2: a 16-byte EFI_TIME, then a
		// WIN_CERTIFICATE whose first field is its own total length.
		if len(raw) > 24 {
			skip := 16 + int(binary.LittleEndian.Uint32(raw[16:20]))
			if skip > 24 && skip < len(raw) {
				ref = parseSignatureLists(raw[skip:])
			}
		}
	}
	if ref == nil || len(ref.hashes) == 0 {
		return nil, fmt.Errorf("%s holds no SHA-256 signature list", path)
	}
	cmp := &DBXComparison{Path: path, ReferenceHashes: len(ref.hashes)}
	for h := range ref.hashes {
		if host == nil || !host.hashes[h] {
			cmp.Missing++
		}
	}
	return cmp, nil
}

// firstLines returns up to n lines of printable text, for a short variable
// such as the SBAT level.
func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\x00\n"), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	out := strings.Join(lines, "; ")
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// crossCheckBootEntries compares the boot entries with the files on the ESP.
func crossCheckBootEntries(efi *EFIReport, esp *ESPReport) []Finding {
	if esp == nil || esp.Truncated {
		return nil
	}
	have := map[string]bool{}
	for _, b := range esp.Binaries {
		have[strings.ToLower(b.Path)] = true
	}
	var out []Finding
	for _, e := range efi.BootEntries {
		p := strings.ToLower(strings.TrimPrefix(e.FilePath, "/"))
		if p == "" || have[p] {
			continue
		}
		out = append(out, finding("efi.boot-entry-target-missing", "Boot"+e.ID,
			"boot entry "+e.ID+" points at a file that is not on the scanned ESP", e.FilePath))
	}
	return out
}
