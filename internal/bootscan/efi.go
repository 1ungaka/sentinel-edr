package bootscan

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

	PlatformKey bool `json:"platform_key_enrolled"`
	// DB and DBX summarise the allow and revocation signature databases.
	DB  *SignatureDB `json:"db,omitempty"`
	DBX *SignatureDB `json:"dbx,omitempty"`
	// MOK summarises the shim machine-owner-key list, when shim publishes it.
	MOK       *SignatureDB `json:"mok,omitempty"`
	SBATLevel string       `json:"sbat_level,omitempty"`

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
}

// SignatureDB summarises an EFI signature database variable.
type SignatureDB struct {
	Hashes       int `json:"sha256_hashes"`
	Certificates int `json:"x509_certificates"`
	Other        int `json:"other_entries,omitempty"`
	// hashes holds the SHA-256 entries for comparison; not serialised.
	hashes map[string]bool
}

// DBXComparison is the host revocation list measured against a reference.
type DBXComparison struct {
	Path            string `json:"path"`
	ReferenceHashes int    `json:"reference_hashes"`
	Missing         int    `json:"missing_on_host"`
}

// readVar reads one variable's data (attribute word removed). ok is false
// when the variable is absent, unreadable or oversized.
func readVar(dir, name, guid string) ([]byte, bool) {
	path := filepath.Join(dir, name+"-"+guid)
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxEFIVarBytes {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < 4 {
		return nil, false
	}
	return raw[4:], true
}

func boolVar(dir, name string) *bool {
	data, ok := readVar(dir, name, guidGlobal)
	if !ok || len(data) < 1 {
		return nil
	}
	v := data[0] == 1
	return &v
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

	bootIDs := map[string]bool{}
	for _, e := range entries {
		if rep.Variables >= maxEFIVars {
			notes = append(notes, fmt.Sprintf("more than %d firmware variables; the rest were not listed", maxEFIVars))
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

	rep.SecureBoot = boolVar(dir, "SecureBoot")
	rep.SetupMode = boolVar(dir, "SetupMode")
	if _, ok := readVar(dir, "PK", guidGlobal); ok {
		rep.PlatformKey = true
	}
	if data, ok := readVar(dir, "BootCurrent", guidGlobal); ok && len(data) >= 2 {
		rep.BootCurrent = fmt.Sprintf("%04X", binary.LittleEndian.Uint16(data))
	}
	inOrder := map[string]bool{}
	if data, ok := readVar(dir, "BootOrder", guidGlobal); ok {
		for i := 0; i+1 < len(data) && len(rep.BootOrder) < maxBootEntries; i += 2 {
			id := fmt.Sprintf("%04X", binary.LittleEndian.Uint16(data[i:]))
			rep.BootOrder = append(rep.BootOrder, id)
			inOrder[id] = true
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
	}
	for _, id := range ids {
		// efivarfs names keep the firmware's case; try both spellings.
		data, ok := readVar(dir, "Boot"+id, guidGlobal)
		if !ok {
			data, ok = readVar(dir, "Boot"+strings.ToLower(id), guidGlobal)
		}
		if !ok {
			continue
		}
		entry := parseLoadOption(data)
		entry.ID, entry.InOrder = id, inOrder[id]
		rep.BootEntries = append(rep.BootEntries, entry)
	}
	for _, id := range rep.BootOrder {
		if !bootIDs[id] {
			out = append(out, finding("efi.bootorder-dangling", "BootOrder",
				"BootOrder names Boot"+id+", which does not exist", ""))
		}
	}

	if data, ok := readVar(dir, "db", guidSecurity); ok {
		rep.DB = parseSignatureLists(data)
	}
	if data, ok := readVar(dir, "dbx", guidSecurity); ok {
		rep.DBX = parseSignatureLists(data)
	}
	if data, ok := readVar(dir, "MokListRT", guidShim); ok {
		rep.MOK = parseSignatureLists(data)
	}
	if data, ok := readVar(dir, "SbatLevelRT", guidShim); ok {
		rep.SBATLevel = firstLines(string(data), 2)
	}

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
// It returns nil when the data is not a well-formed sequence.
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
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxEFIVarBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxEFIVarBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
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
