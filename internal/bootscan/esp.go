package bootscan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/safefs"
)

// The EFI System Partition, read as a mounted directory. The scan inventories
// every EFI binary and the firmware-capsule staging directory; it follows no
// symlink (a FAT volume has none, so one here means the path given is not an
// ESP) and reads each file once.

const (
	maxESPFiles    = 5000
	maxESPDepth    = 8
	maxEFIBinBytes = 256 << 20 // largest binary hashed; a unified kernel image can be large
)

// ESPReport is the EFI System Partition inventory.
type ESPReport struct {
	Path     string      `json:"path"`
	Files    int         `json:"files"`
	Binaries []EFIBinary `json:"binaries,omitempty"`
	// Capsules are firmware update capsules queued under EFI/UpdateCapsule.
	Capsules  []string `json:"pending_capsules,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// EFIBinary is one .efi file on the ESP.
type EFIBinary struct {
	Path   string `json:"path"` // relative to the ESP root, forward slashes
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
	// PE is whether the file is a PE image at all.
	PE        bool   `json:"pe"`
	Machine   string `json:"machine,omitempty"`
	Subsystem string `json:"subsystem,omitempty"`
	// EFI is whether the PE subsystem is one of the EFI ones.
	EFI bool `json:"efi_subsystem"`
	// Signed is whether the image carries a certificate table. Presence
	// only: the signature is not verified.
	Signed   bool   `json:"signed"`
	Modified string `json:"modified,omitempty"`
}

// ScanESP inventories a mounted EFI System Partition. secureBoot is the
// firmware's Secure Boot state when known (nil: unknown).
func ScanESP(root string, secureBoot *bool) (*ESPReport, []Finding, []string) {
	fi, err := os.Stat(root)
	if err != nil {
		return nil, nil, []string{"the EFI System Partition at " + root + " could not be read: " + err.Error()}
	}
	if !fi.IsDir() {
		return nil, nil, []string{root + " is not a directory; give the mount point of the EFI System Partition"}
	}
	// Readable at all? An ESP mounted owner-only (the usual fmask=0077) is
	// closed to a non-root scan. That is "not inspected", never an empty
	// inventory: an empty inventory would make every boot entry look stale.
	if _, err := os.ReadDir(root); err != nil {
		return nil, nil, []string{"the EFI System Partition at " + root + " could not be read (" + err.Error() + "); run as root to inventory it"}
	}
	rep := &ESPReport{Path: root}
	var out []Finding
	var notes []string
	var unsigned []string
	overLimit := false

	walkErr := filepath.WalkDir(safefs.WalkRoot(root), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			notes = append(notes, "part of the ESP could not be read: "+err.Error())
			rep.Truncated = true // the inventory is partial; nothing may be inferred from an absence
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		depth := strings.Count(rel, "/") + 1
		if d.IsDir() {
			if depth > maxESPDepth {
				rep.Truncated, overLimit = true, true
				return filepath.SkipDir
			}
			// A system32 directory at the ESP root is a published bootkit
			// staging location; no installer creates one there.
			if depth == 1 && strings.EqualFold(d.Name(), "system32") {
				out = append(out, finding("esp.windows-system-dir", rel,
					"the EFI System Partition has a system32 directory at its root", ""))
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks, devices: never followed, never opened
		}
		rep.Files++
		if rep.Files > maxESPFiles {
			rep.Truncated, overLimit = true, true
			return filepath.SkipAll
		}
		lower := strings.ToLower(rel)
		if strings.HasPrefix(lower, "efi/updatecapsule/") {
			rep.Capsules = append(rep.Capsules, rel)
			return nil
		}
		if !strings.HasSuffix(lower, ".efi") {
			return nil
		}
		bin, berr := inspectEFIBinary(path, rel)
		if berr != nil {
			notes = append(notes, rel+" could not be read: "+berr.Error())
			rep.Truncated = true // an EFI binary is missing from the inventory
			return nil
		}
		rep.Binaries = append(rep.Binaries, bin)
		switch {
		case !bin.PE:
			out = append(out, finding("esp.efi-binary-not-pe", rel,
				"a file with the .efi extension is not a PE image", ""))
		case !bin.EFI:
			out = append(out, finding("esp.non-efi-executable", rel,
				"a .efi file is a PE built for the "+bin.Subsystem+" subsystem, not an EFI application or driver", ""))
		case !bin.Signed:
			unsigned = append(unsigned, rel)
		}
		return nil
	})
	if walkErr != nil {
		notes = append(notes, "the ESP walk stopped early: "+walkErr.Error())
	}
	if overLimit {
		notes = append(notes, fmt.Sprintf("the ESP holds more than %d files or nests deeper than %d directories; the inventory is partial", maxESPFiles, maxESPDepth))
	}

	if len(unsigned) > 0 {
		// One finding for the set: ten unsigned binaries are one fact about
		// this ESP, not ten. Scored only when the firmware would be expected
		// to refuse them.
		score := 0
		detail := fmt.Sprintf("%d EFI binaries carry no signature; Secure Boot is off or its state is unknown, so this is inventory", len(unsigned))
		if secureBoot != nil && *secureBoot {
			score = scoreUnsignedSB
			detail = fmt.Sprintf("%d EFI binaries carry no signature although Secure Boot is enabled", len(unsigned))
		}
		out = append(out, findingScored("esp.unsigned-efi-binary", root, detail, strings.Join(firstN(unsigned, 8), ", "), score))
	}
	if len(rep.Capsules) > 0 {
		out = append(out, finding("esp.pending-capsule", root,
			fmt.Sprintf("%d firmware capsule(s) are queued for the next boot", len(rep.Capsules)),
			strings.Join(firstN(rep.Capsules, 8), ", ")))
	}
	return rep, out, notes
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("+%d more", len(s)-n))
}

// inspectEFIBinary hashes a file and reads its PE headers.
func inspectEFIBinary(path, rel string) (EFIBinary, error) {
	bin := EFIBinary{Path: rel}
	// Read-only, a regular file, and never through a symlink: the walk saw a
	// regular file here, and the open checks that it still is one.
	f, fi, err := safefs.OpenNoFollow(path)
	if err != nil {
		return bin, err
	}
	defer f.Close()
	bin.Size = fi.Size()
	bin.Modified = fi.ModTime().UTC().Format(time.RFC3339)

	parsePEHeader(f, bin.Size, &bin)

	if bin.Size <= maxEFIBinBytes {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return bin, err
		}
		h := sha256.New()
		if _, err := io.Copy(h, io.LimitReader(f, maxEFIBinBytes)); err != nil {
			return bin, err
		}
		bin.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	return bin, nil
}

// parsePEHeader reads the machine, the subsystem and whether a certificate
// table is declared. It reads the 64-byte DOS header and then at most 1 KiB
// at the offset that header names, wherever in the file that is; every offset
// is checked, so a truncated or lying header leaves bin.PE false or the later
// fields empty.
func parsePEHeader(r io.ReaderAt, size int64, bin *EFIBinary) {
	dos := readAt(r, size, 0, 0x40)
	if dos == nil || dos[0] != 'M' || dos[1] != 'Z' {
		return
	}
	peOff := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	if peOff < 0x40 || peOff > size-24 {
		return
	}
	n := int64(1024)
	if peOff+n > size {
		n = size - peOff
	}
	b := readAt(r, size, peOff, int(n))
	if b == nil || len(b) < 24 || string(b[:4]) != "PE\x00\x00" {
		return
	}
	bin.PE = true
	switch m := binary.LittleEndian.Uint16(b[4:]); m {
	case 0x8664:
		bin.Machine = "x86-64"
	case 0x014c:
		bin.Machine = "x86"
	case 0xaa64:
		bin.Machine = "arm64"
	case 0x01c2, 0x01c4:
		bin.Machine = "arm"
	case 0x5064:
		bin.Machine = "riscv64"
	case 0x6264:
		bin.Machine = "loongarch64"
	default:
		bin.Machine = fmt.Sprintf("0x%04x", m)
	}
	optSize := int(binary.LittleEndian.Uint16(b[20:]))
	const opt = 24
	if optSize < 70 || opt+70 > len(b) {
		return
	}
	magic := binary.LittleEndian.Uint16(b[opt:])
	sub := binary.LittleEndian.Uint16(b[opt+68:])
	switch sub {
	case 10:
		bin.Subsystem, bin.EFI = "EFI application", true
	case 11:
		bin.Subsystem, bin.EFI = "EFI boot-service driver", true
	case 12:
		bin.Subsystem, bin.EFI = "EFI runtime driver", true
	case 13:
		bin.Subsystem, bin.EFI = "EFI ROM", true
	case 1:
		bin.Subsystem = "native"
	case 2:
		bin.Subsystem = "Windows GUI"
	case 3:
		bin.Subsystem = "Windows console"
	default:
		bin.Subsystem = fmt.Sprintf("subsystem %d", sub)
	}
	// Data directory 4 is the certificate table; the directory array starts
	// at a different offset in PE32 and PE32+.
	var dirs int
	switch magic {
	case 0x10b:
		dirs = opt + 96
	case 0x20b:
		dirs = opt + 112
	default:
		return
	}
	if dirs > len(b) {
		return
	}
	numDirs := int(binary.LittleEndian.Uint32(b[dirs-4:]))
	certDir := dirs + 4*8
	if numDirs > 4 && certDir+8 <= len(b) && certDir+8 <= opt+optSize {
		bin.Signed = binary.LittleEndian.Uint32(b[certDir:]) != 0 && binary.LittleEndian.Uint32(b[certDir+4:]) != 0
	}
}
