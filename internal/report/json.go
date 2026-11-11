package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/frameworks"
	"github.com/1ungaka/sentinel-edr/internal/peeler"
	"github.com/1ungaka/sentinel-edr/internal/provenance"
	"github.com/1ungaka/sentinel-edr/scanner"
	"github.com/1ungaka/sentinel-edr/scanner/archive"
	"github.com/1ungaka/sentinel-edr/scanner/chm"
	"github.com/1ungaka/sentinel-edr/scanner/encchain"
	"github.com/1ungaka/sentinel-edr/scanner/fusion"
	"github.com/1ungaka/sentinel-edr/scanner/iso"
	"github.com/1ungaka/sentinel-edr/scanner/linuxpkg"
	"github.com/1ungaka/sentinel-edr/scanner/lnk"
	"github.com/1ungaka/sentinel-edr/scanner/ole"
	"github.com/1ungaka/sentinel-edr/scanner/pdf"
	"github.com/1ungaka/sentinel-edr/scanner/static"
	"github.com/1ungaka/sentinel-edr/scanner/stego"
	"github.com/1ungaka/sentinel-edr/scanner/tradecraft"
)

// JSONSchemaVersion is the version of the native JSON document. See the
// package doc for the compatibility contract.
//
// 1.1.0 added the optional per-file "static" object and the summary fields
// "static_detections" / "static_threshold" (additive: minor bump).
//
// 1.2.0 added the optional per-file "stego" and "fusion" objects, the
// optional "technique" field on heuristic categories and matches, and the
// summary fields "stego_detections", "stego_threshold" and
// "fusion_detections" (additive: minor bump).
//
// 1.3.0 added "is_elf" on the heuristic and static objects, the optional
// static "elf" object (ELF anatomy) and the optional static "import_hash"
// (additive: minor bump).
//
// 1.4.0 added the optional per-file "encchain" object (encoded-executable
// analysis) and the summary fields "encchain_detections" /
// "encchain_threshold" (additive: minor bump).
//
// 1.5.0 added the optional per-file "lnk" object (Windows Shell Link
// analysis) and the summary fields "lnk_detections" / "lnk_threshold"
// (additive: minor bump).
//
// 1.6.0 added the optional per-file "ole" object (OLE compound-file / VBA
// macro analysis) and the summary fields "ole_detections" / "ole_threshold"
// (additive: minor bump).
//
// 1.7.0 added the optional per-file "pdf" object (PDF malicious-document
// analysis) and the summary fields "pdf_detections" / "pdf_threshold"
// (additive: minor bump).
//
// 1.8.0 added the optional per-file "iso" object (ISO 9660 malicious-container
// analysis) and the summary fields "iso_detections" / "iso_threshold"
// (additive: minor bump).
//
// 1.9.0 added the optional per-file "peel" object (obfuscation-chain peeler,
// NOVEL-012) and the summary fields "peel_detections" / "peel_threshold"
// (additive: minor bump).
//
// 1.10.0 added the optional "frameworks" array inside each file's "fusion"
// object: per-technique bindings to complementary models (Unified Kill Chain
// phase/stage derived here; MISP cluster / Malpedia family left for an intel
// feed to populate) so consumers can pick their scheme (additive: minor bump).
//
// 1.11.0 added the optional per-file "tradecraft" object (behavioural analysis
// of scripts and payload bytes) and the summary fields "tradecraft_detections" /
// "tradecraft_threshold" (additive: minor bump).
//
// 1.12.0 added the optional per-file "provenance" object (package-manager
// ownership and shipped-digest verification, --provenance) and the optional
// summary fields "provenance_resolved" / "provenance_modified_binaries"
// (additive: minor bump; absent from a run without --provenance).
//
// 1.13.0 added the optional "vba_member" / "embedded_vba" fields of the
// per-file "archive" object and the optional "via" field of its findings
// (an Office document's vbaProject.bin member run through the OLE pass;
// additive: minor bump).
const JSONSchemaVersion = "1.13.0"

// Overall and per-file verdict strings carried by the JSON document. They are
// lower-case on purpose: they are enum values for machines, not banners.
const (
	JSONVerdictClean      = "clean"
	JSONVerdictSuspicious = "suspicious"
	JSONVerdictMalicious  = "malicious"
	JSONVerdictError      = "error"
)

// Document is the top-level JSON report.
type Document struct {
	SchemaVersion string   `json:"schema_version"`
	Tool          ToolInfo `json:"tool"`
	GeneratedAt   string   `json:"generated_at"`
	Root          string   `json:"root,omitempty"`
	Summary       Summary  `json:"summary"`
	RunError      string   `json:"run_error,omitempty"`
	Files         []File   `json:"files"`
}

// ToolInfo identifies the producer.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Tagline string `json:"tagline,omitempty"`
}

// Summary is the run-level roll-up.
type Summary struct {
	FilesScanned         int `json:"files_scanned"`
	HashDetections       int `json:"hash_detections"`
	YaraDetections       int `json:"yara_detections"`
	HeuristicDetections  int `json:"heuristic_detections"`
	StaticDetections     int `json:"static_detections"`
	StegoDetections      int `json:"stego_detections"`
	EncChainDetections   int `json:"encchain_detections"`
	LNKDetections        int `json:"lnk_detections"`
	OLEDetections        int `json:"ole_detections"`
	PDFDetections        int `json:"pdf_detections"`
	ISODetections        int `json:"iso_detections"`
	LinuxPkgDetections   int `json:"linuxpkg_detections"`
	PeelDetections       int `json:"peel_detections"`
	ArchiveDetections    int `json:"archive_detections"`
	CHMDetections        int `json:"chm_detections"`
	TradecraftDetections int `json:"tradecraft_detections"`
	// FusionDetections counts files the fusion lattice reports as suspicious
	// although no single detector crossed its own threshold.
	FusionDetections int `json:"fusion_detections"`
	// ProvenanceResolved counts the files with a provenance object and
	// ProvenanceModifiedBinaries those carrying the modified-system-binary
	// observation. Both are omitted when the run did not resolve provenance.
	ProvenanceResolved         int    `json:"provenance_resolved,omitempty"`
	ProvenanceModifiedBinaries int    `json:"provenance_modified_binaries,omitempty"`
	Errors                     int    `json:"errors"`
	ElapsedMS                  int64  `json:"elapsed_ms"`
	HeuristicThreshold         int    `json:"heuristic_threshold"`
	StaticThreshold            int    `json:"static_threshold"`
	StegoThreshold             int    `json:"stego_threshold"`
	EncChainThreshold          int    `json:"encchain_threshold"`
	LNKThreshold               int    `json:"lnk_threshold"`
	OLEThreshold               int    `json:"ole_threshold"`
	PDFThreshold               int    `json:"pdf_threshold"`
	ISOThreshold               int    `json:"iso_threshold"`
	LinuxPkgThreshold          int    `json:"linuxpkg_threshold"`
	PeelThreshold              int    `json:"peel_threshold"`
	ArchiveThreshold           int    `json:"archive_threshold"`
	CHMThreshold               int    `json:"chm_threshold"`
	TradecraftThreshold        int    `json:"tradecraft_threshold"`
	Verdict                    string `json:"verdict"`
	FailOn                     string `json:"fail_on"`
	ExitCode                   int    `json:"exit_code"`
	ExitReason                 string `json:"exit_reason"`
}

// File is one scanned path.
type File struct {
	Path       string      `json:"path"`
	Size       *int64      `json:"size"`
	Hashes     *Hashes     `json:"hashes,omitempty"`
	Verdict    string      `json:"verdict"`
	HashMatch  *HashMatch  `json:"hash_match,omitempty"`
	Yara       []YaraHit   `json:"yara,omitempty"`
	Heuristics *Heuristics `json:"heuristics,omitempty"`
	Static     *Static     `json:"static,omitempty"`
	Stego      *Stego      `json:"stego,omitempty"`
	EncChain   *EncChain   `json:"encchain,omitempty"`
	LNK        *LNK        `json:"lnk,omitempty"`
	OLE        *OLE        `json:"ole,omitempty"`
	PDF        *PDF        `json:"pdf,omitempty"`
	ISO        *ISO        `json:"iso,omitempty"`
	LinuxPkg   *LinuxPkg   `json:"linuxpkg,omitempty"`
	Peel       *Peel       `json:"peel,omitempty"`
	Archive    *Archive    `json:"archive,omitempty"`
	CHM        *CHM        `json:"chm,omitempty"`
	Tradecraft *Tradecraft `json:"tradecraft,omitempty"`
	Fusion     *Fusion     `json:"fusion,omitempty"`
	Provenance *Provenance `json:"provenance,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
	Error      string      `json:"error,omitempty"`
	ScanTimeMS int64       `json:"scan_time_ms"`
}

// Provenance is the package-manager provenance of one file (--provenance):
// whether the host's package database owns the path and whether the scanned
// digest still matches the one the package recorded. It is context, not a
// verdict: "intact" means the database and the file agree per the host's own
// package database, which root can rewrite; it says nothing about whether the
// package is trustworthy.
type Provenance struct {
	// Manager is "dpkg", "pacman" or "rpm" (present but unsupported); empty
	// when no package database was found.
	Manager string `json:"manager,omitempty"`
	Package string `json:"package,omitempty"`
	Version string `json:"version,omitempty"`
	// State is one of owned-intact, owned-modified, owned-conffile,
	// owned-unverifiable, unowned, unsupported, unknown.
	State string `json:"state"`
	// ShippedDigest is the digest the package database recorded for the path
	// (DigestAlgo "md5" for dpkg, "sha256" or "md5" for pacman).
	ShippedDigest string `json:"shipped_digest,omitempty"`
	DigestAlgo    string `json:"digest_algo,omitempty"`
	// Finding is the modified-system-binary observation: set when an owned,
	// non-conffile executable or library no longer matches the package's
	// digest. It is reported beside the verdict and never changes it.
	Finding *ProvenanceFinding `json:"finding,omitempty"`
}

// ProvenanceFinding is the modified-system-binary observation.
type ProvenanceFinding struct {
	Class     string `json:"class"`
	Technique string `json:"technique,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Hashes are the digests the scanner computed.
type Hashes struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// HashMatch describes a signature-database hit.
type HashMatch struct {
	Type   string `json:"type"`
	Hash   string `json:"hash"`
	Threat string `json:"threat"`
}

// YaraHit is one matched rule.
type YaraHit struct {
	Rule      string       `json:"rule"`
	Namespace string       `json:"namespace,omitempty"`
	Tags      []string     `json:"tags,omitempty"`
	Meta      []MetaPair   `json:"meta,omitempty"`
	Strings   []YaraString `json:"strings,omitempty"`
}

// MetaPair is one entry of a rule's meta block. A slice of pairs rather than a
// map keeps the document order deterministic and preserves duplicate keys,
// which YARA allows.
type MetaPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// YaraString is one matched string. DataHex is the raw bytes (bounded) as hex;
// Length is the original length so a consumer can tell how much was cut.
type YaraString struct {
	Name      string `json:"name"`
	Offset    uint64 `json:"offset"`
	DataHex   string `json:"data_hex"`
	Preview   string `json:"preview"`
	Truncated bool   `json:"truncated"`
	Length    int    `json:"length"`
	XorKey    uint8  `json:"xor_key,omitempty"`
}

// Heuristics is the per-file heuristic outcome.
type Heuristics struct {
	Score      int                 `json:"score"`
	Threshold  int                 `json:"threshold"`
	Detected   bool                `json:"detected"`
	IsPE       bool                `json:"is_pe"`
	IsELF      bool                `json:"is_elf"`
	Skipped    string              `json:"skipped,omitempty"`
	Categories []HeuristicCategory `json:"categories,omitempty"`
	Matches    []HeuristicMatch    `json:"matches,omitempty"`
	Error      string              `json:"error,omitempty"`
}

// HeuristicCategory explains how one category contributed to the score.
type HeuristicCategory struct {
	Category  string `json:"category"`
	Raw       int    `json:"raw"`
	Applied   int    `json:"applied"`
	Cap       int    `json:"cap,omitempty"`
	Weak      bool   `json:"weak,omitempty"`
	Technique string `json:"technique,omitempty"`
}

// HeuristicMatch is one indicator.
type HeuristicMatch struct {
	Indicator string   `json:"indicator"`
	Category  string   `json:"category"`
	Source    string   `json:"source"`
	Pattern   string   `json:"pattern,omitempty"`
	Score     int      `json:"score,omitempty"`
	Hits      int      `json:"hits,omitempty"`
	Examples  []string `json:"examples,omitempty"`
	Technique string   `json:"technique,omitempty"`
}

// Static is the per-file structural analysis: entropy, fuzzy digests, PE or
// ELF anatomy and the labeled anomalies that scored. Every string came from
// the scanned file and is bounded; Signature.Verified is always false because
// the engine does not hold a trust store, and Note says so.
type Static struct {
	Score      int     `json:"score"`
	Threshold  int     `json:"threshold"`
	Detected   bool    `json:"detected"`
	IsPE       bool    `json:"is_pe"`
	IsELF      bool    `json:"is_elf"`
	Skipped    string  `json:"skipped,omitempty"`
	Error      string  `json:"error,omitempty"`
	ParseError string  `json:"parse_error,omitempty"`
	Entropy    float64 `json:"entropy"`
	// HighEntropyFraction is the share of 256-byte windows above 7.0 bits.
	HighEntropyFraction float64 `json:"high_entropy_fraction"`
	TLSH                string  `json:"tlsh,omitempty"`
	SSDeep              string  `json:"ssdeep,omitempty"`
	Imphash             string  `json:"imphash,omitempty"`
	// ImportHash is the import-set clustering key of an ELF (MD5 over the
	// sorted undefined symbol names; a CAU key, not telfhash). PE files carry
	// the pefile-compatible imphash instead.
	ImportHash string `json:"import_hash,omitempty"`

	IsMachO      bool               `json:"is_macho"`
	PE           *StaticPE          `json:"pe,omitempty"`
	ELF          *StaticELF         `json:"elf,omitempty"`
	MachO        *StaticMachO       `json:"macho,omitempty"`
	Anomalies    []StaticAnomaly    `json:"anomalies,omitempty"`
	Categories   []StaticCategory   `json:"categories,omitempty"`
	FuzzyMatches []StaticFuzzyMatch `json:"fuzzy_matches,omitempty"`
	Warnings     []string           `json:"warnings,omitempty"`
}

// StaticPE is the PE anatomy summary.
type StaticPE struct {
	Format       string           `json:"format"`
	Machine      string           `json:"machine"`
	Subsystem    string           `json:"subsystem"`
	IsDLL        bool             `json:"is_dll"`
	IsCLR        bool             `json:"is_clr,omitempty"`
	Timestamp    string           `json:"timestamp"`
	EntryPoint   uint32           `json:"entry_point"`
	EntrySection string           `json:"entry_section,omitempty"`
	ImportCount  int              `json:"import_count"`
	DLLs         []string         `json:"dlls,omitempty"`
	TLSCallbacks int              `json:"tls_callbacks,omitempty"`
	Sections     []StaticSection  `json:"sections"`
	Overlay      *StaticOverlay   `json:"overlay,omitempty"`
	Packer       *StaticPacker    `json:"packer,omitempty"`
	Rich         *StaticRich      `json:"rich,omitempty"`
	Signature    *StaticSignature `json:"signature,omitempty"`
	Debug        *StaticDebug     `json:"debug,omitempty"`
}

// StaticELF is the ELF anatomy summary. Module.Signed reports the presence
// of the appended signature only; nothing is verified against a keyring.
// StaticMachO is the Mach-O anatomy summary (thin or universal).
type StaticMachO struct {
	Magic     string            `json:"magic"`
	ByteOrder string            `json:"byte_order"`
	Fat       bool              `json:"fat"`
	Arches    []StaticMachOArch `json:"arches"`
}

// StaticMachOArch is one architecture slice of a Mach-O.
type StaticMachOArch struct {
	CPU          string   `json:"cpu"`
	FileType     string   `json:"filetype"`
	Flags        []string `json:"flags,omitempty"`
	Signed       bool     `json:"signed"`
	Encrypted    bool     `json:"encrypted,omitempty"`
	EntrySegment int      `json:"entry_segment"`
	ImportCount  int      `json:"import_count"`
	ImportHash   string   `json:"import_hash,omitempty"`
	Dylibs       []string `json:"dylibs,omitempty"`
}

type StaticELF struct {
	Class           string   `json:"class"`
	ByteOrder       string   `json:"byte_order"`
	Type            string   `json:"type"`
	Machine         string   `json:"machine"`
	OSABI           string   `json:"osabi"`
	EntryPoint      uint64   `json:"entry_point"`
	EntrySection    string   `json:"entry_section,omitempty"`
	Interp          string   `json:"interp,omitempty"`
	PIE             bool     `json:"pie"`
	Static          bool     `json:"static"`
	StackExecutable bool     `json:"stack_executable"`
	RelRO           bool     `json:"relro"`
	TextRel         bool     `json:"textrel,omitempty"`
	BuildID         string   `json:"build_id,omitempty"`
	ABITag          string   `json:"abi_tag,omitempty"`
	SOName          string   `json:"soname,omitempty"`
	Needed          []string `json:"needed,omitempty"`
	RPath           []string `json:"rpath,omitempty"`
	RunPath         []string `json:"runpath,omitempty"`
	ImportCount     int      `json:"import_count"`
	ExportCount     int      `json:"export_count"`
	InitArrayCount  int      `json:"init_array_count,omitempty"`
	// Telfhash is the Trend Micro telfhash over the filtered symbol set; empty
	// when the symbol set is below TLSH's floor (see TelfhashNote).
	Telfhash     string `json:"telfhash,omitempty"`
	TelfhashNote string `json:"telfhash_note,omitempty"`
	// SyscallStubs is the count of raw system-call instructions in executable
	// sections (the raw-syscall interposer / loader tell).
	SyscallStubs     int                `json:"syscall_stubs,omitempty"`
	Segments         []StaticELFSegment `json:"segments"`
	Sections         []StaticELFSection `json:"sections"`
	NoSectionHeaders bool               `json:"no_section_headers,omitempty"`
	Overlay          *StaticOverlay     `json:"overlay,omitempty"`
	Packer           *StaticPacker      `json:"packer,omitempty"`
	Module           *StaticELFModule   `json:"module,omitempty"`
	AppImage         int                `json:"appimage,omitempty"`
}

// StaticELFSegment is one program header plus its measured entropy.
type StaticELFSegment struct {
	Type     string  `json:"type"`
	Perms    string  `json:"perms"`
	Offset   uint64  `json:"offset"`
	FileSize uint64  `json:"file_size"`
	MemSize  uint64  `json:"mem_size"`
	Entropy  float64 `json:"entropy"`
	Entry    bool    `json:"entry,omitempty"`
}

// StaticELFSection is one section header plus its measured entropy.
type StaticELFSection struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Perms   string  `json:"perms"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
	Entry   bool    `json:"entry,omitempty"`
}

// StaticELFModule is what a kernel module declares about itself.
type StaticELFModule struct {
	Name           string `json:"name,omitempty"`
	Vermagic       string `json:"vermagic,omitempty"`
	License        string `json:"license,omitempty"`
	SrcVersion     string `json:"srcversion,omitempty"`
	Signed         bool   `json:"signed"`
	SignatureBytes int    `json:"signature_bytes,omitempty"`
	Note           string `json:"note"`
}

// StaticSection is one section header plus its measured entropy.
type StaticSection struct {
	Name        string  `json:"name"`
	Perms       string  `json:"perms"`
	VirtualSize uint32  `json:"virtual_size"`
	RawSize     uint32  `json:"raw_size"`
	Entropy     float64 `json:"entropy"`
	Entry       bool    `json:"entry,omitempty"`
}

// StaticOverlay describes data appended after the last section.
type StaticOverlay struct {
	Offset           int64   `json:"offset"`
	Size             int64   `json:"size"`
	Entropy          float64 `json:"entropy"`
	CertificateBytes int64   `json:"certificate_bytes,omitempty"`
}

// StaticPacker names the identified packer and its evidence.
type StaticPacker struct {
	Name     string   `json:"name"`
	Generic  bool     `json:"generic,omitempty"`
	Evidence []string `json:"evidence"`
}

// StaticRich summarises the Rich header.
type StaticRich struct {
	ChecksumValid bool `json:"checksum_valid"`
	Entries       int  `json:"entries"`
}

// StaticSignature is the parsed Authenticode blob.
type StaticSignature struct {
	Parsed             bool         `json:"parsed"`
	Verified           bool         `json:"verified"`
	Note               string       `json:"note"`
	ParseError         string       `json:"parse_error,omitempty"`
	DigestAlgorithm    string       `json:"digest_algorithm,omitempty"`
	Signer             string       `json:"signer,omitempty"`
	Countersigned      bool         `json:"countersigned"`
	ChainSelfContained bool         `json:"chain_self_contained"`
	ChainTerminus      string       `json:"chain_terminus,omitempty"`
	Certificates       []StaticCert `json:"certificates,omitempty"`
}

// StaticCert is one embedded certificate.
type StaticCert struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	Serial      string `json:"serial"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	SelfSigned  bool   `json:"self_signed"`
	CodeSigning bool   `json:"code_signing"`
	IsCA        bool   `json:"is_ca"`
	Signer      bool   `json:"signer,omitempty"`
}

// StaticDebug is the debug-directory summary. PDBPath is metadata only.
type StaticDebug struct {
	Timestamp    string `json:"timestamp,omitempty"`
	Reproducible bool   `json:"reproducible,omitempty"`
	PDBPath      string `json:"pdb_path,omitempty"`
}

// StaticAnomaly is one labeled structural finding.
type StaticAnomaly struct {
	Class     string `json:"class"`
	Category  string `json:"category"`
	Score     int    `json:"score"`
	Detail    string `json:"detail"`
	Technique string `json:"technique,omitempty"`
}

// StaticCategory explains how one category contributed to the score.
type StaticCategory struct {
	Category string `json:"category"`
	Raw      int    `json:"raw"`
	Applied  int    `json:"applied"`
	Cap      int    `json:"cap"`
}

// StaticFuzzyMatch is a similarity-database hit.
type StaticFuzzyMatch struct {
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	Threat   string `json:"threat"`
	Distance int    `json:"distance,omitempty"`
	Score    int    `json:"score,omitempty"`
}

// Stego is the per-file invisible-codepoint analysis of a text or code
// artifact. Every string came from the scanned file and is bounded.
type Stego struct {
	Score     int    `json:"score"`
	Threshold int    `json:"threshold"`
	Detected  bool   `json:"detected"`
	IsText    bool   `json:"is_text"`
	Encoding  string `json:"encoding,omitempty"`
	Skipped   string `json:"skipped,omitempty"`
	Error     string `json:"error,omitempty"`
	// Suspicious occurrences scored; Benign were excused by a context rule;
	// Info are unscored marks (BOM, directional marks, soft hyphen).
	Suspicious   int              `json:"suspicious"`
	Benign       int              `json:"benign,omitempty"`
	Info         int              `json:"info,omitempty"`
	LongestRun   int              `json:"longest_run,omitempty"`
	ASCIICarrier int              `json:"ascii_carrier,omitempty"`
	Codepoints   []StegoCodepoint `json:"codepoints,omitempty"`
	Findings     []StegoFinding   `json:"findings,omitempty"`
}

// StegoCodepoint summarises one invisible codepoint's occurrences.
type StegoCodepoint struct {
	Codepoint   string         `json:"codepoint"`
	Name        string         `json:"name"`
	Class       string         `json:"class"`
	Count       int            `json:"count"`
	Benign      int            `json:"benign_context,omitempty"`
	FirstOffset int            `json:"first_offset"`
	FirstLine   int            `json:"first_line"`
	Excuses     map[string]int `json:"excuses,omitempty"`
	Examples    []string       `json:"examples,omitempty"`
}

// StegoFinding is one labeled, scored class of evidence.
type StegoFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Detail    string `json:"detail"`
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
}

// EncChain is the per-file encoded-executable analysis: base64/hex layers
// that decode to a PE or ELF header.
type EncChain struct {
	Score        int               `json:"score"`
	Threshold    int               `json:"threshold"`
	Detected     bool              `json:"detected"`
	Skipped      string            `json:"skipped,omitempty"`
	Candidates   int               `json:"candidates,omitempty"`
	LayersPeeled int               `json:"layers_peeled,omitempty"`
	Budget       bool              `json:"budget_exhausted,omitempty"`
	Findings     []EncChainFinding `json:"findings,omitempty"`
}

// EncChainFinding is one decoded executable.
type EncChainFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Encoding  string `json:"encoding"`
	Depth     int    `json:"depth"`
	Offset    int    `json:"offset"`
	RunBytes  int    `json:"run_bytes"`
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
	Detail    string `json:"detail"`
}

// LNK is the per-file Windows Shell Link analysis: malicious-shortcut
// delivery signals read from the [MS-SHLLINK] structure.
type LNK struct {
	Score     int          `json:"score"`
	Threshold int          `json:"threshold"`
	Detected  bool         `json:"detected"`
	Skipped   string       `json:"skipped,omitempty"`
	TargetExt string       `json:"target_ext,omitempty"`
	ArgsLen   int          `json:"args_len,omitempty"`
	Findings  []LNKFinding `json:"findings,omitempty"`
}

// LNKFinding is one Shell Link detection signal.
type LNKFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// OLE is the per-file OLE compound-file / VBA macro analysis.
type OLE struct {
	Score     int          `json:"score"`
	Threshold int          `json:"threshold"`
	Detected  bool         `json:"detected"`
	Skipped   string       `json:"skipped,omitempty"`
	HasVBA    bool         `json:"has_vba,omitempty"`
	Modules   int          `json:"modules,omitempty"`
	Findings  []OLEFinding `json:"findings,omitempty"`
}

// OLEFinding is one OLE macro detection signal.
type OLEFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// PDF is the per-file PDF malicious-document analysis.
type PDF struct {
	Score         int          `json:"score"`
	Threshold     int          `json:"threshold"`
	Detected      bool         `json:"detected"`
	Skipped       string       `json:"skipped,omitempty"`
	Version       string       `json:"version,omitempty"`
	HasJavaScript bool         `json:"has_javascript,omitempty"`
	HasOpenAction bool         `json:"has_openaction,omitempty"`
	Encrypted     bool         `json:"encrypted,omitempty"`
	Findings      []PDFFinding `json:"findings,omitempty"`
}

// PDFFinding is one PDF detection signal.
type PDFFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// ISO is the per-file ISO 9660 malicious-container analysis.
type ISO struct {
	Score     int          `json:"score"`
	Threshold int          `json:"threshold"`
	Detected  bool         `json:"detected"`
	Skipped   string       `json:"skipped,omitempty"`
	VolumeID  string       `json:"volume_id,omitempty"`
	Files     int          `json:"files,omitempty"`
	HasJoliet bool         `json:"has_joliet,omitempty"`
	Findings  []ISOFinding `json:"findings,omitempty"`
}

// ISOFinding is one ISO container detection signal.
type ISOFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// Archive is the per-file compressed-container analysis (ZIP/TAR/gzip).
type Archive struct {
	Score        int    `json:"score"`
	Threshold    int    `json:"threshold"`
	Detected     bool   `json:"detected"`
	Skipped      string `json:"skipped,omitempty"`
	Format       string `json:"format,omitempty"`
	Members      int    `json:"members,omitempty"`
	Uncompressed int64  `json:"uncompressed_bytes,omitempty"`
	Encrypted    int    `json:"encrypted_members,omitempty"`
	Executables  int    `json:"executable_members,omitempty"`
	NotInspected string `json:"not_inspected,omitempty"`
	// VBAMember names the vbaProject.bin member an Office document carried,
	// and EmbeddedVBA is the OLE pass's result over it (schema 1.13.0). Its
	// findings are also in Findings, prefixed archive.ooxml; this is detail.
	VBAMember   string           `json:"vba_member,omitempty"`
	EmbeddedVBA *OLE             `json:"embedded_vba,omitempty"`
	Findings    []ArchiveFinding `json:"findings,omitempty"`
}

// ArchiveFinding is one container detection signal.
type ArchiveFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
	// Via is the archive member the finding was read from, when it came
	// from inside a member rather than from the container itself.
	Via string `json:"via,omitempty"`
}

// Tradecraft is the per-file behavioural analysis of scripts and payload bytes.
type Tradecraft struct {
	Score     int          `json:"score"`
	Threshold int          `json:"threshold"`
	Detected  bool         `json:"detected"`
	Skipped   string       `json:"skipped,omitempty"`
	Decoded   int          `json:"decoded,omitempty"`
	Findings  []CHMFinding `json:"findings,omitempty"`
}

// CHM is the per-file Compiled HTML Help analysis.
type CHM struct {
	Score        int          `json:"score"`
	Threshold    int          `json:"threshold"`
	Detected     bool         `json:"detected"`
	Skipped      string       `json:"skipped,omitempty"`
	Entries      int          `json:"entries,omitempty"`
	ContentFiles int          `json:"content_files,omitempty"`
	NotInspected string       `json:"not_inspected,omitempty"`
	Findings     []CHMFinding `json:"findings,omitempty"`
}

// CHMFinding is one CHM detection signal.
type CHMFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// LinuxPkg is the per-file Linux software-package analysis (.deb/.rpm/Arch/
// Flatpak/AppImage/PKGBUILD install-script tradecraft).
type LinuxPkg struct {
	Score     int               `json:"score"`
	Threshold int               `json:"threshold"`
	Detected  bool              `json:"detected"`
	Skipped   string            `json:"skipped,omitempty"`
	Format    string            `json:"format,omitempty"`
	Name      string            `json:"name,omitempty"`
	Scripts   []string          `json:"scripts,omitempty"`
	Findings  []LinuxPkgFinding `json:"findings,omitempty"`
}

// LinuxPkgFinding is one Linux-package detection signal.
type LinuxPkgFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// Peel is the per-file obfuscation-chain analysis (NOVEL-012).
type Peel struct {
	Score            int           `json:"score"`
	Threshold        int           `json:"threshold"`
	Detected         bool          `json:"detected"`
	Skipped          string        `json:"skipped,omitempty"`
	Outcome          string        `json:"outcome"`
	MaxDepth         int           `json:"max_depth"`
	PrimarySignature string        `json:"primary_signature,omitempty"`
	Exhausted        bool          `json:"exhausted,omitempty"`
	ExhaustReason    string        `json:"exhaust_reason,omitempty"`
	Findings         []PeelFinding `json:"findings,omitempty"`
}

// PeelFinding is one obfuscation-chain detection signal.
type PeelFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
	Detail    string `json:"detail"`
}

// Fusion is the lattice's view over every detector that ran on the file.
type Fusion struct {
	Tier       string  `json:"tier"`
	Score      float64 `json:"score"`
	Threshold  float64 `json:"threshold"`
	Confidence string  `json:"confidence,omitempty"`
	// Agreed names the sources that counted, strongest first; Techniques and
	// Novel are the union of their evidence's ATT&CK / NOVEL ids.
	Agreed     []string `json:"agreed,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
	Novel      []string `json:"novel,omitempty"`
	// Frameworks binds each technique to complementary models (Unified Kill
	// Chain phase/stage; MISP/Malpedia left for an intel feed) so consumers are
	// not tied to a single registry.
	Frameworks []FrameworkBinding `json:"frameworks,omitempty"`
	// Corroborated is true when the suspicious tier was reached only through
	// corroboration of sub-threshold sources.
	Corroborated bool           `json:"corroborated,omitempty"`
	Explanation  string         `json:"explanation"`
	Sources      []FusionSource `json:"sources"`
}

// FrameworkBinding is one technique's placement across frameworks. UKCPhase and
// UKCStage are derived from the ATT&CK tactic; MISPCluster and MalpediaFamily
// are populated only when an intelligence feed supplied them (never guessed).
type FrameworkBinding struct {
	Technique      string `json:"technique"`
	UKCPhase       string `json:"ukc_phase,omitempty"`
	UKCStage       string `json:"ukc_stage,omitempty"`
	MISPCluster    string `json:"misp_cluster,omitempty"`
	MalpediaFamily string `json:"malpedia_family,omitempty"`
}

// FusionSource is one detector's line in the fused verdict.
type FusionSource struct {
	Name      string           `json:"name"`
	Role      string           `json:"role"`
	Hit       bool             `json:"hit,omitempty"`
	Score     int              `json:"score,omitempty"`
	Threshold int              `json:"threshold,omitempty"`
	Ratio     float64          `json:"ratio,omitempty"`
	Weight    float64          `json:"weight,omitempty"`
	Counted   bool             `json:"counted"`
	Skipped   string           `json:"skipped,omitempty"`
	Evidence  []FusionEvidence `json:"evidence,omitempty"`
}

// FusionEvidence is one labeled reason a source contributed.
type FusionEvidence struct {
	Label     string `json:"label"`
	Detail    string `json:"detail,omitempty"`
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
	Weight    int    `json:"weight,omitempty"`
}

// JSONReporter writes the native JSON document.
type JSONReporter struct {
	cfg config
}

// NewJSONReporter builds a reporter from the shared options.
func NewJSONReporter(opts ...Option) *JSONReporter {
	return &JSONReporter{cfg: buildConfig(opts)}
}

// Build assembles the document without encoding it, for callers that want to
// post-process or embed it.
func (r *JSONReporter) Build(in Input) Document {
	return r.cfg.buildDocument(in)
}

// Write encodes the document to w. It fails only if encoding or writing fails.
func (r *JSONReporter) Write(w io.Writer, in Input) error {
	doc := r.Build(in)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if r.cfg.indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("report: encode json: %w", err)
	}
	return nil
}

// buildDocument is shared with the text reporter's summary logic.
func (c config) buildDocument(in Input) Document {
	policy := &ExitPolicy{cfg: c}
	code, reason := policy.decide(in)

	doc := Document{
		SchemaVersion: JSONSchemaVersion,
		Tool: ToolInfo{
			Name:    c.toolName,
			Version: c.toolVersion,
			Tagline: c.toolTagline,
		},
		GeneratedAt: c.timestamp(),
		Root:        c.root,
		Summary: Summary{
			FilesScanned:               len(in.AllPaths()),
			HashDetections:             in.HashDetectionCount(),
			YaraDetections:             in.YaraDetectionCount(),
			HeuristicDetections:        len(in.HeuristicBreach(c.heuristicThreshold)),
			StaticDetections:           len(in.StaticBreach(c.staticThreshold)),
			StegoDetections:            len(in.StegoBreach(c.stegoThreshold)),
			EncChainDetections:         len(in.EncChainBreach(c.encChainThreshold)),
			LNKDetections:              len(in.LNKBreach(c.lnkThreshold)),
			OLEDetections:              len(in.OLEBreach(c.oleThreshold)),
			PDFDetections:              len(in.PDFBreach(c.pdfThreshold)),
			ISODetections:              len(in.ISOBreach(c.isoThreshold)),
			ArchiveDetections:          len(in.ArchiveBreach(c.archiveThreshold)),
			CHMDetections:              len(in.CHMBreach(c.chmThreshold)),
			TradecraftDetections:       len(in.TradecraftBreach(c.tradecraftThreshold)),
			LinuxPkgDetections:         len(in.LinuxPkgBreach(c.linuxPkgThreshold)),
			PeelDetections:             len(in.PeelBreach(c.peelThreshold)),
			FusionDetections:           len(in.FusionCorroborated()),
			ProvenanceResolved:         in.ProvenanceResolvedCount(),
			ProvenanceModifiedBinaries: len(in.ProvenanceModifiedBinaries()),
			Errors:                     in.ErrorCount(),
			ElapsedMS:                  in.Elapsed.Milliseconds(),
			HeuristicThreshold:         c.heuristicThreshold,
			StaticThreshold:            c.staticThreshold,
			StegoThreshold:             c.stegoThreshold,
			EncChainThreshold:          c.encChainThreshold,
			LNKThreshold:               c.lnkThreshold,
			OLEThreshold:               c.oleThreshold,
			PDFThreshold:               c.pdfThreshold,
			ISOThreshold:               c.isoThreshold,
			ArchiveThreshold:           c.archiveThreshold,
			CHMThreshold:               c.chmThreshold,
			TradecraftThreshold:        c.tradecraftThreshold,
			LinuxPkgThreshold:          c.linuxPkgThreshold,
			PeelThreshold:              c.peelThreshold,
			Verdict:                    c.overallVerdict(in),
			FailOn:                     c.failOn.String(),
			ExitCode:                   code,
			ExitReason:                 reason,
		},
		RunError: c.errorString(in.RunError),
		Files:    []File{},
	}

	byPath := in.HeuristicsByPath()
	// Indexed rather than copied: the document is assembled for a whole tree at
	// once, and holding a second copy of every ScanResult by value (the map this
	// used to be) doubles the peak for no gain over the index.
	at := make(map[string]int, len(in.Results))
	for i, res := range in.Results {
		at[res.FilePath] = i // last one wins, mirroring HeuristicsByPath
	}

	for _, p := range in.AllPaths() {
		var res scanner.ScanResult
		var hasResult bool
		if i, ok := at[p]; ok {
			res, hasResult = in.Results[i], true
		}
		h, hasHeur := byPath[p]
		var hp *scanner.HeuristicResult
		if hasHeur {
			hp = &h
		}
		var rp *scanner.ScanResult
		if hasResult {
			rp = &res
		}
		f := c.buildFile(p, rp, hp)
		if hasResult {
			if prov, ok := in.ProvenanceFor(p); ok {
				f.Provenance = c.buildProvenance(prov)
			}
		}
		doc.Files = append(doc.Files, f)
	}
	return doc
}

// buildProvenance renders one provenance answer. Every string came from the
// host's package database, which is attacker-writable with root, so each is
// bounded like any other file-derived field.
func (c config) buildProvenance(p provenance.Provenance) *Provenance {
	out := &Provenance{
		Manager:       c.boundedMessage(p.Manager),
		Package:       c.boundedMessage(p.Package),
		Version:       c.boundedMessage(p.Version),
		State:         c.boundedMessage(string(p.State)),
		ShippedDigest: c.boundedHash(p.ShippedDigest),
		DigestAlgo:    c.boundedMessage(p.DigestAlgo),
	}
	if p.Finding != nil {
		out.Finding = &ProvenanceFinding{
			Class:     c.boundedMessage(p.Finding.Class),
			Technique: c.boundedMessage(p.Finding.Technique),
			Kind:      c.boundedMessage(p.Finding.Kind),
			Detail:    c.boundedMessage(p.Finding.Detail),
		}
	}
	return out
}

// overallVerdict folds the run into one word. "error" is reserved for a run
// that could not execute; per-file errors are counted in Summary.Errors and
// drive the exit code, but a run that did scan files still gets a verdict for
// the files it did see.
func (c config) overallVerdict(in Input) string {
	switch {
	case in.RunError != nil:
		return JSONVerdictError
	case len(in.Malicious()) > 0:
		return JSONVerdictMalicious
	case len(in.HeuristicBreach(c.heuristicThreshold)) > 0, len(in.StaticBreach(c.staticThreshold)) > 0,
		len(in.StegoBreach(c.stegoThreshold)) > 0, len(in.EncChainBreach(c.encChainThreshold)) > 0,
		len(in.LNKBreach(c.lnkThreshold)) > 0, len(in.OLEBreach(c.oleThreshold)) > 0,
		len(in.PDFBreach(c.pdfThreshold)) > 0, len(in.ISOBreach(c.isoThreshold)) > 0,
		len(in.LinuxPkgBreach(c.linuxPkgThreshold)) > 0,
		len(in.PeelBreach(c.peelThreshold)) > 0,
		len(in.FusionCorroborated()) > 0:
		return JSONVerdictSuspicious
	default:
		return JSONVerdictClean
	}
}

func (c config) buildFile(p string, res *scanner.ScanResult, h *scanner.HeuristicResult) File {
	f := File{
		Path:    c.boundedMessage(p),
		Verdict: JSONVerdictClean,
	}

	// The scanner records the size it saw; fall back to stat only when it did
	// not, so the report describes the bytes that were actually scanned.
	if res != nil && res.Size > 0 {
		s := res.Size
		f.Size = &s
	} else if size, err := c.stat(p); err == nil {
		s := size
		f.Size = &s
	}

	if res != nil {
		f.ScanTimeMS = res.ScanTime.Milliseconds()
		for _, w := range res.Warnings {
			f.Warnings = append(f.Warnings, c.boundedMessage(w))
		}
		if res.MD5 != "" || res.SHA1 != "" || res.SHA256 != "" {
			f.Hashes = &Hashes{
				MD5:    c.boundedHash(res.MD5),
				SHA1:   c.boundedHash(res.SHA1),
				SHA256: c.boundedHash(res.SHA256),
			}
		}
		if res.Error != nil {
			f.Error = c.errorString(res.Error)
			f.Verdict = JSONVerdictError
		}
		if res.Detected {
			f.HashMatch = &HashMatch{
				Type:   c.boundedMessage(res.MatchType),
				Hash:   c.boundedHash(res.MatchHash),
				Threat: c.boundedMessage(res.ThreatName),
			}
		}
		for _, m := range res.YaraMatches {
			f.Yara = append(f.Yara, c.buildYara(m))
		}
		if isMalicious(*res) {
			f.Verdict = JSONVerdictMalicious
		}
		if res.Static != nil {
			f.Static = c.buildStatic(res.Static)
			if f.Static.Error != "" && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictError
			}
			if f.Static.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.Stego != nil {
			f.Stego = c.buildStego(res.Stego)
			if f.Stego.Error != "" && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictError
			}
			if f.Stego.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.EncChain != nil {
			f.EncChain = c.buildEncChain(res.EncChain)
			if f.EncChain.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.LNK != nil {
			f.LNK = c.buildLNK(res.LNK)
			if f.LNK.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.OLE != nil {
			f.OLE = c.buildOLE(res.OLE)
			if f.OLE.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.PDF != nil {
			f.PDF = c.buildPDF(res.PDF)
			if f.PDF.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.ISO != nil {
			f.ISO = c.buildISO(res.ISO)
			if f.ISO.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.LinuxPkg != nil {
			f.LinuxPkg = c.buildLinuxPkg(res.LinuxPkg)
			if f.LinuxPkg.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.Peel != nil {
			f.Peel = c.buildPeel(res.Peel)
			if f.Peel.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.Archive != nil {
			f.Archive = c.buildArchive(res.Archive)
			if f.Archive.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.CHM != nil {
			f.CHM = c.buildCHM(res.CHM)
			if f.CHM.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.Tradecraft != nil {
			f.Tradecraft = c.buildTradecraft(res.Tradecraft)
			if f.Tradecraft.Detected && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
		if res.Fusion != nil {
			f.Fusion = c.buildFusion(res.Fusion)
			// The lattice never lowers a verdict; it can only raise CLEAN to
			// SUSPICIOUS when sub-threshold sources corroborate each other.
			if fusionCorroborated(res.Fusion) && f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictSuspicious
			}
		}
	}

	if h != nil {
		hh := &Heuristics{
			Score:     h.Score,
			Threshold: thresholdFor(*h, c.heuristicThreshold),
			Detected:  heuristicBreached(*h, c.heuristicThreshold),
			IsPE:      h.IsPE,
			IsELF:     h.IsELF,
			Skipped:   c.boundedMessage(h.Skipped),
		}
		for _, cs := range h.Categories {
			hh.Categories = append(hh.Categories, HeuristicCategory{
				Category:  c.boundedMessage(cs.Category),
				Raw:       cs.Raw,
				Applied:   cs.Applied,
				Cap:       cs.Cap,
				Weak:      cs.Weak,
				Technique: c.boundedMessage(cs.Technique),
			})
		}
		for _, m := range h.Matches {
			hm := HeuristicMatch{
				Indicator: c.boundedMessage(m.Indicator),
				Category:  c.boundedMessage(m.Category),
				Source:    c.boundedMessage(m.Source),
				Score:     m.Score,
				Hits:      m.Hits,
				Technique: c.boundedMessage(m.Technique),
			}
			if m.Pattern != "" && m.Pattern != m.Indicator {
				hm.Pattern = c.boundedMessage(m.Pattern)
			}
			for _, ex := range m.Examples {
				hm.Examples = append(hm.Examples, c.boundedMessage(ex))
			}
			hh.Matches = append(hh.Matches, hm)
		}
		if h.Error != nil {
			hh.Error = c.errorString(h.Error)
			if f.Verdict == JSONVerdictClean {
				f.Verdict = JSONVerdictError
			}
		}
		f.Heuristics = hh
		if hh.Detected && f.Verdict == JSONVerdictClean {
			f.Verdict = JSONVerdictSuspicious
		}
	}
	return f
}

func (c config) buildStatic(s *static.Result) *Static {
	out := &Static{
		Score:               s.Score,
		Threshold:           staticThresholdFor(s, c.staticThreshold),
		Detected:            staticBreached(s, c.staticThreshold),
		IsPE:                s.IsPE,
		IsELF:               s.IsELF,
		IsMachO:             s.IsMachO,
		Skipped:             c.boundedMessage(s.Skipped),
		Error:               c.errorString(s.Error),
		ParseError:          c.boundedMessage(s.ParseError),
		Entropy:             round3(s.Entropy),
		HighEntropyFraction: round3(s.Profile.HighFraction),
		TLSH:                c.boundedHash(s.Fuzzy.TLSH),
		SSDeep:              c.boundedMessage(s.Fuzzy.SSDeep),
		Imphash:             c.boundedHash(s.Imphash()),
	}
	for _, a := range s.Anomalies {
		out.Anomalies = append(out.Anomalies, StaticAnomaly{
			Class:     c.boundedMessage(a.Class),
			Category:  c.boundedMessage(a.Category),
			Score:     a.Score,
			Detail:    c.boundedMessage(a.Detail),
			Technique: c.boundedMessage(a.Technique),
		})
	}
	for _, cs := range s.Categories {
		out.Categories = append(out.Categories, StaticCategory{Category: c.boundedMessage(cs.Category), Raw: cs.Raw, Applied: cs.Applied, Cap: cs.Cap})
	}
	for _, m := range s.FuzzyMatches {
		out.FuzzyMatches = append(out.FuzzyMatches, StaticFuzzyMatch{
			Type: c.boundedMessage(m.Type), Hash: c.boundedMessage(m.Hash), Threat: c.boundedMessage(m.ThreatName),
			Distance: m.Distance, Score: m.Score,
		})
	}
	if e := s.ELF; e != nil {
		out.ImportHash = c.boundedHash(e.ImportHash)
		out.ELF = c.buildStaticELF(e)
		for _, w := range e.Warnings {
			out.Warnings = append(out.Warnings, c.boundedMessage(w))
		}
	}
	if mo := s.MachO; mo != nil {
		out.MachO = c.buildStaticMachO(mo)
		for _, w := range mo.Warnings {
			out.Warnings = append(out.Warnings, c.boundedMessage(w))
		}
	}
	p := s.PE
	if p == nil {
		return out
	}
	for _, w := range p.Warnings {
		out.Warnings = append(out.Warnings, c.boundedMessage(w))
	}
	pe := &StaticPE{
		Format:       p.Format,
		Machine:      c.boundedMessage(p.MachineName),
		Subsystem:    c.boundedMessage(p.SubsystemName),
		IsDLL:        p.IsDLL,
		IsCLR:        p.IsCLR,
		Timestamp:    p.TimestampTime().Format(time.RFC3339),
		EntryPoint:   p.EntryPoint,
		EntrySection: c.boundedMessage(p.EntrySection),
		ImportCount:  p.ImportCount,
		TLSCallbacks: p.TLSCallbacks,
		Sections:     []StaticSection{},
	}
	for _, d := range p.DLLNames() {
		pe.DLLs = append(pe.DLLs, c.boundedMessage(d))
	}
	for _, sec := range p.Sections {
		pe.Sections = append(pe.Sections, StaticSection{
			Name: c.boundedMessage(sec.Name), Perms: sec.Perms, VirtualSize: sec.VirtualSize,
			RawSize: sec.RawSize, Entropy: round3(sec.Entropy), Entry: sec.Entry,
		})
	}
	if p.Overlay.Size > 0 || p.Overlay.CertificateBytes > 0 {
		pe.Overlay = &StaticOverlay{Offset: p.Overlay.Offset, Size: p.Overlay.Size, Entropy: round3(p.Overlay.Entropy), CertificateBytes: p.Overlay.CertificateBytes}
	}
	if pk := p.Packer; pk != nil {
		sp := &StaticPacker{Name: c.boundedMessage(pk.Name), Generic: pk.Generic, Evidence: []string{}}
		for _, e := range pk.Evidence {
			sp.Evidence = append(sp.Evidence, c.boundedMessage(e))
		}
		pe.Packer = sp
	}
	if p.Rich != nil {
		pe.Rich = &StaticRich{ChecksumValid: p.Rich.ChecksumValid, Entries: len(p.Rich.Entries)}
	}
	if a := p.Authenticode; a != nil {
		sig := &StaticSignature{
			Parsed:             a.Parsed,
			Verified:           a.Verified,
			Note:               a.Note,
			ParseError:         c.boundedMessage(a.ParseErr),
			DigestAlgorithm:    c.boundedMessage(a.DigestAlg),
			Signer:             c.boundedMessage(a.SignerSubject),
			Countersigned:      a.Countersigned,
			ChainSelfContained: a.ChainSelfContained,
			ChainTerminus:      c.boundedMessage(a.ChainTerminus),
		}
		for _, cert := range a.Certificates {
			sig.Certificates = append(sig.Certificates, StaticCert{
				Subject: c.boundedMessage(cert.Subject), Issuer: c.boundedMessage(cert.Issuer), Serial: c.boundedHash(cert.Serial),
				NotBefore: cert.NotBefore.Format(time.RFC3339), NotAfter: cert.NotAfter.Format(time.RFC3339),
				SelfSigned: cert.SelfSigned, CodeSigning: cert.CodeSigning, IsCA: cert.IsCA, Signer: cert.Signer,
			})
		}
		pe.Signature = sig
	}
	if p.Debug.Present {
		d := &StaticDebug{Reproducible: p.Debug.Reproducible, PDBPath: c.boundedMessage(p.Debug.PDBPath)}
		if p.Debug.Timestamp != 0 {
			d.Timestamp = time.Unix(int64(p.Debug.Timestamp), 0).UTC().Format(time.RFC3339)
		}
		pe.Debug = d
	}
	out.PE = pe
	return out
}

func (c config) buildStaticMachO(m *static.MachO) *StaticMachO {
	out := &StaticMachO{
		Magic:     c.boundedMessage(m.Magic),
		ByteOrder: m.ByteOrder,
		Fat:       m.Fat,
	}
	for _, img := range m.Arches {
		arch := StaticMachOArch{
			CPU:          c.boundedMessage(img.CPUType),
			FileType:     c.boundedMessage(img.FileType),
			Signed:       img.Signed,
			Encrypted:    img.Encrypted,
			EntrySegment: img.EntrySegment,
			ImportCount:  img.ImportCount,
			ImportHash:   c.boundedHash(img.ImportHash),
		}
		for _, fl := range img.FlagNames {
			arch.Flags = append(arch.Flags, c.boundedMessage(fl))
		}
		for _, d := range img.Dylibs {
			arch.Dylibs = append(arch.Dylibs, c.boundedMessage(d.Name))
		}
		out.Arches = append(out.Arches, arch)
	}
	return out
}

func (c config) buildStaticELF(e *static.ELF) *StaticELF {
	out := &StaticELF{
		Class:            e.Class,
		ByteOrder:        e.ByteOrder,
		Type:             c.boundedMessage(e.TypeName),
		Machine:          c.boundedMessage(e.MachineName),
		OSABI:            c.boundedMessage(e.OSABIName),
		EntryPoint:       e.Entry,
		EntrySection:     c.boundedMessage(e.EntrySection),
		Interp:           c.boundedMessage(e.Interp),
		PIE:              e.IsPIE,
		Static:           e.Static,
		StackExecutable:  e.StackExecutable,
		RelRO:            e.RelRO,
		TextRel:          e.TextRel,
		BuildID:          c.boundedHash(e.BuildID),
		ABITag:           c.boundedMessage(e.ABITag),
		SOName:           c.boundedMessage(e.SOName),
		ImportCount:      e.ImportCount,
		ExportCount:      e.ExportCount,
		InitArrayCount:   e.InitArrayCount,
		Telfhash:         c.boundedHash(e.Telfhash),
		TelfhashNote:     c.boundedMessage(e.TelfhashNote),
		SyscallStubs:     e.SyscallStubs,
		Segments:         []StaticELFSegment{},
		Sections:         []StaticELFSection{},
		NoSectionHeaders: e.NoSectionHeaders,
		AppImage:         e.AppImage,
	}
	for _, n := range e.Needed {
		out.Needed = append(out.Needed, c.boundedMessage(n))
	}
	for _, p := range e.RPath {
		out.RPath = append(out.RPath, c.boundedMessage(p))
	}
	for _, p := range e.RunPath {
		out.RunPath = append(out.RunPath, c.boundedMessage(p))
	}
	for _, s := range e.Segments {
		out.Segments = append(out.Segments, StaticELFSegment{
			Type: c.boundedMessage(s.Type), Perms: s.Perms, Offset: s.Offset, FileSize: s.FileSize, MemSize: s.MemSize,
			Entropy: round3(s.Entropy), Entry: s.Entry,
		})
	}
	for _, s := range e.Sections {
		out.Sections = append(out.Sections, StaticELFSection{
			Name: c.boundedMessage(s.Name), Type: c.boundedMessage(s.TypeName), Perms: s.Perms, Size: s.Size,
			Entropy: round3(s.Entropy), Entry: s.Entry,
		})
	}
	if e.Overlay.Size > 0 || e.Overlay.CertificateBytes > 0 {
		out.Overlay = &StaticOverlay{Offset: e.Overlay.Offset, Size: e.Overlay.Size, Entropy: round3(e.Overlay.Entropy), CertificateBytes: e.Overlay.CertificateBytes}
	}
	if pk := e.Packer; pk != nil {
		sp := &StaticPacker{Name: c.boundedMessage(pk.Name), Generic: pk.Generic, Evidence: []string{}}
		for _, ev := range pk.Evidence {
			sp.Evidence = append(sp.Evidence, c.boundedMessage(ev))
		}
		out.Packer = sp
	}
	if m := e.Module; m != nil {
		out.Module = &StaticELFModule{
			Name: c.boundedMessage(m.Name), Vermagic: c.boundedMessage(m.Vermagic), License: c.boundedMessage(m.License),
			SrcVersion: c.boundedMessage(m.SrcVersion), Signed: m.Signed, SignatureBytes: m.SignatureBytes,
			Note: "signature presence only; not verified against the kernel keyring",
		}
	}
	return out
}

func (c config) buildStego(s *stego.Result) *Stego {
	out := &Stego{
		Score:        s.Score,
		Threshold:    stegoThresholdFor(s, c.stegoThreshold),
		Detected:     stegoBreached(s, c.stegoThreshold),
		IsText:       s.IsText,
		Encoding:     c.boundedMessage(s.Encoding),
		Skipped:      c.boundedMessage(s.Skipped),
		Error:        c.errorString(s.Error),
		Suspicious:   s.Suspicious,
		Benign:       s.Benign,
		Info:         s.Info,
		LongestRun:   s.LongestRun,
		ASCIICarrier: s.ASCIICarrier,
	}
	for _, cp := range s.Codepoints {
		sc := StegoCodepoint{
			Codepoint:   c.boundedMessage(cp.Code),
			Name:        c.boundedMessage(cp.Name),
			Class:       c.boundedMessage(cp.Class),
			Count:       cp.Count,
			Benign:      cp.Benign,
			FirstOffset: cp.FirstOffset,
			FirstLine:   cp.FirstLine,
		}
		if len(cp.Excuses) > 0 {
			sc.Excuses = make(map[string]int, len(cp.Excuses))
			for k, v := range cp.Excuses {
				sc.Excuses[c.boundedMessage(k)] = v
			}
		}
		for _, ex := range cp.Examples {
			sc.Examples = append(sc.Examples, c.boundedMessage(ex))
		}
		out.Codepoints = append(out.Codepoints, sc)
	}
	for _, f := range s.Findings {
		out.Findings = append(out.Findings, StegoFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score, Detail: c.boundedMessage(f.Detail),
			Technique: c.boundedMessage(f.Technique), Novel: c.boundedMessage(f.Novel),
		})
	}
	return out
}

func (c config) buildEncChain(e *encchain.Result) *EncChain {
	out := &EncChain{
		Score:        e.Score,
		Threshold:    encChainThresholdFor(e, c.encChainThreshold),
		Detected:     encChainBreached(e, c.encChainThreshold),
		Skipped:      c.boundedMessage(e.Skipped),
		Candidates:   e.Candidates,
		LayersPeeled: e.LayersPeeled,
		Budget:       e.Budget,
	}
	for _, f := range e.Findings {
		out.Findings = append(out.Findings, EncChainFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score, Encoding: c.boundedMessage(f.Encoding),
			Depth: f.Depth, Offset: f.Offset, RunBytes: f.RunBytes,
			Technique: c.boundedMessage(f.Technique), Novel: c.boundedMessage(f.Novel),
			Detail: c.boundedMessage(f.Detail),
		})
	}
	return out
}

func (c config) buildLNK(l *lnk.Result) *LNK {
	out := &LNK{
		Score:     l.Score,
		Threshold: lnkThresholdFor(l, c.lnkThreshold),
		Detected:  lnkBreached(l, c.lnkThreshold),
		Skipped:   c.boundedMessage(l.Skipped),
	}
	if l.Parsed != nil {
		out.TargetExt = c.boundedMessage(l.Parsed.TargetExt)
		out.ArgsLen = l.Parsed.ArgsLen
	}
	for _, f := range l.Findings {
		out.Findings = append(out.Findings, LNKFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique),
			Detail:    c.boundedMessage(f.Detail), Evidence: c.boundedMessage(f.Evidence),
		})
	}
	return out
}

func (c config) buildOLE(o *ole.Result) *OLE {
	out := &OLE{
		Score:     o.Score,
		Threshold: oleThresholdFor(o, c.oleThreshold),
		Detected:  oleBreached(o, c.oleThreshold),
		Skipped:   c.boundedMessage(o.Skipped),
	}
	if o.Parsed != nil {
		out.HasVBA = o.Parsed.HasVBA
		out.Modules = o.Parsed.Modules
	}
	for _, f := range o.Findings {
		out.Findings = append(out.Findings, OLEFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique),
			Detail:    c.boundedMessage(f.Detail), Evidence: c.boundedMessage(f.Evidence),
		})
	}
	return out
}

func (c config) buildPDF(p *pdf.Result) *PDF {
	out := &PDF{
		Score:     p.Score,
		Threshold: pdfThresholdFor(p, c.pdfThreshold),
		Detected:  pdfBreached(p, c.pdfThreshold),
		Skipped:   c.boundedMessage(p.Skipped),
	}
	if p.Parsed != nil {
		out.Version = c.boundedMessage(p.Parsed.Version)
		out.HasJavaScript = p.Parsed.HasJavaScript
		out.HasOpenAction = p.Parsed.HasOpenAction
		out.Encrypted = p.Parsed.Encrypted
	}
	for _, f := range p.Findings {
		out.Findings = append(out.Findings, PDFFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique),
			Detail:    c.boundedMessage(f.Detail), Evidence: c.boundedMessage(f.Evidence),
		})
	}
	return out
}

func (c config) buildISO(i *iso.Result) *ISO {
	out := &ISO{
		Score:     i.Score,
		Threshold: isoThresholdFor(i, c.isoThreshold),
		Detected:  isoBreached(i, c.isoThreshold),
		Skipped:   c.boundedMessage(i.Skipped),
	}
	if i.Parsed != nil {
		out.VolumeID = c.boundedMessage(i.Parsed.VolumeID)
		out.Files = i.Parsed.Files
		out.HasJoliet = i.Parsed.HasJoliet
	}
	for _, f := range i.Findings {
		out.Findings = append(out.Findings, ISOFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique),
			Detail:    c.boundedMessage(f.Detail), Evidence: c.boundedMessage(f.Evidence),
		})
	}
	return out
}

func (c config) buildArchive(a *archive.Result) *Archive {
	out := &Archive{
		Score:     a.Score,
		Threshold: archiveThresholdFor(a, c.archiveThreshold),
		Detected:  archiveBreached(a, c.archiveThreshold),
		Skipped:   c.boundedMessage(a.Skipped),
	}
	if a.Parsed != nil {
		out.Format = c.boundedMessage(a.Parsed.Format)
		out.Members = a.Parsed.Members
		out.Uncompressed = a.Parsed.Uncompressed
		out.Encrypted = a.Parsed.Encrypted
		out.Executables = a.Parsed.Executables
		out.NotInspected = c.boundedMessage(a.Parsed.NotInspected)
		out.VBAMember = c.boundedMessage(a.Parsed.VBAMember)
	}
	if a.EmbeddedVBA != nil {
		out.EmbeddedVBA = c.buildOLE(a.EmbeddedVBA)
	}
	for _, f := range a.Findings {
		out.Findings = append(out.Findings, ArchiveFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique),
			Detail:    c.boundedMessage(f.Detail), Evidence: c.boundedMessage(f.Evidence),
			Via: c.boundedMessage(f.Via),
		})
	}
	return out
}

func (c config) buildCHM(h *chm.Result) *CHM {
	out := &CHM{
		Score:     h.Score,
		Threshold: chmThresholdFor(h, c.chmThreshold),
		Detected:  chmBreached(h, c.chmThreshold),
		Skipped:   c.boundedMessage(h.Skipped),
	}
	if h.Parsed != nil {
		out.Entries = h.Parsed.Entries
		out.ContentFiles = h.Parsed.ContentDirs
		out.NotInspected = c.boundedMessage(h.Parsed.NotInspected)
	}
	for _, f := range h.Findings {
		out.Findings = append(out.Findings, CHMFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique),
			Detail:    c.boundedMessage(f.Detail), Evidence: c.boundedMessage(f.Evidence),
		})
	}
	return out
}

func (c config) buildTradecraft(t *tradecraft.Result) *Tradecraft {
	out := &Tradecraft{
		Score:     t.Score,
		Threshold: tradecraftThresholdFor(t, c.tradecraftThreshold),
		Detected:  tradecraftBreached(t, c.tradecraftThreshold),
		Skipped:   c.boundedMessage(t.Skipped),
		Decoded:   t.Decoded,
	}
	for _, f := range t.Findings {
		out.Findings = append(out.Findings, CHMFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique),
			Detail:    c.boundedMessage(f.Detail), Evidence: c.boundedMessage(f.Evidence),
		})
	}
	return out
}

func (c config) buildLinuxPkg(p *linuxpkg.Result) *LinuxPkg {
	out := &LinuxPkg{
		Score:     p.Score,
		Threshold: linuxPkgThresholdFor(p, c.linuxPkgThreshold),
		Detected:  linuxPkgBreached(p, c.linuxPkgThreshold),
		Skipped:   c.boundedMessage(p.Skipped),
	}
	if p.Parsed != nil {
		out.Format = c.boundedMessage(p.Parsed.Format)
		out.Name = c.boundedMessage(p.Parsed.Name)
		for _, s := range p.Parsed.Scripts {
			out.Scripts = append(out.Scripts, c.boundedMessage(s))
		}
	}
	for _, f := range p.Findings {
		out.Findings = append(out.Findings, LinuxPkgFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique),
			Detail:    c.boundedMessage(f.Detail), Evidence: c.boundedMessage(f.Evidence),
		})
	}
	return out
}

func (c config) buildPeel(p *peeler.Result) *Peel {
	out := &Peel{
		Score:            p.Score,
		Threshold:        peelThresholdFor(p, c.peelThreshold),
		Detected:         peelBreached(p, c.peelThreshold),
		Skipped:          c.boundedMessage(p.Skipped),
		Outcome:          string(p.Outcome),
		MaxDepth:         p.MaxDepth,
		PrimarySignature: c.boundedMessage(p.PrimarySignature),
		Exhausted:        p.Exhausted,
		ExhaustReason:    c.boundedMessage(p.ExhaustReason),
	}
	for _, f := range p.Findings {
		out.Findings = append(out.Findings, PeelFinding{
			Class: c.boundedMessage(f.Class), Score: f.Score,
			Technique: c.boundedMessage(f.Technique), Novel: c.boundedMessage(f.Novel),
			Detail: c.boundedMessage(f.Detail),
		})
	}
	return out
}

func (c config) buildFusion(v *fusion.Verdict) *Fusion {
	out := &Fusion{
		Tier:         string(v.Tier),
		Score:        v.Score,
		Threshold:    v.Threshold,
		Confidence:   v.Confidence,
		Corroborated: v.Corroborated,
		Explanation:  c.boundedMessage(v.Explanation),
		Sources:      []FusionSource{},
	}
	for _, a := range v.Agreed {
		out.Agreed = append(out.Agreed, c.boundedMessage(a))
	}
	for _, t := range v.Techniques {
		out.Techniques = append(out.Techniques, c.boundedMessage(t))
		b := frameworks.ForTechnique(t)
		out.Frameworks = append(out.Frameworks, FrameworkBinding{
			Technique: c.boundedMessage(t), UKCPhase: b.UKCPhase, UKCStage: b.UKCStage,
		})
	}
	for _, n := range v.Novel {
		out.Novel = append(out.Novel, c.boundedMessage(n))
	}
	for _, s := range v.Sources {
		fs := FusionSource{
			Name: c.boundedMessage(s.Name), Role: string(s.Role), Hit: s.Hit, Score: s.Score, Threshold: s.Threshold,
			Ratio: round3(s.Ratio), Weight: s.Weight, Counted: s.Counted, Skipped: c.boundedMessage(s.Skipped),
		}
		for _, e := range s.Evidence {
			fs.Evidence = append(fs.Evidence, FusionEvidence{
				Label: c.boundedMessage(e.Label), Detail: c.boundedMessage(e.Detail),
				Technique: c.boundedMessage(e.Technique), Novel: c.boundedMessage(e.Novel), Weight: e.Weight,
			})
		}
		out.Sources = append(out.Sources, fs)
	}
	return out
}

// round3 keeps floating-point fields readable and stable across platforms.
func round3(f float64) float64 { return float64(int64(f*1000+0.5)) / 1000 }

func (c config) buildYara(m scanner.YaraMatch) YaraHit {
	hit := YaraHit{
		Rule:      c.boundedMessage(m.RuleName),
		Namespace: c.boundedMessage(m.Namespace),
	}
	for _, t := range m.Tags {
		hit.Tags = append(hit.Tags, c.boundedMessage(t))
	}
	sort.Strings(hit.Tags)
	for _, meta := range m.Metas {
		hit.Meta = append(hit.Meta, MetaPair{
			Key:   c.boundedMessage(meta.Identifier),
			Value: c.boundedMessage(meta.String()),
		})
	}
	for _, s := range m.Strings {
		hit.Strings = append(hit.Strings, c.buildYaraString(s))
	}
	return hit
}

func (c config) buildYaraString(s scanner.YaraMatchString) YaraString {
	data, cut := truncateBytes(s.Data, c.maxMatchStringBytes)
	return YaraString{
		Name:      c.boundedMessage(s.Name),
		Offset:    s.Offset,
		DataHex:   hexString(data),
		Preview:   preview(s.Data, c.maxPreviewBytes),
		Truncated: cut,
		Length:    len(s.Data),
		XorKey:    s.XorKey,
	}
}

// elapsedString renders a duration the way the text reporter prints it.
func elapsedString(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}
