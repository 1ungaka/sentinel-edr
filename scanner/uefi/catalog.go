package uefi

// Class describes one finding class the firmware detector can emit, for the
// ATT&CK coverage matrix. Field names and tags match the sibling detectors.
// The set is deliberately tiny: firmware is overwhelmingly legitimate drivers,
// so only a genuine tamper signal and the operator blocklist are scored.
type Class struct {
	Class       string `json:"class"`
	Technique   string `json:"technique"`
	Novel       string `json:"novel,omitempty"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
}

// Classes returns the catalog in a stable, report-friendly order.
func Classes() []Class {
	return []Class{
		{"uefi.volume-checksum-invalid", techPreOSBoot, "", scoreChecksum,
			"a firmware-volume header fails its 16-bit checksum: a hand-built or tampered volume"},
		{"uefi.known-implant-guid", techPreOSBoot, "", scoreImplant,
			"a module GUID matches the operator-supplied implant blocklist (empty by default; no implant truth set ships with the engine)"},
	}
}
