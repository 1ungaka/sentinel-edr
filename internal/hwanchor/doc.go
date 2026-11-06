// Package hwanchor takes a point-in-time snapshot of a host's hardware identity
// from sysfs and compares two snapshots.
//
// It is the engine-side, single-host half of "hardware-anchored identity": the
// anchors a host can show about the machine it runs on (DMI/SMBIOS identity,
// the permanent address of each physical network interface, the TPM's PCR
// values, the active hardware entropy source), each labelled with how far it
// could actually be read. A later snapshot compared with a saved one answers
// "is this still the same hardware", as a list of differences. There are no
// scores and no thresholds: identity either differs or it does not.
//
// # Honest degradation
//
// Every value carries a State. Only StateOK is an identity. An anchor that is
// absent (no TPM, no DMI table), unreadable (product_uuid and the serials need
// root), or a placeholder the firmware vendor never filled in ("Default
// string", an all-zero UUID) is recorded as exactly that and is listed again
// in Snapshot.Unverifiable, so a consumer sees at a glance what this host could
// not prove. Nothing is padded to "verified", and Compare never treats a value
// that is not StateOK as an identity.
//
// # What this package does not do
//
//   - It does not capture a TPM quote. A signed TPM2_Quote needs /dev/tpm0 and
//     an attestation key; this package only reads sysfs. The PCR values are the
//     kernel's unsigned report of them: evidence of the measured boot chain,
//     not proof to a remote verifier. Snapshot.TPM.Quote says "not captured"
//     on every host.
//   - It does not read a NIC's burned-in address. sysfs exposes the configured
//     address and addr_assign_type, which says whether that address is the
//     device's permanent one (0) or was set by userspace (3). So the snapshot
//     knows that a MAC was changed, not what it was changed from; the EEPROM
//     address needs an ethtool ioctl this package does not make.
//   - It does not test the entropy source. It reports which hardware RNG the
//     kernel has selected, or that none is; the quality of its output is not
//     measured.
//   - It does not trust sysfs beyond the kernel: root, or a hypervisor, can
//     present any DMI table it likes. A snapshot is what the kernel reported.
//
// # Read-only by construction
//
// The package opens files for reading and nothing else: no writes, no ioctls,
// no network, no subprocess. A source-level test enforces that. Saving a
// baseline is the caller's explicit act (Marshal returns bytes; the cau hwid
// command writes them). Every read is bounded (4096 bytes per attribute, 1024
// interfaces) and no symbolic link is followed out of the sysfs root.
//
// # Privacy
//
// Serials, UUIDs and MAC addresses are hardware metadata that identify one
// physical machine. A snapshot is built in memory and stays on the host unless
// the operator moves it. Redact replaces those values with a truncated SHA-256
// so a snapshot can be shared and still compared with another redacted one.
// That is a pseudonym, not anonymity: the digest is unsalted so that two
// snapshots agree, and a serial or MAC drawn from a small space can be
// recovered from it by enumeration.
package hwanchor
